"""
Offline checks of the per-device state machine.

    python -m pytest tests
"""

import struct

import pytest

from strx import broadcast as strx
from strx import device as dev

KEY = bytes.fromhex("4BD224860416877824974BAF9ED1E1E4")
OTHER_KEY = bytes(range(16))

ADV = strx.ADVERTISING_UUID
RSP = strx.SCAN_RESPONSE_UUID


class Sim:
    """Firmware side of one device, builds the two payloads it broadcasts."""

    def __init__(self, mode=strx.BEACON_PLAIN, key=KEY, boot=7, msg=100, ccc=0, level=500,
                 volume=200, tank_type=0x01, major=1):
        self.mode = mode
        self.key = key
        self.boot = boot
        self.msg = msg
        self.ccc = ccc
        self.level = level
        self.volume = volume
        self.tank_type = tank_type
        self.major = major

    def rsp(self) -> bytes:
        """Scan response service data."""
        return struct.pack("<BBBHBHHB", 0x01, self.major, 9, 42, self.mode, self.boot,
                           self.volume, self.tank_type)

    def adv(self) -> bytes:
        """Advertising service data of the current message."""
        if self.mode in strx.BEACON_MODES_ENCRYPTED:
            rsp = strx.parse_scan_response(self.rsp())
            level_bytes, mic = strx.encrypt_level(self.key, rsp, self.msg, self.ccc, self.level)
        else:
            level = strx.LEVEL_INVALID if self.mode == strx.BEACON_OFF else self.level
            level_bytes, mic = struct.pack("<H", level), bytes(4)
        return self.msg.to_bytes(3, "little") + level_bytes + mic + bytes([self.ccc])

    def tick(self, count=1) -> None:
        """Advance to the next message."""
        self.msg += count


class Host:
    """Scanner side, merges service data per address like habluetooth."""

    def __init__(self, key=None, description=None, following=True):
        """
        Args:
            key: Encryption key the host holds
            description: Tank description remembered from an earlier run
            following: Listening before the device is first heard, so its first scan response is
                fresh rather than one cached from before
        """
        self.device = dev.STRxDevice("test", key, description)
        self.service_data = {}
        self.now = 1000.0
        if following:
            self.device.update({}, self.now)

    def hear(self, payloads: dict, dt: float = 1.0, active: bool = False) -> dev.Result:
        """One scanner callback dt seconds after the previous one, with the given packets merged in."""
        self.now += dt
        self.service_data.update(payloads)
        return self.device.update(dict(self.service_data), self.now, active)

    def hear_adv(self, sim: Sim, **kwargs) -> dev.Result:
        """Advertising packet only, the scan response stays as cached."""
        return self.hear({ADV: sim.adv()}, **kwargs)

    def hear_both(self, sim: Sim, **kwargs) -> dev.Result:
        """Advertising packet and its scan response."""
        return self.hear({ADV: sim.adv(), RSP: sim.rsp()}, **kwargs)


def scan_actively(host: Host, sim: Sim, seconds: float = dev.CONFIRM_SECONDS) -> dev.Result:
    """Active scanning for a while, one message per second, the scan response stays as cached."""
    result = host.hear_adv(sim, active=True)
    for _ in range(int(seconds)):
        sim.tick()
        result = host.hear_adv(sim, active=True)
    return result


class TestPlain:
    def test_level_and_volume(self):
        host = Host()
        host.hear_both(Sim())
        d = host.device
        assert d.status == dev.STATUS_OK
        assert d.level_pct == 50.0
        assert d.tank_volume_total == 200
        assert d.tank_type == 0x01
        assert d.volume_l == 100.0

    def test_waits_for_scan_response(self):
        host = Host()
        result = host.hear_adv(Sim())
        assert result.request_scan
        assert host.device.status == dev.STATUS_WAITING_SCAN_RESPONSE
        assert host.device.level_pct is None

    def test_out_of_range_level_ignored(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)
        sim.tick()
        sim.level = 0x1234
        host.hear_adv(sim)
        assert host.device.level_pct == 50.0

    def test_broadcast_off(self):
        host = Host()
        host.hear_both(Sim(mode=strx.BEACON_OFF))
        assert host.device.status == dev.STATUS_BROADCAST_OFF
        assert host.device.level_pct is None
        assert host.device.tank_volume_total == 200

    def test_no_measurement(self):
        host = Host()
        host.hear_both(Sim(level=strx.LEVEL_INVALID))
        assert host.device.status == dev.STATUS_NO_MEASUREMENT
        assert host.device.level_pct is None

    def test_downgrade_rejected_with_key(self):
        host = Host(key=KEY)
        host.hear_both(Sim(mode=strx.BEACON_PLAIN))
        assert host.device.status == dev.STATUS_DOWNGRADE_REJECTED
        assert host.device.level_pct is None


class TestEncrypted:
    def test_level_with_key(self):
        host = Host(key=KEY)
        host.hear_both(Sim(mode=strx.BEACON_LOW_SECURITY))
        assert host.device.status == dev.STATUS_OK
        assert host.device.level_pct == 50.0
        assert host.device.volume_l == 100.0

    def test_key_needed(self):
        host = Host()
        host.hear_both(Sim(mode=strx.BEACON_LOW_SECURITY))
        assert host.device.status == dev.STATUS_KEY_NEEDED
        assert host.device.level_pct is None

    def test_device_could_not_encrypt(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY)
        host = Host(key=KEY)
        host.hear({RSP: sim.rsp(), ADV: sim.msg.to_bytes(3, "little") + b"\xff\xff" + bytes(5)})
        assert host.device.status == dev.STATUS_NO_MEASUREMENT

    def test_high_security_hides_description(self):
        host = Host(key=KEY)
        host.hear_both(Sim(mode=strx.BEACON_HIGH_SECURITY, volume=0xFFFF, tank_type=0xFF))
        assert host.device.level_pct == 50.0
        assert host.device.tank_volume_total is None
        assert host.device.volume_l is None

    def test_wrong_key_rejected_after_distinct_failures(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY, key=OTHER_KEY)
        host = Host(key=KEY)
        for _ in range(dev.MIC_FAIL_REAUTH * 2):
            host.hear_both(sim)
        assert host.device.status != dev.STATUS_KEY_REJECTED
        for _ in range(dev.MIC_FAIL_REAUTH - 2):
            sim.tick()
            host.hear_adv(sim)
        assert host.device.status != dev.STATUS_KEY_REJECTED
        sim.tick()
        host.hear_adv(sim)
        assert host.device.status == dev.STATUS_KEY_REJECTED
        assert host.device.level_pct is None

    def test_failures_not_counted_while_stale(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY)
        host = Host(key=KEY)
        host.hear_both(sim)
        # Mode changes, a passive scanner never brings the new scan response
        sim.mode, sim.ccc = strx.BEACON_HIGH_SECURITY, 1
        for _ in range(dev.MIC_FAIL_REAUTH * 2):
            sim.tick()
            result = host.hear_adv(sim)
            assert result.request_scan
        assert host.device.stale
        assert host.device.status == dev.STATUS_WAITING_SCAN_RESPONSE

    def test_replay_with_old_scan_response_rejected(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY)
        host = Host(key=KEY)
        old = {ADV: sim.adv(), RSP: sim.rsp()}
        # Reboot, new BOOT_COUNTER and level
        sim.boot, sim.msg, sim.level = 8, 0, 700
        host.hear_both(sim)
        assert host.device.level_pct == 70.0
        host.hear(old)
        assert host.device.level_pct == 70.0


class TestConfigChange:
    def test_stale_until_new_scan_response(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)

        sim.tick()
        sim.volume, sim.ccc = 300, 1
        result = host.hear_adv(sim)
        d = host.device
        assert result.request_scan
        assert d.stale
        assert d.status == dev.STATUS_WAITING_SCAN_RESPONSE
        assert d.tank_volume_total is None
        assert d.volume_l is None

        result = host.hear_both(sim)
        assert result.description_changed
        assert not result.request_scan
        assert not d.stale
        assert d.status == dev.STATUS_OK
        assert d.tank_volume_total == 300
        assert d.volume_l == 150.0

    def test_scan_response_before_its_advertisement(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)
        stale_adv = sim.adv()

        # The scanner missed the advertising packet but caught the scan response
        sim.tick()
        sim.volume, sim.ccc = 300, 1
        host.hear({ADV: stale_adv, RSP: sim.rsp()})
        sim.tick()
        result = host.hear_adv(sim)
        assert result.scan_now
        assert host.device.stale

        # The active scan finds nothing newer, so the scan response in hand belongs to the new counter
        result = scan_actively(host, sim)
        assert not result.request_scan
        assert not host.device.stale
        assert host.device.tank_volume_total == 300
        assert host.device.description == dev.TankDescription(300, 0x01, 1)

    def test_older_scan_response_not_bound_to_a_later_change(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)
        for _ in range(5):
            sim.tick()
            host.hear_adv(sim)

        # Switched to Low Security, the new scan response has not come in yet
        sim.mode, sim.ccc = strx.BEACON_LOW_SECURITY, 1
        sim.tick()
        scan_actively(host, sim, seconds=2 * dev.CONFIRM_SECONDS)
        assert host.device.stale
        assert host.device.level_pct is None
        assert host.device.status == dev.STATUS_WAITING_SCAN_RESPONSE

    def test_change_during_app_session_not_taken_for_the_old_one(self):
        sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=1)
        host = Host(key=KEY)
        host.hear_both(sim)
        assert host.device.tank_volume_total == 200

        # The app connects right away: MESSAGE_COUNTER stands still while the volume changes
        sim.volume, sim.ccc = 300, 2
        sim.tick()
        result = host.hear_adv(sim, dt=40)
        assert result.scan_now
        assert host.device.stale
        assert host.device.tank_volume_total is None

        result = host.hear_both(sim)
        assert result.description_changed
        assert host.device.description == dev.TankDescription(300, 0x01, 2)

    def test_plain_to_security_not_read_as_plaintext(self):
        sim = Sim()
        host = Host(key=None)
        host.hear_both(sim)
        sim.tick()
        sim.mode, sim.ccc = strx.BEACON_LOW_SECURITY, 1
        host.hear_adv(sim)
        assert host.device.level_pct is None
        host.hear_both(sim)
        assert host.device.status == dev.STATUS_KEY_NEEDED


class TestCounters:
    def test_reboot_waits_for_boot_counter(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY)
        host = Host(key=KEY)
        host.hear_both(sim)

        sim.boot, sim.msg, sim.level = 8, 0, 700
        result = host.hear_adv(sim)
        assert result.request_scan
        assert host.device.stale
        assert host.device.status == dev.STATUS_WAITING_SCAN_RESPONSE
        assert host.device.level_pct == 50.0

        host.hear_both(sim)
        assert not host.device.stale
        assert host.device.status == dev.STATUS_OK
        assert host.device.level_pct == 70.0

    def test_plain_reboot_continues(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)
        sim.boot, sim.msg, sim.level = 8, 0, 700
        host.hear_adv(sim)
        assert not host.device.stale
        assert host.device.level_pct == 70.0

    def test_replay_under_same_scan_response_not_accepted(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY)
        host = Host(key=KEY)
        host.hear_both(sim)
        old_adv = sim.adv()
        sim.tick()
        sim.level = 600
        host.hear_adv(sim)
        assert host.device.level_pct == 60.0

        host.hear({ADV: old_adv})
        assert host.device.level_pct == 60.0
        sim.tick()
        host.hear_adv(sim)
        assert not host.device.stale
        assert host.device.status == dev.STATUS_OK

    def test_factory_reset_asks_for_key(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY, ccc=3)
        host = Host(key=KEY)
        host.hear_both(sim)

        sim.key, sim.boot, sim.msg, sim.ccc = OTHER_KEY, 0, 0, 0
        host.hear_adv(sim)
        assert host.device.stale
        host.hear_both(sim)
        for _ in range(dev.MIC_FAIL_REAUTH):
            sim.tick()
            host.hear_adv(sim)
        assert host.device.status == dev.STATUS_KEY_REJECTED


class TestMediumWindow:
    def test_description_kept_after_window(self):
        sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=1)
        host = Host(key=KEY)
        result = host.hear_both(sim)
        assert result.description_changed
        assert host.device.description == dev.TankDescription(200, 0x01, 1)

        # Window closes, fields withheld under the same counter
        sim.tick()
        sim.volume, sim.tank_type = 0xFFFF, 0xFF
        result = host.hear_both(sim)
        assert not result.description_changed
        assert host.device.tank_volume_total == 200
        assert host.device.volume_l == 100.0

    def test_missed_window_drops_description(self):
        sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=2, volume=0xFFFF, tank_type=0xFF)
        host = Host(key=KEY, description=dev.TankDescription(200, 0x01, 1))
        host.hear_both(sim)
        assert host.device.level_pct == 50.0
        assert host.device.tank_volume_total is None

    def test_remembered_description_restored(self):
        sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=1, volume=0xFFFF, tank_type=0xFF)
        host = Host(key=KEY, description=dev.TankDescription(200, 0x01, 1))
        host.hear_both(sim)
        assert host.device.tank_volume_total == 200


class TestScanRequests:
    def test_first_callback_asks_at_once(self):
        host = Host(following=False)
        result = host.hear_both(Sim())
        assert result.scan_now

    def test_settled_device_asks_nothing(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)
        sim.tick()
        result = host.hear_adv(sim)
        assert not result.request_scan
        assert not result.scan_now

    def test_counter_move_asks_at_once_then_keeps_asking(self):
        sim = Sim(mode=strx.BEACON_LOW_SECURITY)
        host = Host(key=KEY)
        host.hear_both(sim)
        sim.tick()
        sim.ccc = 1
        result = host.hear_adv(sim)
        assert result.scan_now
        sim.tick()
        result = host.hear_adv(sim)
        assert result.request_scan
        assert not result.scan_now

    def test_heard_again_after_silence(self):
        sim = Sim()
        host = Host()
        host.hear_both(sim)
        sim.tick()
        result = host.hear_adv(sim, dt=dev.SILENCE_SECONDS)
        assert result.scan_now
        assert not host.device.stale


class TestCachedScanResponse:
    def test_medium_description_taken_once_confirmed(self):
        # Listening starts during the window, the scan response came from the cache
        sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=1)
        host = Host(key=KEY, following=False)
        result = host.hear_both(sim)
        assert result.scan_now
        assert host.device.level_pct == 50.0
        assert host.device.description is None

        result = scan_actively(host, sim)
        assert result.description_changed
        assert host.device.description == dev.TankDescription(200, 0x01, 1)

    def test_plaintext_level_waits_for_confirmation(self):
        sim = Sim()
        host = Host(following=False)
        host.hear_both(sim)
        assert host.device.level_pct is None
        assert host.device.status == dev.STATUS_WAITING_SCAN_RESPONSE

        sim.tick()
        scan_actively(host, sim)
        assert host.device.level_pct == 50.0
        assert host.device.status == dev.STATUS_OK

    def test_passive_scanning_never_confirms(self):
        sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=1)
        host = Host(key=KEY, following=False)
        host.hear_both(sim)
        for _ in range(10):
            sim.tick()
            host.hear_adv(sim)
        assert host.device.description is None

    def test_old_description_not_bound_to_new_counter(self):
        # Cached from Low Security, since then switched to Medium with a new volume, window missed
        old = Sim(mode=strx.BEACON_LOW_SECURITY, ccc=1)
        now = Sim(mode=strx.BEACON_MED_SECURITY, ccc=3, volume=0xFFFF, tank_type=0xFF)
        host = Host(key=KEY, following=False)
        host.hear({ADV: now.adv(), RSP: old.rsp()})
        assert host.device.description is None

        host.hear_both(now, active=True)
        scan_actively(host, now)
        assert host.device.description is None
        assert host.device.level_pct == 50.0

    def test_mic_failures_not_counted_before_confirmed(self):
        # Rebooted while nobody listened, the cached scan response holds the old BOOT_COUNTER
        old = Sim(mode=strx.BEACON_LOW_SECURITY, boot=7)
        sim = Sim(mode=strx.BEACON_LOW_SECURITY, boot=8, msg=0)
        host = Host(key=KEY, following=False)
        host.hear({ADV: sim.adv(), RSP: old.rsp()})
        for _ in range(dev.MIC_FAIL_REAUTH + 5):
            sim.tick()
            host.hear_adv(sim)
        assert host.device.status == dev.STATUS_WAITING_SCAN_RESPONSE

        host.hear_both(sim)
        assert host.device.status == dev.STATUS_OK


class TestStoredDescription:
    def test_shown_before_first_advertisement(self):
        host = Host(description=dev.TankDescription(200, 0x01, 3))
        assert host.device.tank_volume_total == 200
        assert host.device.tank_type == 0x01

    def test_dropped_when_counter_moved_meanwhile(self):
        host = Host(key=KEY, description=dev.TankDescription(200, 0x01, 3))
        host.hear_adv(Sim(mode=strx.BEACON_MED_SECURITY, ccc=4))
        assert host.device.tank_volume_total is None


class TestUnparsable:
    def test_unknown_mode(self):
        host = Host()
        host.hear_both(Sim(mode=0x05))
        assert host.device.status == dev.STATUS_UNKNOWN_MODE
        assert host.device.level_pct is None

    def test_unsupported_major(self):
        host = Host()
        host.hear_both(Sim(major=2))
        assert host.device.status == dev.STATUS_UNSUPPORTED_PROTOCOL
        assert host.device.level_pct is None

    def test_short_payloads_ignored(self):
        host = Host()
        host.hear({ADV: bytes(3), RSP: bytes(4)})
        assert host.device.advertisement is None
        assert host.device.scan_response is None


@pytest.mark.parametrize("description", [dev.TankDescription(200, 1, 3), dev.TankDescription(None, None, 0)])
def test_description_round_trip(description):
    assert dev.TankDescription.from_dict(description.as_dict()) == description
    assert dev.TankDescription.from_dict(None) is None
    assert dev.TankDescription.from_dict({"volume_total": 1}) is None
