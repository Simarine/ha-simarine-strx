"""
State of one STRx device across scanner callbacks.

Pairs the advertising packet with the scan response it has to be read under,
notices when that scan response went out of date, verifies and decrypts the
level, guards the counters and remembers the tank description. Pure Python:
the caller hands in the service data of each callback and acts on the Result.

@see STRx-ble-advertising.md
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from . import broadcast as strx

_LOGGER = logging.getLogger(__name__)

# PROTOCOL_VERSION_MAJOR this host parses, and its offset in the scan response
SUPPORTED_PROTOCOL_MAJOR = 1
PROTOCOL_MAJOR_OFFSET = 1

# Highest valid LEVEL, permille
LEVEL_MAX = 1000

# Distinct messages failing the MIC under an up to date scan response before the key is asked again
MIC_FAIL_REAUTH = 30

# Seconds of active scanning under one CONFIG_CHANGE_COUNTER after which the scan
# response in hand is the current one: the device advertises at least every 250 ms
# and an active scanner asks for the scan response on each advertisement
CONFIRM_SECONDS = 3.0

# Seconds without a callback after which the device counts as having been away:
# connected to the app, out of range or rebooting
SILENCE_SECONDS = 10.0

# Seconds a scan response may have arrived before the first advertising packet with
# its CONFIG_CHANGE_COUNTER, for the scanner missing the packet that went out with it
REBIND_SECONDS = 2.0

# Status
STATUS_OK = "ok"
STATUS_WAITING_SCAN_RESPONSE = "waiting_scan_response"
STATUS_NO_MEASUREMENT = "no_measurement"
STATUS_BROADCAST_OFF = "broadcast_off"
STATUS_KEY_NEEDED = "key_needed"
STATUS_KEY_REJECTED = "key_rejected"
STATUS_DOWNGRADE_REJECTED = "downgrade_rejected"
STATUS_UNSUPPORTED_PROTOCOL = "unsupported_protocol"
STATUS_UNKNOWN_MODE = "unknown_mode"

STATUSES = (
    STATUS_OK,
    STATUS_WAITING_SCAN_RESPONSE,
    STATUS_NO_MEASUREMENT,
    STATUS_BROADCAST_OFF,
    STATUS_KEY_NEEDED,
    STATUS_KEY_REJECTED,
    STATUS_DOWNGRADE_REJECTED,
    STATUS_UNSUPPORTED_PROTOCOL,
    STATUS_UNKNOWN_MODE,
)

# Modes whose scan response always carries the tank description in plaintext
DESCRIPTION_PLAIN_MODES = (strx.BEACON_OFF, strx.BEACON_LOW_SECURITY, strx.BEACON_PLAIN)


@dataclass(frozen=True)
class TankDescription:
    """Tank description and the CONFIG_CHANGE_COUNTER it was broadcast under."""

    volume_total: Optional[int]
    tank_type: Optional[int]
    config_change_counter: int

    def as_dict(self) -> dict[str, Any]:
        """Form stored in the config entry."""
        return {
            "volume_total": self.volume_total,
            "tank_type": self.tank_type,
            "config_change_counter": self.config_change_counter,
        }

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> Optional[TankDescription]:
        """
        Description stored in the config entry.

        Args:
            data: Output of as_dict, or None

        Returns:
            TankDescription, None if nothing usable was stored
        """
        if not data:
            return None
        try:
            return cls(data["volume_total"], data["tank_type"], data["config_change_counter"])
        except KeyError:
            return None


def description_of(rsp: strx.ScanResponse, config_change_counter: int) -> Optional[TankDescription]:
    """
    Tank description a scan response carries in plaintext.

    Args:
        rsp: Scan response
        config_change_counter: CONFIG_CHANGE_COUNTER the scan response belongs to

    Returns:
        TankDescription, None if the mode withholds it
    """
    volume = rsp.tank_volume_total
    tank_type = None if rsp.tank_type == strx.TANK_TYPE_UNKNOWN else rsp.tank_type
    in_window = rsp.beacon_mode == strx.BEACON_MED_SECURITY and (volume is not None or tank_type is not None)
    if rsp.beacon_mode not in DESCRIPTION_PLAIN_MODES and not in_window:
        return None
    return TankDescription(volume, tank_type, config_change_counter)


@dataclass
class Result:
    """What the caller has to act on after one update."""

    request_scan: bool = False  # scan response missing or out of date, keep asking
    scan_now: bool = False  # something just changed, ask right away
    description_changed: bool = False


class STRxDevice:
    """
    Broadcast state of one STRx device.

    A scan response is bound to the CONFIG_CHANGE_COUNTER of the advertising
    packet it arrived with. It is stale while the advertising packet shows a
    different counter, or while the counters went back (reboot, MESSAGE_COUNTER
    wrap) and no scan response with the new BOOT_COUNTER arrived yet. A stale
    scan response asks for an active scan and does not count MIC failures.

    A scan response whose bytes change while the device is followed was just
    received. The one in the first callback may be cached from long before, so
    it is used to read the level but its tank description is only taken once
    it is confirmed: CONFIRM_SECONDS of active scanning under one counter.
    """

    def __init__(self, name: str, key: Optional[bytes] = None,
                 description: Optional[TankDescription] = None) -> None:
        """
        Args:
            name: Name used in log messages
            key: Encryption key, None if the user gave none
            description: Tank description remembered from an earlier run
        """
        self.name = name
        self.key = key
        self.description = description
        self.scan_response: Optional[strx.ScanResponse] = None
        self.advertisement: Optional[strx.Advertisement] = None
        self.protocol_major: Optional[int] = None
        self.level_permille: Optional[int] = None
        self.status = STATUS_WAITING_SCAN_RESPONSE
        self.stale = False

        self._rsp_bytes: Optional[bytes] = None
        self._rsp_ccc: Optional[int] = None
        self._rsp_confirmed = False
        self._rsp_at: Optional[float] = None
        self._accepted_rsp_bytes: Optional[bytes] = None
        self._guard = strx.CounterGuard()
        self._mic_failures = 0
        self._failed_message: Optional[int] = None

        self._last_heard: Optional[float] = None
        self._adv_ccc: Optional[int] = None
        self._ccc_since: Optional[float] = None
        self._active_since: Optional[float] = None

    # Public interface

    def update(self, service_data: Mapping[str, bytes], now: float, active: bool = False) -> Result:
        """
        Take in the service data of one scanner callback.

        Args:
            service_data: Service data by UUID, either packet may be missing
            now: Time the callback is handled, monotonic seconds
            active: Whether the scanner that heard it scans actively right now

        Returns:
            Result the caller has to act on
        """
        result = Result()
        first = self._last_heard is None
        if not first and now - self._last_heard >= SILENCE_SECONDS:
            _LOGGER.debug("%s: heard again after %.0f s", self.name, now - self._last_heard)
            self._ccc_since = None
            self._active_since = None
            result.scan_now = True
        self._last_heard = now
        if active:
            if self._active_since is None:
                self._active_since = now
        else:
            self._active_since = None

        payload = service_data.get(strx.ADVERTISING_UUID)
        if payload is not None:
            try:
                self.advertisement = strx.parse_advertisement(bytes(payload))
            except ValueError as err:
                _LOGGER.debug("%s: %s", self.name, err)

        payload = service_data.get(strx.SCAN_RESPONSE_UUID)
        if payload is not None and bytes(payload) != self._rsp_bytes:
            self._adopt_scan_response(bytes(payload), now, fresh=not first, result=result)

        adv = self.advertisement
        if adv is not None:
            self._follow_counter(adv, now, result)
            self._confirm_if_due(adv, now, result)
            self._process(adv, result)

        if first and not self._rsp_confirmed:
            result.scan_now = True
        if result.scan_now:
            result.request_scan = True
        return result

    @property
    def tank_description(self) -> Optional[TankDescription]:
        """Tank description valid for the current advertising packet, None if unknown."""
        adv = self.advertisement
        if self.description is None:
            return None
        if adv is None:
            # Nothing heard yet, the remembered description stands until a packet says otherwise
            return self.description
        if self.description.config_change_counter != adv.config_change_counter:
            return None
        return self.description

    @property
    def tank_volume_total(self) -> Optional[int]:
        """Total tank volume in liters, None if unknown or withheld."""
        description = self.tank_description
        return description.volume_total if description else None

    @property
    def tank_type(self) -> Optional[int]:
        """TANK_TYPE, None if unknown or withheld."""
        description = self.tank_description
        return description.tank_type if description else None

    @property
    def beacon_mode(self) -> Optional[int]:
        """BEACON_MODE of the current scan response."""
        return self.scan_response.beacon_mode if self.scan_response else None

    @property
    def level_pct(self) -> Optional[float]:
        """Tank level in percent."""
        return None if self.level_permille is None else self.level_permille / 10

    @property
    def volume_l(self) -> Optional[float]:
        """Fluid volume in liters, None while level or total volume is unknown."""
        total = self.tank_volume_total
        if self.level_permille is None or total is None:
            return None
        return self.level_permille / 1000 * total

    # Scan response

    def _adopt_scan_response(self, payload: bytes, now: float, fresh: bool, result: Result) -> None:
        """Take a scan response whose bytes differ from the cached one."""
        if len(payload) > PROTOCOL_MAJOR_OFFSET and payload[PROTOCOL_MAJOR_OFFSET] != SUPPORTED_PROTOCOL_MAJOR:
            self._rsp_bytes = payload
            self.protocol_major = payload[PROTOCOL_MAJOR_OFFSET]
            self.scan_response = None
            return
        try:
            rsp = strx.parse_scan_response(payload)
        except ValueError as err:
            _LOGGER.debug("%s: %s", self.name, err)
            return

        self._rsp_bytes = payload
        self.protocol_major = rsp.protocol_major
        self.scan_response = rsp
        self._rsp_confirmed = fresh
        self._rsp_at = now
        self._mic_failures = 0
        self._failed_message = None
        self._bind_scan_response(self.advertisement, result)
        _LOGGER.debug("%s: %s scan response %s, BOOT_COUNTER %d, CONFIG_CHANGE_COUNTER %s",
                      self.name, "new" if fresh else "cached",
                      strx.BEACON_MODE_NAMES.get(rsp.beacon_mode, rsp.beacon_mode),
                      rsp.boot_counter, self._rsp_ccc)

    def _bind_scan_response(self, adv: Optional[strx.Advertisement], result: Result) -> None:
        """Bind the scan response to the CONFIG_CHANGE_COUNTER of adv."""
        if adv is None:
            self._rsp_ccc = None
            return
        self._rsp_ccc = adv.config_change_counter
        if self._rsp_confirmed:
            self._remember_description(result)

    def _follow_counter(self, adv: strx.Advertisement, now: float, result: Result) -> None:
        """Note when CONFIG_CHANGE_COUNTER moves, a scan now finds what changed."""
        ccc = adv.config_change_counter
        if ccc != self._adv_ccc:
            if self._adv_ccc is not None:
                _LOGGER.debug("%s: CONFIG_CHANGE_COUNTER moved to %d", self.name, ccc)
                result.scan_now = True
            self._adv_ccc = ccc
            self._ccc_since = now
        elif self._ccc_since is None:
            self._ccc_since = now

    def _confirm_if_due(self, adv: strx.Advertisement, now: float, result: Result) -> None:
        """Take the scan response as current once active scanning had time to replace it."""
        if self.scan_response is None or self._active_since is None or self._ccc_since is None:
            return
        if now - max(self._active_since, self._ccc_since) < CONFIRM_SECONDS:
            return
        if self._rsp_ccc == adv.config_change_counter:
            if self._rsp_confirmed:
                return
        elif self._rsp_at is None or self._rsp_at < self._ccc_since - REBIND_SECONDS:
            # Every change of the counter changes the scan response, so one older than
            # the change is not its scan response: that one is still to come
            return
        _LOGGER.debug("%s: scan response confirmed for CONFIG_CHANGE_COUNTER %d",
                      self.name, adv.config_change_counter)
        self._rsp_confirmed = True
        self._bind_scan_response(adv, result)

    def _remember_description(self, result: Result) -> None:
        """Keep the tank description of the scan response if it carries one in plaintext."""
        if self.scan_response is None or self._rsp_ccc is None:
            return
        description = description_of(self.scan_response, self._rsp_ccc)
        if description is not None and description != self.description:
            self.description = description
            result.description_changed = True

    # Advertising packet

    def _process(self, adv: strx.Advertisement, result: Result) -> None:
        """Check the scan response is current and read the level of adv."""
        if self.protocol_major is not None and self.protocol_major != SUPPORTED_PROTOCOL_MAJOR:
            self.stale = False
            self._set(None, STATUS_UNSUPPORTED_PROTOCOL)
            return

        rsp = self.scan_response
        if rsp is None:
            result.request_scan = True
            self._set(None, STATUS_WAITING_SCAN_RESPONSE)
            return
        if self._rsp_ccc is None:
            self._bind_scan_response(adv, result)

        config_changed = adv.config_change_counter != self._rsp_ccc
        last = self._guard.last
        regressed = last is not None and (rsp.boot_counter, adv.message_counter) < last
        if regressed and not rsp.encrypted and not config_changed:
            # Plaintext has nothing to protect: take a reboot or factory reset without waiting for BOOT_COUNTER
            _LOGGER.debug("%s: counters restarted", self.name)
            self._guard = strx.CounterGuard()
            regressed = False
        outdated = regressed and self._rsp_bytes == self._accepted_rsp_bytes

        was_stale = self.stale
        self.stale = config_changed or outdated
        if self.stale:
            result.request_scan = True
            if not was_stale:
                result.scan_now = True
                _LOGGER.debug("%s: %s, waiting for a new scan response", self.name,
                              "counters restarted" if outdated else
                              f"scan response is for CONFIG_CHANGE_COUNTER {self._rsp_ccc}")
        if outdated:
            self.status = STATUS_WAITING_SCAN_RESPONSE
            return
        if config_changed and not rsp.encrypted:
            # The mode may have changed too, LEVEL cannot be trusted as plaintext
            self._set(None, STATUS_WAITING_SCAN_RESPONSE)
            return

        self._read_level(rsp, adv)

    def _read_level(self, rsp: strx.ScanResponse, adv: strx.Advertisement) -> None:
        """Verify and decrypt LEVEL as the mode calls for."""
        mode = rsp.beacon_mode
        if mode not in strx.BEACON_MODE_NAMES:
            self._set(None, STATUS_UNKNOWN_MODE)
            return
        if mode == strx.BEACON_OFF:
            self._set(None, STATUS_BROADCAST_OFF)
            return
        if mode == strx.BEACON_PLAIN and self.key is not None:
            self._set(None, STATUS_DOWNGRADE_REJECTED)
            return

        if not rsp.encrypted:
            if not self._rsp_confirmed:
                # A cached scan response may say Open while the device encrypts by now
                self._set(None, STATUS_WAITING_SCAN_RESPONSE)
                return
            level = int.from_bytes(adv.level_bytes, "little")
            if level > LEVEL_MAX and level != strx.LEVEL_INVALID:
                _LOGGER.debug("%s: plaintext LEVEL %d out of range, ignored", self.name, level)
                return
            self._accept(rsp, adv, level)
            return

        if self.key is None:
            self._set(None, STATUS_KEY_NEEDED)
            return
        if adv.level_plain is None and not any(adv.mic):
            # The device could not encrypt and never falls back to plaintext
            self._set(None, STATUS_NO_MEASUREMENT)
            return
        level = strx.decrypt_level(self.key, rsp, adv)
        if level is None:
            self._mic_failed(adv)
            return
        self._mic_failures = 0
        self._failed_message = None
        self._accept(rsp, adv, level)

    def _mic_failed(self, adv: strx.Advertisement) -> None:
        """Count a failed tag, ask for the key once failures persist."""
        if self.stale or not self._rsp_confirmed:
            # The scan response may predate a reboot or a mode change, the key is not to blame yet
            self.status = STATUS_WAITING_SCAN_RESPONSE
            return
        if adv.message_counter != self._failed_message:
            self._failed_message = adv.message_counter
            self._mic_failures += 1
            _LOGGER.debug("%s: MIC failed for message %d, %d in a row",
                          self.name, adv.message_counter, self._mic_failures)
        if self._mic_failures >= MIC_FAIL_REAUTH:
            self._set(None, STATUS_KEY_REJECTED)

    def _accept(self, rsp: strx.ScanResponse, adv: strx.Advertisement, level: int) -> None:
        """Take a verified level unless it replays an older message."""
        verdict = self._guard.check(rsp.boot_counter, adv.message_counter)
        if verdict == strx.CounterGuard.REPLAY:
            _LOGGER.debug("%s: message %d/%d is older than the last accepted, rejected",
                          self.name, rsp.boot_counter, adv.message_counter)
            return
        self._accepted_rsp_bytes = self._rsp_bytes
        if level == strx.LEVEL_INVALID:
            self._set(None, STATUS_NO_MEASUREMENT)
        else:
            self._set(level, STATUS_WAITING_SCAN_RESPONSE if self.stale else STATUS_OK)

    def _set(self, level: Optional[int], status: str) -> None:
        """Set level and status together."""
        self.level_permille = level
        self.status = status
