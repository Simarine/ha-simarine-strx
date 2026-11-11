"""The integration inside Home Assistant: discovery, key entry, reauth, repairs and the sensors."""

import struct

from unittest.mock import AsyncMock, patch

import pytest
from bleak.backends.device import BLEDevice
from habluetooth import BluetoothServiceInfoBleak
from habluetooth.central_manager import get_manager
from homeassistant import config_entries
from homeassistant.components.bluetooth import MONOTONIC_TIME
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.simarine_strx.const import (
    CONF_ENCRYPTION_KEY,
    CONF_MANUAL,
    CONF_MANUAL_TYPE,
    CONF_MANUAL_VOLUME,
    CONF_TANK,
    DOMAIN,
)
from custom_components.simarine_strx.strx import broadcast as strx

ADDRESS = "AA:BB:CC:DD:EE:01"
KEY = bytes.fromhex("4BD224860416877824974BAF9ED1E1E4")
ADV = strx.ADVERTISING_UUID
RSP = strx.SCAN_RESPONSE_UUID

pytestmark = pytest.mark.usefixtures("enable_bluetooth")


class Sim:
    """Firmware side of one device."""

    def __init__(self, mode=strx.BEACON_PLAIN, key=KEY, boot=7, msg=100, ccc=0, level=500,
                 volume=200, tank_type=1):
        self.mode, self.key, self.boot, self.msg, self.ccc = mode, key, boot, msg, ccc
        self.level, self.volume, self.tank_type = level, volume, tank_type

    def rsp(self):
        return struct.pack("<BBBHBHHB", 1, 1, 9, 42, self.mode, self.boot, self.volume, self.tank_type)

    def adv(self):
        if self.mode in strx.BEACON_MODES_ENCRYPTED:
            rsp = strx.parse_scan_response(self.rsp())
            level_bytes, mic = strx.encrypt_level(self.key, rsp, self.msg, self.ccc, self.level)
        else:
            level = strx.LEVEL_INVALID if self.mode == strx.BEACON_OFF else self.level
            level_bytes, mic = struct.pack("<H", level), bytes(4)
        return self.msg.to_bytes(3, "little") + level_bytes + mic + bytes([self.ccc])


class Radio:
    """Scanner side, merges service data per address like habluetooth."""

    def __init__(self, hass):
        self.hass = hass
        self.service_data = {}

    def push(self, payloads):
        """Hand one advertisement to the Bluetooth manager without waiting for its effects."""
        self.service_data.update(payloads)
        info = BluetoothServiceInfoBleak(
            name=ADDRESS, address=ADDRESS, rssi=-61, manufacturer_data={},
            service_data=dict(self.service_data), service_uuids=[], source="local",
            device=BLEDevice(ADDRESS, None, None), advertisement=None, connectable=True,
            time=MONOTONIC_TIME(), tx_power=None,
        )
        get_manager().scanner_adv_received(info)
        return info

    async def hear(self, payloads):
        info = self.push(payloads)
        await self.hass.async_block_till_done(wait_background_tasks=True)
        return info

    async def both(self, sim):
        return await self.hear({ADV: sim.adv(), RSP: sim.rsp()})

    async def adv(self, sim):
        return await self.hear({ADV: sim.adv()})


def state(hass, key):
    entity_id = {
        "level": "sensor.str1_0042_level",
        "volume": "sensor.str1_0042_volume",
        "status": "sensor.str1_0042_broadcast_status",
        "tank_type": "sensor.str1_0042_tank_type",
        "mode": "sensor.str1_0042_broadcast_mode",
        "total": "sensor.str1_0042_tank_volume",
    }[key]
    s = hass.states.get(entity_id)
    return s.state if s else None


async def add_entry(hass, key=None):
    entry = MockConfigEntry(domain=DOMAIN, unique_id=ADDRESS, title="STR1-0042",
                            data={CONF_ENCRYPTION_KEY: key.hex() if key else None, "product_type": 1})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def test_discovery_plain(hass):
    radio = Radio(hass)
    sim = Sim()
    await radio.both(sim)
    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert len(flows) == 1
    assert flows[0]["step_id"] == "bluetooth_confirm"
    assert flows[0]["context"]["title_placeholders"] == {"name": "STR1-0042"}

    result = await hass.config_entries.flow.async_configure(flows[0]["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "STR1-0042"
    assert result["data"] == {
        CONF_ENCRYPTION_KEY: None,
        "product_type": 1,
        CONF_TANK: {"volume_total": 200, "tank_type": 1, "config_change_counter": 0},
    }
    await hass.async_block_till_done()

    sim.msg += 1
    await radio.both(sim)
    assert state(hass, "level") == "50.0"
    assert state(hass, "volume") == "100.0"
    assert state(hass, "status") == "ok"
    assert state(hass, "tank_type") == "fresh_water"
    assert state(hass, "mode") == "open"
    assert state(hass, "total") == "200"


async def test_discovery_encrypted_key(hass):
    radio = Radio(hass)
    sim = Sim(mode=strx.BEACON_LOW_SECURITY)
    await radio.both(sim)
    flow = hass.config_entries.flow.async_progress_by_handler(DOMAIN)[0]
    result = await hass.config_entries.flow.async_configure(flow["flow_id"], {})
    assert result["step_id"] == "get_encryption_key"

    result = await hass.config_entries.flow.async_configure(flow["flow_id"], {CONF_ENCRYPTION_KEY: "zz"})
    assert result["errors"] == {CONF_ENCRYPTION_KEY: "invalid_key_format"}
    result = await hass.config_entries.flow.async_configure(flow["flow_id"], {CONF_ENCRYPTION_KEY: "00" * 16})
    assert result["errors"] == {CONF_ENCRYPTION_KEY: "decryption_failed"}
    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_ENCRYPTION_KEY: "4BD2 2486 0416 8778 2497 4BAF 9ED1 E1E4"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_ENCRYPTION_KEY] == KEY.hex()
    await hass.async_block_till_done()

    sim.msg += 1
    sim.level = 250
    await radio.both(sim)
    assert state(hass, "level") == "25.0"
    assert state(hass, "status") == "ok"


async def test_mode_change_requests_scan_then_reauth(hass):
    radio = Radio(hass)
    sim = Sim()
    with patch("homeassistant.components.bluetooth.async_request_active_scan", AsyncMock()) as scan:
        entry = await add_entry(hass)
        await radio.both(sim)
        sim.msg += 5
        await radio.adv(sim)
        assert state(hass, "level") == "50.0"
        scan.assert_not_called()

        # Switched to Low Security in the app, the new scan response is not in yet
        sim.mode, sim.ccc = strx.BEACON_LOW_SECURITY, 1
        sim.msg += 1
        await radio.adv(sim)
        assert state(hass, "status") == "waiting_scan_response"
        assert state(hass, "volume") == "unknown"
        scan.assert_called_once()

        await radio.both(sim)
        assert state(hass, "status") == "key_needed"
        flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        assert len(flows) == 1
        assert flows[0]["context"]["source"] == config_entries.SOURCE_REAUTH
        assert flows[0]["step_id"] == "get_encryption_key"

        result = await hass.config_entries.flow.async_configure(flows[0]["flow_id"], {CONF_ENCRYPTION_KEY: KEY.hex()})
        assert result["type"] is FlowResultType.ABORT
        assert result["reason"] == "reauth_successful"
        await hass.async_block_till_done()
        assert entry.data[CONF_ENCRYPTION_KEY] == KEY.hex()

        sim.msg += 1
        await radio.both(sim)
        assert state(hass, "level") == "50.0"
        assert state(hass, "status") == "ok"


async def test_downgrade_issue_cleared_by_reconfigure(hass):
    radio = Radio(hass)
    sim = Sim(mode=strx.BEACON_PLAIN)
    entry = await add_entry(hass, KEY)
    await radio.both(sim)
    assert state(hass, "status") == "downgrade_rejected"
    assert state(hass, "level") == "unknown"
    registry = ir.async_get(hass)
    assert registry.async_get_issue(DOMAIN, "encryption_downgrade_aabbccddee01")

    result = await entry.start_reconfigure_flow(hass)
    assert result["step_id"] == "reconfigure"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert entry.data[CONF_ENCRYPTION_KEY] is None
    assert not registry.async_get_issue(DOMAIN, "encryption_downgrade_aabbccddee01")

    sim.msg += 1
    await radio.both(sim)
    assert state(hass, "level") == "50.0"


async def test_medium_window_description_persisted(hass):
    radio = Radio(hass)
    sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=3)
    entry = await add_entry(hass, KEY)
    await radio.both(sim)
    assert entry.data[CONF_TANK] == {"volume_total": 200, "tank_type": 1, "config_change_counter": 3}

    sim.msg += 1
    sim.volume, sim.tank_type = 0xFFFF, 0xFF
    await radio.both(sim)
    assert state(hass, "total") == "200"
    assert state(hass, "volume") == "100.0"

    # Survives a reload with the fields still withheld
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    sim.msg += 1
    await radio.both(sim)
    assert state(hass, "total") == "200"


async def test_user_flow(hass):
    radio = Radio(hass)
    await radio.both(Sim())
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["step_id"] == "user"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"address": ADDRESS})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "STR1-0042"


async def test_user_flow_nothing_found(hass):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_devices_found"


async def test_medium_window_caught_during_setup(hass):
    radio = Radio(hass)
    sim = Sim(mode=strx.BEACON_MED_SECURITY, ccc=2)
    await radio.both(sim)
    flow = hass.config_entries.flow.async_progress_by_handler(DOMAIN)[0]

    # The window closes while the key is looked up in the app
    sim.msg += 60
    sim.volume, sim.tank_type = 0xFFFF, 0xFF
    await radio.both(sim)

    result = await hass.config_entries.flow.async_configure(flow["flow_id"], {})
    assert result["step_id"] == "get_encryption_key"
    result = await hass.config_entries.flow.async_configure(flow["flow_id"], {CONF_ENCRYPTION_KEY: KEY.hex()})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_TANK] == {"volume_total": 200, "tank_type": 1, "config_change_counter": 2}
    await hass.async_block_till_done()

    sim.msg += 1
    await radio.both(sim)
    assert state(hass, "total") == "200"
    assert state(hass, "volume") == "100.0"


async def test_key_checked_against_fresh_scan_response(hass):
    radio = Radio(hass)
    sim = Sim(mode=strx.BEACON_LOW_SECURITY)
    await radio.both(sim)
    flow = hass.config_entries.flow.async_progress_by_handler(DOMAIN)[0]
    result = await hass.config_entries.flow.async_configure(flow["flow_id"], {})
    assert result["step_id"] == "get_encryption_key"

    # Rebooted: new advertising packets, the cached scan response still has the old BOOT_COUNTER
    sim.boot, sim.msg = 8, 0
    await radio.adv(sim)

    async def active_scan(hass, duration=None):
        radio.push({RSP: sim.rsp()})

    with patch("homeassistant.components.bluetooth.async_request_active_scan", side_effect=active_scan):
        result = await hass.config_entries.flow.async_configure(flow["flow_id"], {CONF_ENCRYPTION_KEY: KEY.hex()})
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_key_while_not_broadcasting(hass):
    radio = Radio(hass)
    await radio.both(Sim(mode=strx.BEACON_LOW_SECURITY))
    flow = hass.config_entries.flow.async_progress_by_handler(DOMAIN)[0]
    await hass.config_entries.flow.async_configure(flow["flow_id"], {})

    # The app is connected, nothing heard for a minute
    later = MONOTONIC_TIME() + 60
    with patch("custom_components.simarine_strx.config_flow.MONOTONIC_TIME", return_value=later):
        result = await hass.config_entries.flow.async_configure(flow["flow_id"], {CONF_ENCRYPTION_KEY: "00" * 16})
        assert result["errors"] == {CONF_ENCRYPTION_KEY: "not_broadcasting"}

        # The right key still decrypts the last broadcast
        result = await hass.config_entries.flow.async_configure(flow["flow_id"], {CONF_ENCRYPTION_KEY: KEY.hex()})
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_each_change_requests_scan_at_once(hass):
    radio = Radio(hass)
    sim = Sim()
    with patch("homeassistant.components.bluetooth.async_request_active_scan", AsyncMock()) as scan:
        await add_entry(hass)
        await radio.both(sim)
        for ccc in (1, 2):
            sim.msg += 1
            sim.ccc, sim.volume = ccc, 200 + ccc
            await radio.adv(sim)
            await radio.both(sim)
        assert scan.call_count == 2
        assert state(hass, "total") == "202"


async def test_tank_description_outlasts_device(hass):
    radio = Radio(hass)
    entry = await add_entry(hass)
    info = await radio.both(Sim())
    assert state(hass, "total") == "200"

    # Out of range
    entry.runtime_data._async_handle_unavailable(info)
    await hass.async_block_till_done()
    assert state(hass, "level") == "unavailable"
    assert state(hass, "total") == "200"
    assert state(hass, "tank_type") == "fresh_water"

    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert state(hass, "total") == "200"


async def test_manual_tank_description(hass):
    radio = Radio(hass)
    entry = await add_entry(hass, KEY)
    await radio.both(Sim(mode=strx.BEACON_HIGH_SECURITY, volume=0xFFFF, tank_type=0xFF))
    assert state(hass, "total") == "unknown"

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["step_id"] == "init"
    result = await hass.config_entries.options.async_configure(result["flow_id"], {CONF_MANUAL: True})
    assert result["errors"] == {"base": "manual_empty"}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_MANUAL: True, CONF_MANUAL_VOLUME: 400.0, CONF_MANUAL_TYPE: "fuel"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert entry.options == {CONF_MANUAL: True, CONF_MANUAL_VOLUME: 400, CONF_MANUAL_TYPE: "fuel"}
    assert state(hass, "total") == "400"
    assert state(hass, "tank_type") == "fuel"
    assert state(hass, "volume") == "200.0"
    assert hass.states.get("sensor.str1_0042_tank_volume").attributes["source"] == "manual"

    # Turned off, the values are kept for later
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_MANUAL: False, CONF_MANUAL_VOLUME: 400, CONF_MANUAL_TYPE: "fuel"})
    await hass.async_block_till_done()
    assert entry.options[CONF_MANUAL_VOLUME] == 400
    assert state(hass, "total") == "unknown"
    assert state(hass, "volume") == "unknown"
