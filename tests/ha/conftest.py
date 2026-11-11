"""Fixtures for running the integration inside Home Assistant."""

from unittest.mock import patch

import pytest
from homeassistant.setup import async_setup_component


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture(autouse=True)
def active_scanning():
    """
    The scanner scans actively, so a scan response counts as current at once,
    and the flow waits only briefly for a newer scan response.

    The tests run within milliseconds, so every scan response would count as
    arriving just before a counter change: binding one to a later counter is
    covered by tests/test_device.py with a clock of its own.
    """
    with (
        patch("custom_components.simarine_strx.coordinator.scanning_actively", return_value=True),
        patch("custom_components.simarine_strx.config_flow.scanning_actively", return_value=True),
        patch("custom_components.simarine_strx.strx.device.CONFIRM_SECONDS", 0),
        patch("custom_components.simarine_strx.strx.device.REBIND_SECONDS", -1e9),
        patch("custom_components.simarine_strx.config_flow.SCAN_RESPONSE_TIMEOUT", 0.2),
    ):
        yield


@pytest.fixture
async def enable_bluetooth(hass, mock_bleak_scanner_start, mock_bluetooth_adapters):
    assert await async_setup_component(hass, "bluetooth", {})
    await hass.async_block_till_done()
    yield
