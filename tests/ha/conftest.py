"""Fixtures for running the integration inside Home Assistant."""

import pytest
from homeassistant.setup import async_setup_component


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
async def enable_bluetooth(hass, mock_bleak_scanner_start, mock_bluetooth_adapters):
    assert await async_setup_component(hass, "bluetooth", {})
    await hass.async_block_till_done()
    yield
