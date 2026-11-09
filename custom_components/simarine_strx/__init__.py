"""Simarine STRx tank level from the BLE broadcast, one config entry per device."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .coordinator import STRxCoordinator

PLATFORMS = [Platform.SENSOR]

type STRxConfigEntry = ConfigEntry[STRxCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: STRxConfigEntry) -> bool:
    """Start listening to one device."""
    coordinator = STRxCoordinator(hass, entry)
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(coordinator.async_start())
    return True


async def async_unload_entry(hass: HomeAssistant, entry: STRxConfigEntry) -> bool:
    """Stop listening, issues are raised again after a reload if they still apply."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        entry.runtime_data.async_delete_issues()
    return unloaded
