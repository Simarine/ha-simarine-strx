"""Simarine STRx tank level from the BLE broadcast, one config entry per device."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .card import async_register_card
from .const import DOMAIN
from .coordinator import STRxCoordinator

PLATFORMS = [Platform.SENSOR]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

type STRxConfigEntry = ConfigEntry[STRxCoordinator]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Serve the tank card once, for all devices."""
    await async_register_card(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: STRxConfigEntry) -> bool:
    """Start listening to one device."""
    coordinator = STRxCoordinator(hass, entry)
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(coordinator.async_start())
    entry.async_on_unload(entry.add_update_listener(_async_entry_updated))
    return True


async def _async_entry_updated(hass: HomeAssistant, entry: STRxConfigEntry) -> None:
    """Options changed, or the stored tank description: applied without a reload."""
    entry.runtime_data.async_apply_options()


async def async_unload_entry(hass: HomeAssistant, entry: STRxConfigEntry) -> bool:
    """Stop listening, issues are raised again after a reload if they still apply."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        entry.runtime_data.async_delete_issues()
    return unloaded
