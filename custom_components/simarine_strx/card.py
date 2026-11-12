"""Simarine tank dashboard card, served and loaded by the integration itself."""

from __future__ import annotations

from pathlib import Path

from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_integration

from .const import DOMAIN

CARD_FILE = Path(__file__).parent / "frontend" / "simarine-tank-card.js"
CARD_URL = f"/{DOMAIN}/simarine-tank-card.js"


async def async_register_card(hass: HomeAssistant) -> None:
    """
    Serve the card and load it in every dashboard.

    Nothing to do without the frontend, as in the tests.

    Args:
        hass: Home Assistant
    """
    if "frontend" not in hass.config.components:
        return
    from homeassistant.components.frontend import add_extra_js_url  # noqa: PLC0415

    integration = await async_get_integration(hass, DOMAIN)
    await hass.http.async_register_static_paths([StaticPathConfig(CARD_URL, str(CARD_FILE), True)])
    # The version makes browsers fetch the card again after an update
    add_extra_js_url(hass, f"{CARD_URL}?v={integration.version}")
