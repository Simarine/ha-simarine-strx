"""Helpers around the Bluetooth scanning of Home Assistant, shared by the coordinator and the config flow."""

from __future__ import annotations

import logging
from collections.abc import Coroutine
from typing import Any

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothScanningMode, BluetoothServiceInfoBleak
from homeassistant.core import HomeAssistant

from .const import ACTIVE_SCAN_DURATION

_LOGGER = logging.getLogger(__name__)


def scanning_actively(hass: HomeAssistant, service_info: BluetoothServiceInfoBleak) -> bool:
    """
    Whether the scanner that heard an advertisement scans actively right now.

    An active scanner asks for the scan response on each advertisement, so the
    scan response in its service info is current.

    Args:
        hass: Home Assistant
        service_info: Service info of the advertisement

    Returns:
        True if active, False if passive or unknown
    """
    scanner = bluetooth.async_scanner_by_source(hass, service_info.source)
    return scanner is not None and getattr(scanner, "current_mode", None) is BluetoothScanningMode.ACTIVE


def active_scan(hass: HomeAssistant, name: str) -> Coroutine[Any, Any, None] | None:
    """
    One on-demand active scan on the adapters and proxies that scan on demand.

    Args:
        hass: Home Assistant
        name: Device name for the log

    Returns:
        Coroutine to run as a task, None where Home Assistant has no on-demand scan
    """
    request = getattr(bluetooth, "async_request_active_scan", None)
    if request is None:
        return None

    async def _run() -> None:
        try:
            await request(hass, duration=ACTIVE_SCAN_DURATION)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("%s: active scan request failed", name, exc_info=True)

    return _run()
