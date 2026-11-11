"""Coordinator feeding the broadcast of one STRx device into its state machine."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.bluetooth import (
    MONOTONIC_TIME,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
)
from homeassistant.components.bluetooth.passive_update_coordinator import (
    PassiveBluetoothDataUpdateCoordinator,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import (
    ACTIVE_SCAN_INTERVAL,
    CONF_ENCRYPTION_KEY,
    CONF_TANK,
    DOMAIN,
    ISSUE_DOWNGRADE,
    ISSUE_UNSUPPORTED,
)
from .scanning import active_scan, scanning_actively
from .strx import device as strx_device

_LOGGER = logging.getLogger(__name__)

# Statuses that need a key from the user
KEY_STATUSES = (strx_device.STATUS_KEY_NEEDED, strx_device.STATUS_KEY_REJECTED)

# Repair issue raised while the device is in a status
STATUS_ISSUES = {
    strx_device.STATUS_DOWNGRADE_REJECTED: ISSUE_DOWNGRADE,
    strx_device.STATUS_UNSUPPORTED_PROTOCOL: ISSUE_UNSUPPORTED,
}


class STRxCoordinator(PassiveBluetoothDataUpdateCoordinator):
    """Receives the broadcast of one device and acts on what its state machine reports."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """
        Args:
            hass: Home Assistant
            entry: Config entry of the device, unique id is the address
        """
        super().__init__(hass, _LOGGER, entry.unique_id, BluetoothScanningMode.ACTIVE, connectable=False)
        self.entry = entry
        key = entry.data.get(CONF_ENCRYPTION_KEY)
        self.device = strx_device.STRxDevice(
            entry.title,
            bytes.fromhex(key) if key else None,
            strx_device.TankDescription.from_dict(entry.data.get(CONF_TANK)),
        )
        self.rssi: int | None = None
        self._status: str | None = None
        self._last_scan_request: float | None = None
        self._scan_task: asyncio.Task[None] | None = None

    @callback
    def _async_handle_bluetooth_event(self, service_info: BluetoothServiceInfoBleak,
                                      change: BluetoothChange) -> None:
        """Feed one callback into the state machine, then notify the entities."""
        self.rssi = service_info.rssi
        result = self.device.update(service_info.service_data, MONOTONIC_TIME(),
                                    scanning_actively(self.hass, service_info))
        if result.request_scan:
            self._async_request_active_scan(result.scan_now)
        if result.description_changed:
            self._async_store_description()
        if self.device.status != self._status:
            self._async_status_changed(self._status, self.device.status)
            self._status = self.device.status
        super()._async_handle_bluetooth_event(service_info, change)

    @callback
    def async_delete_issues(self) -> None:
        """Remove the repair issues of this device."""
        for issue in STATUS_ISSUES.values():
            ir.async_delete_issue(self.hass, DOMAIN, self._issue_id(issue))

    # Helpers

    @callback
    def _async_status_changed(self, old: str | None, new: str) -> None:
        """Start reauth and raise or clear repair issues on a status change."""
        _LOGGER.debug("%s: status %s -> %s", self.entry.title, old, new)
        if new in KEY_STATUSES:
            self.entry.async_start_reauth(self.hass)

        for status, issue in STATUS_ISSUES.items():
            if new == status:
                ir.async_create_issue(
                    self.hass, DOMAIN, self._issue_id(issue),
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key=issue,
                    translation_placeholders={"name": self.entry.title},
                )
            elif old == status:
                ir.async_delete_issue(self.hass, DOMAIN, self._issue_id(issue))

    @callback
    def _async_request_active_scan(self, now: bool) -> None:
        """
        Ask for an active scan so the current scan response arrives.

        Args:
            now: Something just changed: ask right away unless a scan is running,
                otherwise at most once per ACTIVE_SCAN_INTERVAL
        """
        if self._scan_task is not None and not self._scan_task.done():
            return
        started = MONOTONIC_TIME()
        if (not now and self._last_scan_request is not None
                and started - self._last_scan_request < ACTIVE_SCAN_INTERVAL):
            return
        if (scan := active_scan(self.hass, self.entry.title)) is None:
            # Older Home Assistant: the ACTIVE registration is all there is
            return
        self._last_scan_request = started
        _LOGGER.debug("%s: requesting an active scan", self.entry.title)
        self._scan_task = self.entry.async_create_background_task(
            self.hass, scan, f"{DOMAIN} active scan {self.address}"
        )

    @callback
    def _async_store_description(self) -> None:
        """Persist the tank description so it outlives a restart."""
        description = self.device.description
        self.hass.config_entries.async_update_entry(
            self.entry,
            data={**self.entry.data, CONF_TANK: description.as_dict() if description else None},
        )

    def _issue_id(self, issue: str) -> str:
        """Repair issue id of this device."""
        return f"{issue}_{self.address.replace(':', '').lower()}"
