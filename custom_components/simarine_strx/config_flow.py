"""Config flow of Simarine STRx: Bluetooth discovery, encryption key, reauth and reconfigure."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
    async_last_service_info,
    async_process_advertisements,
)
from homeassistant.config_entries import (
    SOURCE_REAUTH,
    SOURCE_RECONFIGURE,
    ConfigFlow,
    ConfigFlowResult,
)
from homeassistant.const import CONF_ADDRESS

from .const import CONF_ENCRYPTION_KEY, CONF_PRODUCT_TYPE, DOMAIN, SCAN_RESPONSE_TIMEOUT
from .strx import broadcast as strx
from .strx.device import SUPPORTED_PROTOCOL_MAJOR

# BEACON_MODE as the Simarine Connect app names it
MODE_NAMES = {
    strx.BEACON_OFF: "Broadcast Mode off",
    strx.BEACON_HIGH_SECURITY: "High Security",
    strx.BEACON_MED_SECURITY: "Medium Security",
    strx.BEACON_LOW_SECURITY: "Low Security",
    strx.BEACON_PLAIN: "Open",
}


def _is_strx(info: BluetoothServiceInfoBleak) -> bool:
    """True if the advertisement carries either STRx service data UUID."""
    return strx.ADVERTISING_UUID in info.service_data or strx.SCAN_RESPONSE_UUID in info.service_data


def _scan_response(info: BluetoothServiceInfoBleak | None) -> strx.ScanResponse | None:
    """Scan response in the service info, None if missing or unparsable."""
    payload = info.service_data.get(strx.SCAN_RESPONSE_UUID) if info else None
    if payload is None:
        return None
    try:
        return strx.parse_scan_response(payload)
    except ValueError:
        return None


class SimarineSTRxConfigFlow(ConfigFlow, domain=DOMAIN):
    """One config entry per STRx device, keyed by its address."""

    VERSION = 2

    def __init__(self) -> None:
        self._address: str | None = None
        self._title: str | None = None
        self._scan_response: strx.ScanResponse | None = None
        self._discovered: dict[str, str] = {}

    # Discovery

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak) -> ConfigFlowResult:
        """Device found by the Bluetooth integration."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._address = discovery_info.address
        self._scan_response = _scan_response(discovery_info) or await self._async_wait_scan_response()
        self.context["title_placeholders"] = {"name": self._name()}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Confirm a discovered device."""
        errors: dict[str, str] = {}
        if user_input is not None:
            if self._scan_response is None:
                self._scan_response = await self._async_wait_scan_response()
            if self._scan_response is not None:
                return await self._async_step_device()
            errors["base"] = "no_scan_response"

        self._set_confirm_only()
        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={"name": self._name(), "mode": self._mode_name()},
            errors=errors,
        )

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Pick one of the STRx devices in range."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(self._address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._scan_response = await self._async_wait_scan_response()
            if self._scan_response is not None:
                return await self._async_step_device()
            errors["base"] = "no_scan_response"

        configured = self._async_current_ids(include_ignore=False)
        for info in async_discovered_service_info(self.hass, connectable=False):
            if info.address in configured or info.address in self._discovered or not _is_strx(info):
                continue
            rsp = _scan_response(info)
            self._discovered[info.address] = f"{rsp.display_name} ({info.address})" if rsp else info.address
        if not self._discovered:
            return self.async_abort(reason="no_devices_found")

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required(CONF_ADDRESS): vol.In(self._discovered)}),
            errors=errors,
        )

    async def _async_step_device(self) -> ConfigFlowResult:
        """Scan response in hand: ask for the key if the mode encrypts."""
        rsp = self._scan_response
        if rsp.protocol_major != SUPPORTED_PROTOCOL_MAJOR:
            return self.async_abort(reason="unsupported_protocol")
        if rsp.encrypted:
            return await self.async_step_get_encryption_key()
        return self._async_finish(None)

    # Encryption key

    async def async_step_get_encryption_key(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Encryption key shown in the Simarine Connect app."""
        errors: dict[str, str] = {}
        if user_input is not None:
            key, error = self._validate_key(user_input[CONF_ENCRYPTION_KEY])
            if error is None:
                return self._async_finish(key)
            errors[CONF_ENCRYPTION_KEY] = error

        return self.async_show_form(
            step_id="get_encryption_key",
            data_schema=vol.Schema({vol.Required(CONF_ENCRYPTION_KEY): str}),
            description_placeholders={"name": self._name()},
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """The device started encrypting, or its key was replaced."""
        entry = self._get_reauth_entry()
        self._address = entry.unique_id
        self._title = entry.title
        return await self.async_step_get_encryption_key()

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Change the key, or clear it to accept an unencrypted broadcast again."""
        entry = self._get_reconfigure_entry()
        self._address = entry.unique_id
        self._title = entry.title
        errors: dict[str, str] = {}
        if user_input is not None:
            text = user_input.get(CONF_ENCRYPTION_KEY, "").strip()
            if not text:
                return self._async_finish(None)
            key, error = self._validate_key(text)
            if error is None:
                return self._async_finish(key)
            errors[CONF_ENCRYPTION_KEY] = error

        schema = self.add_suggested_values_to_schema(
            vol.Schema({vol.Optional(CONF_ENCRYPTION_KEY): str}),
            {CONF_ENCRYPTION_KEY: entry.data.get(CONF_ENCRYPTION_KEY)} if entry.data.get(CONF_ENCRYPTION_KEY) else {},
        )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=schema,
            description_placeholders={"name": entry.title},
            errors=errors,
        )

    # Helpers

    def _async_finish(self, key: str | None) -> ConfigFlowResult:
        """Create the entry, or update the key of an existing one and reload it."""
        if self.source == SOURCE_REAUTH:
            return self.async_update_reload_and_abort(
                self._get_reauth_entry(), data_updates={CONF_ENCRYPTION_KEY: key}
            )
        if self.source == SOURCE_RECONFIGURE:
            return self.async_update_reload_and_abort(
                self._get_reconfigure_entry(), data_updates={CONF_ENCRYPTION_KEY: key}
            )
        rsp = self._scan_response
        return self.async_create_entry(
            title=rsp.display_name,
            data={CONF_ENCRYPTION_KEY: key, CONF_PRODUCT_TYPE: rsp.product_type},
        )

    def _validate_key(self, text: str) -> tuple[str | None, str | None]:
        """
        Check the format of a key and, when the broadcast allows it, that it decrypts.

        Args:
            text: Key as entered, 32 hexadecimal digits, spaces and colons allowed

        Returns:
            (key as lowercase hex, None) or (None, error key)
        """
        try:
            key = strx.key_from_hex(text)
        except ValueError:
            return None, "invalid_key_format"
        if self._key_verifies(key) is False:
            return None, "decryption_failed"
        return key.hex(), None

    def _key_verifies(self, key: bytes) -> bool | None:
        """True or False against the last broadcast, None if it cannot tell."""
        info = async_last_service_info(self.hass, self._address, connectable=False)
        rsp = _scan_response(info)
        payload = info.service_data.get(strx.ADVERTISING_UUID) if info else None
        if rsp is None or payload is None or not rsp.encrypted:
            return None
        try:
            adv = strx.parse_advertisement(payload)
        except ValueError:
            return None
        if adv.level_plain is None and not any(adv.mic):
            # The device could not encrypt, nothing to verify against
            return None
        return strx.decrypt_level(key, rsp, adv) is not None

    async def _async_wait_scan_response(self) -> strx.ScanResponse | None:
        """Scan response of the device, asking for an active scan if none is cached."""
        rsp = _scan_response(async_last_service_info(self.hass, self._address, connectable=False))
        if rsp is not None:
            return rsp
        try:
            info = await async_process_advertisements(
                self.hass,
                lambda info: strx.SCAN_RESPONSE_UUID in info.service_data,
                BluetoothCallbackMatcher(address=self._address, connectable=False),
                BluetoothScanningMode.ACTIVE,
                SCAN_RESPONSE_TIMEOUT,
            )
        except TimeoutError:
            return None
        return _scan_response(info)

    def _name(self) -> str:
        """Name shown in the flow."""
        if self._scan_response is not None:
            return self._scan_response.display_name
        return self._title or self._address or "STRx"

    def _mode_name(self) -> str:
        """Broadcast mode as the app names it."""
        if self._scan_response is None:
            return "unknown"
        mode = self._scan_response.beacon_mode
        return MODE_NAMES.get(mode, f"0x{mode:02x}")
