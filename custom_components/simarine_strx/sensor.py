"""Sensors of one STRx device, fed by its BLE broadcast."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.bluetooth.passive_update_coordinator import (
    PassiveBluetoothCoordinatorEntity,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
    UnitOfVolume,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.typing import StateType

from . import STRxConfigEntry
from .const import CONF_PRODUCT_TYPE, DOMAIN, MANUFACTURER
from .coordinator import STRxCoordinator
from .strx import broadcast as strx
from .strx import device as strx_device

# ENUM sensor options by protocol value
TANK_TYPE_OPTIONS = {value: name.lower() for value, name in strx.TANK_TYPE_NAMES.items()}
BROADCAST_MODE_OPTIONS = {
    strx.BEACON_OFF: "off",
    strx.BEACON_HIGH_SECURITY: "high_security",
    strx.BEACON_MED_SECURITY: "medium_security",
    strx.BEACON_LOW_SECURITY: "low_security",
    strx.BEACON_PLAIN: "open",
}


@dataclass(frozen=True, kw_only=True)
class STRxSensorDescription(SensorEntityDescription):
    """Sensor description with the function reading its value."""

    value_fn: Callable[[STRxCoordinator], StateType]
    # Stored rather than live: stays available while the device is out of range or not heard yet
    available_offline: bool = False


SENSORS: tuple[STRxSensorDescription, ...] = (
    STRxSensorDescription(
        key="level",
        translation_key="level",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda c: c.device.level_pct,
    ),
    STRxSensorDescription(
        key="volume",
        translation_key="volume",
        native_unit_of_measurement=UnitOfVolume.LITERS,
        device_class=SensorDeviceClass.VOLUME_STORAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda c: c.device.volume_l,
    ),
    STRxSensorDescription(
        key="tank_volume_total",
        translation_key="tank_volume_total",
        native_unit_of_measurement=UnitOfVolume.LITERS,
        device_class=SensorDeviceClass.VOLUME_STORAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=0,
        value_fn=lambda c: c.device.tank_volume_total,
        available_offline=True,
    ),
    STRxSensorDescription(
        key="tank_type",
        translation_key="tank_type",
        device_class=SensorDeviceClass.ENUM,
        options=list(TANK_TYPE_OPTIONS.values()),
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: TANK_TYPE_OPTIONS.get(c.device.tank_type),
        available_offline=True,
    ),
    STRxSensorDescription(
        key="broadcast_mode",
        translation_key="broadcast_mode",
        device_class=SensorDeviceClass.ENUM,
        options=list(BROADCAST_MODE_OPTIONS.values()),
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: BROADCAST_MODE_OPTIONS.get(c.device.beacon_mode),
    ),
    STRxSensorDescription(
        key="status",
        translation_key="status",
        device_class=SensorDeviceClass.ENUM,
        options=list(strx_device.STATUSES),
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: c.device.status,
    ),
    STRxSensorDescription(
        key="rssi",
        translation_key="rssi",
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda c: c.rssi,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: STRxConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add the sensors of one device."""
    coordinator = entry.runtime_data
    async_add_entities(STRxSensor(coordinator, description) for description in SENSORS)


class STRxSensor(PassiveBluetoothCoordinatorEntity[STRxCoordinator], SensorEntity):
    """One value of the STRx broadcast."""

    entity_description: STRxSensorDescription
    _attr_has_entity_name = True

    def __init__(self, coordinator: STRxCoordinator, description: STRxSensorDescription) -> None:
        """
        Args:
            coordinator: Coordinator of the device
            description: Which value this sensor shows
        """
        super().__init__(coordinator)
        self.entity_description = description
        address = coordinator.address
        entry = coordinator.entry
        self._attr_unique_id = f"{address}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            connections={(CONNECTION_BLUETOOTH, address)},
            name=entry.title,
            manufacturer=MANUFACTURER,
            model=strx.PRODUCT_NAMES.get(entry.data.get(CONF_PRODUCT_TYPE), "STRx"),
        )

    @property
    def available(self) -> bool:
        """Live values follow the device, a stored tank description outlasts it."""
        if self.entity_description.available_offline and self.native_value is not None:
            return True
        return super().available

    @property
    def native_value(self) -> StateType:
        """Current value from the device state."""
        return self.entity_description.value_fn(self.coordinator)
