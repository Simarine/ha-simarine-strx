"""
Parser for the STRx BLE broadcast, protocol v1.9.

Turns the two service data payloads of an STRx device into fields, verifies and
decrypts the level in the modes that protect it, and builds the display name.
Nothing here talks to a radio: hand in the payloads a BLE library gives you.

Copied unchanged from strx-ble-broadcast-protocol/examples/python/strx_broadcast.py,
update it from there rather than editing it here.

@see STRx-ble-advertising.md
"""

import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Service data UUIDs, either one identifies an STRx device
ADVERTISING_UUID = "ea4a9703-a497-42a7-a177-f5a0b3214a0e"
SCAN_RESPONSE_UUID = "ea4a96f3-a497-42a7-a177-f5a0b3214a0e"

# Service data payload sizes without the 16 byte UUID
ADVERTISING_PAYLOAD_SIZE = 10
SCAN_RESPONSE_PAYLOAD_SIZE = 11

# Reserved bits b4-7 of MODE_FLAGS and CONFIG_CHANGE_COUNTER must be masked off
LOW_NIBBLE_MASK = 0x0F

# Sentinels for fields that are invalid, not provisioned or withheld by the mode
LEVEL_INVALID = 0xFFFF
SERIAL_PREFIX_NONE = 0xFFFF
TANK_VOLUME_TOTAL_UNKNOWN = 0xFFFF
TANK_TYPE_UNKNOWN = 0xFF

# BEACON_MODE
BEACON_OFF = 0x00
BEACON_HIGH_SECURITY = 0x01
BEACON_MED_SECURITY = 0x02
BEACON_LOW_SECURITY = 0x03
BEACON_PLAIN = 0x04

BEACON_MODE_NAMES = {
    BEACON_OFF: "BEACON_OFF",
    BEACON_HIGH_SECURITY: "BEACON_HIGH_SECURITY",
    BEACON_MED_SECURITY: "BEACON_MED_SECURITY",
    BEACON_LOW_SECURITY: "BEACON_LOW_SECURITY",
    BEACON_PLAIN: "BEACON_PLAIN",
}
BEACON_MODES_ENCRYPTED = (BEACON_HIGH_SECURITY, BEACON_MED_SECURITY, BEACON_LOW_SECURITY)

PRODUCT_NAMES = {0x01: "STR1", 0x02: "STR2", 0x03: "STR3"}

TANK_TYPE_NAMES = {
    0x00: "OTHER",
    0x01: "FRESH_WATER",
    0x02: "GRAY_WATER",
    0x03: "BLACK_WATER",
    0x04: "FUEL",
}

# AES-CCM parameters, fixed by the protocol
KEY_SIZE = 16
NONCE_SIZE = 13
TAG_SIZE = 4


@dataclass
class ScanResponse:
    """Fields of the scan response service data, sentinels kept as transmitted."""

    product_type: int
    protocol_major: int
    protocol_minor: int
    serial_prefix: int
    mode_flags: int
    boot_counter: int
    tank_volume_total_l: int
    tank_type: int

    @property
    def beacon_mode(self) -> int:
        """BEACON_MODE, the low nibble of MODE_FLAGS."""
        return self.mode_flags & LOW_NIBBLE_MASK

    @property
    def encrypted(self) -> bool:
        """True in the modes that protect LEVEL with AES-CCM."""
        return self.beacon_mode in BEACON_MODES_ENCRYPTED

    @property
    def product_name(self) -> str:
        """Product name, STRx for a product newer than this parser."""
        return PRODUCT_NAMES.get(self.product_type, "STRx")

    @property
    def display_name(self) -> str:
        """Name shown to the user, matching the label on the device."""
        if self.serial_prefix == SERIAL_PREFIX_NONE:
            return self.product_name
        return f"{self.product_name}-{self.serial_prefix:04d}"

    @property
    def tank_volume_total(self) -> Optional[int]:
        """Total tank volume in liters, None if unknown or withheld."""
        if self.tank_volume_total_l == TANK_VOLUME_TOTAL_UNKNOWN:
            return None
        return self.tank_volume_total_l

    @property
    def tank_type_name(self) -> Optional[str]:
        """Tank type name, None if unknown or withheld."""
        if self.tank_type == TANK_TYPE_UNKNOWN:
            return None
        return TANK_TYPE_NAMES.get(self.tank_type, f"0x{self.tank_type:02x}")


@dataclass
class Advertisement:
    """Fields of the advertising service data, LEVEL kept as raw bytes."""

    message_counter: int
    level_bytes: bytes
    mic: bytes
    config_change_flags: int

    @property
    def config_change_counter(self) -> int:
        """CONFIG_CHANGE_COUNTER, the low nibble of the byte."""
        return self.config_change_flags & LOW_NIBBLE_MASK

    @property
    def level_plain(self) -> Optional[int]:
        """LEVEL read as plaintext, only meaningful in BEACON_PLAIN."""
        level = struct.unpack("<H", self.level_bytes)[0]
        return None if level == LEVEL_INVALID else level


def parse_scan_response(payload: bytes) -> ScanResponse:
    """
    Parse the scan response service data.

    Args:
        payload: Service data for SCAN_RESPONSE_UUID, without the UUID

    Returns:
        ScanResponse, trailing bytes of a newer minor version are ignored

    Raises:
        ValueError: payload shorter than the v1.9 layout
    """
    if len(payload) < SCAN_RESPONSE_PAYLOAD_SIZE:
        raise ValueError(f"scan response payload too short: {len(payload)} bytes")
    fields = struct.unpack("<BBBHBHHB", payload[:SCAN_RESPONSE_PAYLOAD_SIZE])
    return ScanResponse(*fields)


def parse_advertisement(payload: bytes) -> Advertisement:
    """
    Parse the advertising service data.

    Args:
        payload: Service data for ADVERTISING_UUID, without the UUID

    Returns:
        Advertisement, trailing bytes of a newer minor version are ignored

    Raises:
        ValueError: payload shorter than the v1.9 layout
    """
    if len(payload) < ADVERTISING_PAYLOAD_SIZE:
        raise ValueError(f"advertising payload too short: {len(payload)} bytes")
    return Advertisement(
        message_counter=int.from_bytes(payload[0:3], "little"),
        level_bytes=bytes(payload[3:5]),
        mic=bytes(payload[5:9]),
        config_change_flags=payload[9],
    )


def build_nonce(serial_prefix: int, boot_counter: int, message_counter: int,
                config_change_counter: int) -> bytes:
    """
    AES-CCM nonce of one message, every field is public.

    Args:
        serial_prefix: SERIAL_PREFIX as transmitted
        boot_counter: BOOT_COUNTER from the scan response
        message_counter: MESSAGE_COUNTER from the advertising packet
        config_change_counter: CONFIG_CHANGE_COUNTER, reserved bits masked off

    Returns:
        13 byte nonce
    """
    nonce = (struct.pack("<HH", serial_prefix, boot_counter)
             + message_counter.to_bytes(3, "little")
             + bytes([config_change_counter & LOW_NIBBLE_MASK]))
    return nonce.ljust(NONCE_SIZE, b"\x00")


def decrypt_level(key: bytes, scan_response: ScanResponse,
                  advertisement: Advertisement) -> Optional[int]:
    """
    Verify the MIC and recover LEVEL.

    Args:
        key: 16 byte encryption key shown in the app
        scan_response: Last scan response of the device
        advertisement: Advertising packet to verify

    Returns:
        Level in permille, LEVEL_INVALID if the device had none, None if the
        tag did not verify
    """
    nonce = build_nonce(scan_response.serial_prefix, scan_response.boot_counter,
                        advertisement.message_counter, advertisement.config_change_counter)
    aad = bytes([scan_response.beacon_mode])
    try:
        plaintext = AESCCM(key, tag_length=TAG_SIZE).decrypt(
            nonce, advertisement.level_bytes + advertisement.mic, aad)
    except InvalidTag:
        return None
    return struct.unpack("<H", plaintext)[0]


def encrypt_level(key: bytes, scan_response: ScanResponse, message_counter: int,
                  config_change_counter: int, level: int) -> tuple[bytes, bytes]:
    """
    Encrypt LEVEL the way the device does, for tests and simulators.

    Args:
        key: 16 byte encryption key
        scan_response: Scan response the message is broadcast under
        message_counter: MESSAGE_COUNTER of the message
        config_change_counter: CONFIG_CHANGE_COUNTER of the message
        level: Level in permille

    Returns:
        (level_bytes, mic) as they go out in the advertising packet
    """
    nonce = build_nonce(scan_response.serial_prefix, scan_response.boot_counter,
                        message_counter, config_change_counter)
    aad = bytes([scan_response.beacon_mode])
    sealed = AESCCM(key, tag_length=TAG_SIZE).encrypt(nonce, struct.pack("<H", level), aad)
    return sealed[:2], sealed[2:]


def read_level(scan_response: ScanResponse, advertisement: Advertisement,
               key: Optional[bytes] = None) -> tuple[Optional[int], str]:
    """
    Level of one message, decrypted when the mode calls for it.

    Args:
        scan_response: Last scan response of the device
        advertisement: Advertising packet to read
        key: Encryption key, None if the host has none

    Returns:
        (level in permille or None, reason when None)
    """
    mode = scan_response.beacon_mode
    if mode not in BEACON_MODE_NAMES:
        return None, "unknown BEACON_MODE, LEVEL not parsed"
    if mode == BEACON_OFF:
        return None, "broadcast is off"

    if not scan_response.encrypted:
        level = advertisement.level_plain
        return (level, "") if level is not None else (None, "no valid level")

    if advertisement.level_plain is None and not any(advertisement.mic):
        return None, "device could not encrypt"
    if key is None:
        return None, "encryption key needed"

    level = decrypt_level(key, scan_response, advertisement)
    if level is None:
        return None, "MIC failed, wrong or regenerated key"
    if level == LEVEL_INVALID:
        return None, "no valid level"
    return level, ""


class CounterGuard:
    """
    Rejects messages that are not newer than the last one accepted.

    A repeat of the last counter pair is the same message advertised again,
    not a replay. Create one guard per device address.
    """

    NEW = "new"
    REPEAT = "repeat"
    REPLAY = "replay"

    def __init__(self) -> None:
        self.last: Optional[tuple[int, int]] = None

    def check(self, boot_counter: int, message_counter: int) -> str:
        """
        Classify one message against the last one accepted.

        Args:
            boot_counter: BOOT_COUNTER from the scan response
            message_counter: MESSAGE_COUNTER from the advertising packet

        Returns:
            NEW, REPEAT or REPLAY
        """
        counters = (boot_counter, message_counter)
        if self.last is None or counters > self.last:
            self.last = counters
            return self.NEW
        return self.REPEAT if counters == self.last else self.REPLAY


def key_from_hex(text: str) -> bytes:
    """
    Key as the app shows it, 32 hexadecimal digits, first pair is byte 0.

    Args:
        text: Key text, spaces and colons allowed

    Returns:
        16 key bytes

    Raises:
        ValueError: not 16 bytes of hexadecimal
    """
    key = bytes.fromhex(text.replace(":", "").replace(" ", ""))
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    return key
