"""
Offline checks of the parser against hand-built payloads.

    python -m unittest test_strx_broadcast
"""

import struct
import unittest

from strx import broadcast as strx

KEY = bytes.fromhex("4BD224860416877824974BAF9ED1E1E4")


def scan_response_payload(mode=strx.BEACON_LOW_SECURITY, serial_prefix=42, boot_counter=7,
                          volume=200, tank_type=0x01):
    """Scan response service data for an STR1, protocol v1.9."""
    return struct.pack("<BBBHBHHB", 0x01, 1, 9, serial_prefix, mode, boot_counter, volume, tank_type)


def advertisement_payload(message_counter, level_bytes, mic, config_change=0):
    """Advertising service data."""
    return message_counter.to_bytes(3, "little") + level_bytes + mic + bytes([config_change])


class ParseTest(unittest.TestCase):
    def test_scan_response_fields(self):
        rsp = strx.parse_scan_response(scan_response_payload())
        self.assertEqual(rsp.product_name, "STR1")
        self.assertEqual(rsp.display_name, "STR1-0042")
        self.assertEqual(rsp.beacon_mode, strx.BEACON_LOW_SECURITY)
        self.assertTrue(rsp.encrypted)
        self.assertEqual(rsp.tank_volume_total, 200)
        self.assertEqual(rsp.tank_type_name, "FRESH_WATER")

    def test_reserved_bits_masked(self):
        rsp = strx.parse_scan_response(scan_response_payload(mode=0xF0 | strx.BEACON_PLAIN))
        self.assertEqual(rsp.beacon_mode, strx.BEACON_PLAIN)
        adv = strx.parse_advertisement(advertisement_payload(1, b"\x00\x00", bytes(4), 0xF5))
        self.assertEqual(adv.config_change_counter, 5)

    def test_sentinels(self):
        rsp = strx.parse_scan_response(
            scan_response_payload(serial_prefix=0xFFFF, volume=0xFFFF, tank_type=0xFF))
        self.assertEqual(rsp.display_name, "STR1")
        self.assertIsNone(rsp.tank_volume_total)
        self.assertIsNone(rsp.tank_type_name)

    def test_unknown_product_stays_selectable(self):
        payload = bytearray(scan_response_payload())
        payload[0] = 0x09
        self.assertEqual(strx.parse_scan_response(payload).display_name, "STRx-0042")

    def test_short_payload_rejected(self):
        with self.assertRaises(ValueError):
            strx.parse_scan_response(scan_response_payload()[:5])
        with self.assertRaises(ValueError):
            strx.parse_advertisement(bytes(9))


class LevelTest(unittest.TestCase):
    def test_plain_level(self):
        rsp = strx.parse_scan_response(scan_response_payload(mode=strx.BEACON_PLAIN))
        adv = strx.parse_advertisement(advertisement_payload(3, struct.pack("<H", 750), bytes(4)))
        self.assertEqual(strx.read_level(rsp, adv), (750, ""))

    def test_off_has_no_level(self):
        rsp = strx.parse_scan_response(scan_response_payload(mode=strx.BEACON_OFF))
        adv = strx.parse_advertisement(advertisement_payload(3, b"\xff\xff", bytes(4)))
        self.assertIsNone(strx.read_level(rsp, adv)[0])

    def test_encrypted_round_trip(self):
        rsp = strx.parse_scan_response(scan_response_payload())
        level_bytes, mic = strx.encrypt_level(KEY, rsp, 1000, 3, 512)
        adv = strx.parse_advertisement(advertisement_payload(1000, level_bytes, mic, 3))
        self.assertIsNone(strx.read_level(rsp, adv)[0])
        self.assertEqual(strx.read_level(rsp, adv, KEY), (512, ""))

    def test_mode_is_authenticated(self):
        rsp = strx.parse_scan_response(scan_response_payload(mode=strx.BEACON_HIGH_SECURITY))
        level_bytes, mic = strx.encrypt_level(KEY, rsp, 1000, 0, 512)
        adv = strx.parse_advertisement(advertisement_payload(1000, level_bytes, mic))
        other = strx.parse_scan_response(scan_response_payload(mode=strx.BEACON_LOW_SECURITY))
        self.assertIsNone(strx.decrypt_level(KEY, other, adv))

    def test_stale_scan_response_fails(self):
        rsp = strx.parse_scan_response(scan_response_payload(boot_counter=7))
        level_bytes, mic = strx.encrypt_level(KEY, rsp, 1000, 0, 512)
        adv = strx.parse_advertisement(advertisement_payload(1000, level_bytes, mic))
        stale = strx.parse_scan_response(scan_response_payload(boot_counter=6))
        self.assertIsNone(strx.decrypt_level(KEY, stale, adv))

    def test_device_could_not_encrypt(self):
        rsp = strx.parse_scan_response(scan_response_payload())
        adv = strx.parse_advertisement(advertisement_payload(3, b"\xff\xff", bytes(4)))
        self.assertEqual(strx.read_level(rsp, adv, KEY), (None, "device could not encrypt"))


class CounterGuardTest(unittest.TestCase):
    def test_order(self):
        guard = strx.CounterGuard()
        self.assertEqual(guard.check(1, 10), guard.NEW)
        self.assertEqual(guard.check(1, 10), guard.REPEAT)
        self.assertEqual(guard.check(1, 9), guard.REPLAY)
        self.assertEqual(guard.check(1, 11), guard.NEW)
        self.assertEqual(guard.check(2, 0), guard.NEW)
        self.assertEqual(guard.check(1, 500), guard.REPLAY)


class KeyTest(unittest.TestCase):
    def test_key_from_hex(self):
        self.assertEqual(strx.key_from_hex("4BD2 2486 0416 8778 2497 4BAF 9ED1 E1E4"), KEY)
        with self.assertRaises(ValueError):
            strx.key_from_hex("4BD2")


if __name__ == "__main__":
    unittest.main()
