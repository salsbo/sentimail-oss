from __future__ import annotations

import os
import unittest
from tempfile import TemporaryDirectory

from sentimail_v3.crypto import (
    ALGORITHM,
    DecryptionError,
    decrypt,
    encrypt,
    is_encrypted,
    load_key,
    protect,
    reveal,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
MESSAGE = b"From: a@example.org\r\nSubject: secret\r\n\r\ncorps confidentiel\r\n"


class CryptoTests(unittest.TestCase):
    def test_a_message_survives_a_round_trip(self) -> None:
        sealed = encrypt(MESSAGE, KEY)
        self.assertNotIn(b"confidentiel", sealed)
        self.assertTrue(is_encrypted(sealed))
        self.assertEqual(decrypt(sealed, KEY), MESSAGE)

    def test_every_encryption_uses_a_fresh_nonce(self) -> None:
        self.assertNotEqual(encrypt(MESSAGE, KEY), encrypt(MESSAGE, KEY))

    def test_another_key_cannot_read_the_message(self) -> None:
        with self.assertRaises(DecryptionError):
            decrypt(encrypt(MESSAGE, KEY), OTHER_KEY)

    def test_a_tampered_message_is_refused_not_returned(self) -> None:
        sealed = bytearray(encrypt(MESSAGE, KEY))
        sealed[-1] ^= 0x01
        with self.assertRaises(DecryptionError):
            decrypt(bytes(sealed), KEY)

    def test_legacy_plaintext_stays_readable(self) -> None:
        self.assertFalse(is_encrypted(MESSAGE))
        self.assertEqual(reveal(MESSAGE, KEY), MESSAGE)
        self.assertEqual(reveal(MESSAGE, None), MESSAGE)

    def test_capture_without_a_key_never_fails(self) -> None:
        stored, algorithm = protect(MESSAGE, None)
        self.assertEqual(stored, MESSAGE)
        self.assertIsNone(algorithm)
        stored, algorithm = protect(MESSAGE, KEY)
        self.assertEqual(algorithm, ALGORITHM)
        self.assertTrue(is_encrypted(stored))

    def test_an_encrypted_message_is_never_silently_returned(self) -> None:
        with self.assertRaises(DecryptionError):
            reveal(encrypt(MESSAGE, KEY), None)

    def test_the_key_is_read_as_hex_or_raw_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            hex_path = os.path.join(directory, "hex")
            raw_path = os.path.join(directory, "raw")
            short_path = os.path.join(directory, "short")
            with open(hex_path, "w", encoding="ascii") as handle:
                handle.write(KEY.hex() + "\n")
            with open(raw_path, "wb") as handle:
                handle.write(KEY)
            with open(short_path, "wb") as handle:
                handle.write(b"trop court")
            self.assertEqual(load_key(hex_path), KEY)
            self.assertEqual(load_key(raw_path), KEY)
            self.assertIsNone(load_key(None))
            with self.assertRaises(ValueError):
                load_key(short_path)


if __name__ == "__main__":
    unittest.main()
