"""Tests for the production ECIES layer."""

import unittest

from ecc_mail.crypto import (
    ARMOR_BEGIN,
    decrypt_bytes,
    decrypt_message,
    encrypt_bytes,
    encrypt_message,
    find_armored_blocks,
)
from ecc_mail.exceptions import DecryptionError
from ecc_mail.keys import generate_keypair


class TestEcies(unittest.TestCase):
    def setUp(self) -> None:
        self.priv, self.pub = generate_keypair()

    def test_roundtrip_unicode(self) -> None:
        msg = "مرحباً — Hello ECC! 🔐\nLine 2"
        armored = encrypt_message(msg, self.pub)
        self.assertTrue(armored.startswith(ARMOR_BEGIN))
        self.assertEqual(decrypt_message(armored, self.priv), msg)

    def test_empty_message(self) -> None:
        self.assertEqual(decrypt_message(encrypt_message("", self.pub), self.priv), "")

    def test_ciphertext_is_randomized(self) -> None:
        self.assertNotEqual(encrypt_message("same", self.pub), encrypt_message("same", self.pub))

    def test_wrong_key_fails(self) -> None:
        other_priv, _ = generate_keypair()
        with self.assertRaises(DecryptionError):
            decrypt_message(encrypt_message("secret", self.pub), other_priv)

    def test_tampering_detected(self) -> None:
        env = bytearray(encrypt_bytes(b"secret", self.pub))
        env[-1] ^= 0x01
        with self.assertRaises(DecryptionError):
            decrypt_bytes(bytes(env), self.priv)

    def test_header_tampering_detected(self) -> None:
        env = bytearray(encrypt_bytes(b"secret", self.pub))
        env[40] ^= 0x01  # inside the nonce (authenticated as AAD)
        with self.assertRaises(DecryptionError):
            decrypt_bytes(bytes(env), self.priv)

    def test_find_blocks_in_email_body(self) -> None:
        body = "Hi,\n\n" + encrypt_message("a", self.pub) + "\n\nBye\n" + encrypt_message("b", self.pub)
        blocks = find_armored_blocks(body)
        self.assertEqual([decrypt_message(b, self.priv) for b in blocks], ["a", "b"])

    def test_garbage_input(self) -> None:
        with self.assertRaises(DecryptionError):
            decrypt_message("not encrypted", self.priv)


if __name__ == "__main__":
    unittest.main()
