"""Tests for key storage."""

import tempfile
import unittest
from pathlib import Path

from ecc_mail.crypto import decrypt_message, encrypt_message
from ecc_mail.exceptions import KeyError_
from ecc_mail.keys import generate_keypair, load_private_key, load_public_key, save_keypair


class TestKeys(unittest.TestCase):
    def test_save_and_load_with_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priv, _ = generate_keypair()
            priv_path, pub_path = save_keypair(priv, tmp, b"s3cret")
            loaded_priv = load_private_key(priv_path, b"s3cret")
            loaded_pub = load_public_key(pub_path)
            self.assertEqual(decrypt_message(encrypt_message("hi", loaded_pub), loaded_priv), "hi")

    def test_wrong_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priv, _ = generate_keypair()
            priv_path, _ = save_keypair(priv, tmp, b"right")
            with self.assertRaises(KeyError_):
                load_private_key(priv_path, b"wrong")

    def test_no_accidental_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priv, _ = generate_keypair()
            save_keypair(priv, tmp, None)
            with self.assertRaises(KeyError_):
                save_keypair(priv, tmp, None)

    def test_missing_file(self) -> None:
        with self.assertRaises(KeyError_):
            load_public_key(Path("does/not/exist.pem"))


if __name__ == "__main__":
    unittest.main()
