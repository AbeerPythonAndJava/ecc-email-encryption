"""Tests for the educational curve (original Java parameters)."""

import unittest

from ecc_mail import toy_ecc
from ecc_mail.toy_ecc import DEFAULT_ALPHABET, ORIGINAL_CURVE as C


class TestToyEcc(unittest.TestCase):
    def test_base_point_on_curve(self) -> None:
        self.assertTrue(C.is_on_curve(C.g))

    def test_group_law(self) -> None:
        g = C.g
        self.assertEqual(C.multiply(2, g), C.double(g))
        self.assertEqual(C.multiply(5, g), C.add(C.multiply(2, g), C.multiply(3, g)))
        self.assertIsNone(C.add(g, C.negate(g)))
        for k in range(1, 50):
            self.assertTrue(C.is_on_curve(C.multiply(k, g)))

    def test_every_char_encodes(self) -> None:
        for ch in DEFAULT_ALPHABET:
            pt = toy_ecc.encode_char(ch)
            self.assertTrue(C.is_on_curve(pt))
            self.assertEqual(toy_ecc.decode_point(pt), ch)

    def test_elgamal_roundtrip(self) -> None:
        d, q = toy_ecc.generate_keypair()
        msg = "Hello ECC, xyz!"
        self.assertEqual(toy_ecc.decrypt(toy_ecc.encrypt(msg, q), d), msg)

    def test_unsupported_char(self) -> None:
        with self.assertRaises(ValueError):
            toy_ecc.encode_char("#")


if __name__ == "__main__":
    unittest.main()
