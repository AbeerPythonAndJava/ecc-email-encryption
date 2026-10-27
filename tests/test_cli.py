"""End-to-end CLI test (no network)."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from ecc_mail.cli import main


class TestCli(unittest.TestCase):
    def test_keygen_encrypt_decrypt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "ecc_mail.cli.getpass.getpass", return_value="pw"
        ):
            self.assertEqual(main(["--key-dir", tmp, "keygen"]), 0)

            msg_file = Path(tmp) / "msg.txt"
            msg_file.write_text("CLI test ✓", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                main(["encrypt", "-r", str(Path(tmp) / "public_key.pem"), "-i", str(msg_file)])

            ct_file = Path(tmp) / "ct.txt"
            ct_file.write_text(out.getvalue(), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["--key-dir", tmp, "decrypt", "-i", str(ct_file)]), 0)
            self.assertEqual(out.getvalue().strip(), "CLI test ✓")


if __name__ == "__main__":
    unittest.main()
