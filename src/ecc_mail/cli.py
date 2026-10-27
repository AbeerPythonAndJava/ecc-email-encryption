"""Command-line interface — replaces the Swing screens.

    Java screen          →  command
    ------------------      ---------------------------
    mainf / secf login   →  keygen  (passphrase-protected key)
    sender  "Encrypt"    →  encrypt
    sender  "Send"       →  send
    resever "Open"       →  inbox
    resever "Decrypt"    →  decrypt  /  inbox --decrypt
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from ecc_mail import __version__
from ecc_mail.config import MailConfig
from ecc_mail.crypto import decrypt_message, encrypt_message, find_armored_blocks
from ecc_mail.exceptions import EccMailError
from ecc_mail.keys import (
    PRIVATE_KEY_NAME,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)

logger = logging.getLogger("ecc_mail")
DEFAULT_KEY_DIR = Path.home() / ".ecc_mail"


def _passphrase(confirm: bool = False) -> bytes | None:
    pw = getpass.getpass("Key passphrase (empty = none): ")
    if confirm and pw and pw != getpass.getpass("Repeat passphrase: "):
        raise EccMailError("Passphrases do not match.")
    return pw.encode() if pw else None


def _read_text(path: str | None) -> str:
    """Read from a file, or from stdin when path is None or '-'."""
    if path in (None, "-"):
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def cmd_keygen(args: argparse.Namespace) -> None:
    private_key, _ = generate_keypair()
    priv, pub = save_keypair(
        private_key, args.key_dir, _passphrase(confirm=True), overwrite=args.force
    )
    print(f"Private key: {priv}  (keep secret!)")
    print(f"Public key : {pub}  (share with senders)")


def cmd_encrypt(args: argparse.Namespace) -> None:
    public = load_public_key(args.recipient_key)
    print(encrypt_message(_read_text(args.input), public))


def cmd_decrypt(args: argparse.Namespace) -> None:
    private = load_private_key(Path(args.key_dir) / PRIVATE_KEY_NAME, _passphrase())
    print(decrypt_message(_read_text(args.input), private))


def cmd_send(args: argparse.Namespace) -> None:
    public = load_public_key(args.recipient_key)
    armored = encrypt_message(_read_text(args.input), public)
    from ecc_mail.mail_client import send_email

    send_email(MailConfig.from_env(), args.to, args.subject, armored)
    print(f"Encrypted email sent to {args.to}")


def cmd_inbox(args: argparse.Namespace) -> None:
    from ecc_mail.mail_client import fetch_inbox

    messages = fetch_inbox(MailConfig.from_env(), limit=args.limit)
    private = (
        load_private_key(Path(args.key_dir) / PRIVATE_KEY_NAME, _passphrase())
        if args.decrypt
        else None
    )
    for i, msg in enumerate(messages, 1):
        print(f"\n[{i}] From: {msg.sender}\n    Subject: {msg.subject}")
        blocks = find_armored_blocks(msg.body)
        if not blocks:
            continue
        if private is None:
            print(f"    🔒 {len(blocks)} encrypted block(s) — use --decrypt")
            continue
        for block in blocks:
            try:
                print("    🔓 " + decrypt_message(block, private).replace("\n", "\n       "))
            except EccMailError as exc:
                print(f"    ⚠️  {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecc-mail", description="End-to-end email encryption with ECC (X25519 + AES-GCM)."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--key-dir", default=str(DEFAULT_KEY_DIR), help="folder for your keys")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create your key pair")
    p.add_argument("--force", action="store_true", help="overwrite existing keys")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt", help="encrypt text for a recipient")
    p.add_argument("-r", "--recipient-key", required=True, help="recipient public_key.pem")
    p.add_argument("-i", "--input", help="input file (default: stdin)")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt an ECC-MAIL block")
    p.add_argument("-i", "--input", help="input file (default: stdin)")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("send", help="encrypt and email a message")
    p.add_argument("--to", required=True)
    p.add_argument("-r", "--recipient-key", required=True)
    p.add_argument("-s", "--subject", default="Encrypted message")
    p.add_argument("-i", "--input", help="message file (default: stdin)")
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("inbox", help="list recent emails")
    p.add_argument("-n", "--limit", type=int, default=10)
    p.add_argument("--decrypt", action="store_true", help="decrypt ECC-MAIL blocks")
    p.set_defaults(func=cmd_inbox)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        args.func(args)
    except EccMailError as exc:
        logger.debug("Failure", exc_info=True)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
