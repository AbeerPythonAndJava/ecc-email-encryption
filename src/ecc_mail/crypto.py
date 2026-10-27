"""ECIES: hybrid public-key encryption with X25519 + HKDF + AES-256-GCM.

This is the production replacement for the hand-written ElGamal scheme in
``multi.java``. The idea is the same (the sender mixes a random scalar ``k``
with the recipient's public point), but every building block is a vetted,
constant-time primitive:

    1. Sender creates an *ephemeral* key pair (k, k·G)       ← "kB" in the Java code
    2. Shared secret  S = k · Q_recipient  (ECDH)           ← "k·aB"
    3. Key            K = HKDF-SHA256(S, info, salt=k·G)
    4. Ciphertext     C = AES-256-GCM(K, nonce, message, AAD=header)
    5. Output         version ‖ k·G ‖ nonce ‖ C  → Base64 "armor"

The recipient recomputes S = d · (k·G) with their private key ``d``.
AES-GCM authenticates the data, so any tampering is detected.

Wire format (before Base64):
    +---------+----------------+-----------+--------------------------+
    | 1 byte  | 32 bytes       | 12 bytes  | N + 16 bytes             |
    | version | ephemeral pub  | nonce     | ciphertext ‖ GCM tag     |
    +---------+----------------+-----------+--------------------------+
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import textwrap

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ecc_mail.exceptions import DecryptionError

logger = logging.getLogger(__name__)

VERSION = 1
_PUB_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_HEADER_LEN = 1 + _PUB_LEN + _NONCE_LEN
_HKDF_INFO = b"ecc-mail/v1/aes-256-gcm"

ARMOR_BEGIN = "-----BEGIN ECC-MAIL MESSAGE-----"
ARMOR_END = "-----END ECC-MAIL MESSAGE-----"
_ARMOR_RE = re.compile(
    re.escape(ARMOR_BEGIN) + r"(.*?)" + re.escape(ARMOR_END), re.DOTALL
)


def _raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def _derive_key(shared_secret: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    """Stretch the raw ECDH output into a uniform 256-bit AES key.

    Binding both public keys into the KDF prevents key-substitution attacks.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub,
        info=_HKDF_INFO + recipient_pub,
    ).derive(shared_secret)


def encrypt_bytes(plaintext: bytes, recipient: X25519PublicKey) -> bytes:
    """Encrypt raw bytes for ``recipient``. Returns the binary envelope."""
    ephemeral = X25519PrivateKey.generate()  # fresh random k for every message
    ephemeral_pub = _raw_public(ephemeral.public_key())
    recipient_pub = _raw_public(recipient)

    key = _derive_key(ephemeral.exchange(recipient), ephemeral_pub, recipient_pub)
    nonce = os.urandom(_NONCE_LEN)
    header = bytes([VERSION]) + ephemeral_pub + nonce

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)  # header = AAD
    return header + ciphertext


def decrypt_bytes(envelope: bytes, private_key: X25519PrivateKey) -> bytes:
    """Reverse :func:`encrypt_bytes`. Raises DecryptionError on any failure."""
    if len(envelope) < _HEADER_LEN + _TAG_LEN:
        raise DecryptionError("Ciphertext is too short.")
    if envelope[0] != VERSION:
        raise DecryptionError(f"Unsupported format version: {envelope[0]}")

    header = envelope[:_HEADER_LEN]
    ephemeral_pub = header[1 : 1 + _PUB_LEN]
    nonce = header[1 + _PUB_LEN :]
    ciphertext = envelope[_HEADER_LEN:]

    try:
        ephemeral = X25519PublicKey.from_public_bytes(ephemeral_pub)
        shared = private_key.exchange(ephemeral)
    except ValueError as exc:
        raise DecryptionError("Invalid ephemeral public key.") from exc

    key = _derive_key(shared, ephemeral_pub, _raw_public(private_key.public_key()))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        # Same error for "wrong key" and "tampered": do not leak which one.
        raise DecryptionError(
            "Authentication failed: wrong key or the message was modified."
        ) from exc


def encrypt_message(message: str, recipient: X25519PublicKey) -> str:
    """Encrypt a text message and return an ASCII-armored block for email."""
    envelope = encrypt_bytes(message.encode("utf-8"), recipient)
    body = "\n".join(textwrap.wrap(base64.b64encode(envelope).decode("ascii"), 64))
    logger.debug("Encrypted %d bytes", len(envelope))
    return f"{ARMOR_BEGIN}\n{body}\n{ARMOR_END}"


def decrypt_message(armored: str, private_key: X25519PrivateKey) -> str:
    """Decrypt an armored block produced by :func:`encrypt_message`."""
    match = _ARMOR_RE.search(armored)
    if not match:
        raise DecryptionError("No ECC-MAIL block found in the text.")
    try:
        envelope = base64.b64decode("".join(match.group(1).split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError("Invalid Base64 payload.") from exc
    try:
        return decrypt_bytes(envelope, private_key).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError("Decrypted data is not valid UTF-8.") from exc


def find_armored_blocks(text: str) -> list[str]:
    """Return every armored block inside an arbitrary email body."""
    return [m.group(0) for m in _ARMOR_RE.finditer(text)]
