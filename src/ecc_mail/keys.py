"""Key-pair generation and PEM storage (X25519).

Replaces the Java login screen (``mainf.java`` with the hard-coded
"almn"/"1234"): the private key itself is now protected by a passphrase
using the PKCS#8 "best available" encryption, so only its owner can decrypt.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ecc_mail.exceptions import KeyError_

logger = logging.getLogger(__name__)

PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_KEY_NAME = "public_key.pem"


def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate a fresh X25519 key pair from the OS CSPRNG."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_keypair(
    private_key: X25519PrivateKey,
    directory: str | Path,
    passphrase: bytes | None,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Write the key pair to ``directory`` as PEM files.

    Args:
        private_key: The key to store.
        directory: Target folder (created if missing).
        passphrase: Encrypts the private key. ``None`` stores it unencrypted
            (only acceptable for tests).
        overwrite: Refuse to replace existing keys unless True.

    Returns:
        Paths of the private and public key files.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    priv_path = directory / PRIVATE_KEY_NAME
    pub_path = directory / PUBLIC_KEY_NAME

    if not overwrite and (priv_path.exists() or pub_path.exists()):
        raise KeyError_(f"Keys already exist in {directory}; use overwrite=True.")

    encryption: serialization.KeySerializationEncryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        logger.warning("Saving private key WITHOUT a passphrase.")
        encryption = serialization.NoEncryption()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    try:
        os.chmod(priv_path, 0o600)  # owner read/write only (no-op on Windows)
    except OSError:  # pragma: no cover
        pass
    pub_path.write_bytes(pub_pem)

    logger.info("Saved key pair to %s", directory)
    return priv_path, pub_path


def load_private_key(path: str | Path, passphrase: bytes | None) -> X25519PrivateKey:
    """Load an X25519 private key from a PEM file."""
    try:
        key = serialization.load_pem_private_key(
            Path(path).read_bytes(), password=passphrase
        )
    except FileNotFoundError as exc:
        raise KeyError_(f"Private key not found: {path}") from exc
    except (ValueError, TypeError) as exc:
        raise KeyError_("Wrong passphrase or corrupted private key.") from exc

    if not isinstance(key, X25519PrivateKey):
        raise KeyError_("Private key is not an X25519 key.")
    return key


def load_public_key(path: str | Path) -> X25519PublicKey:
    """Load an X25519 public key from a PEM file."""
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except FileNotFoundError as exc:
        raise KeyError_(f"Public key not found: {path}") from exc
    except ValueError as exc:
        raise KeyError_("Corrupted public key file.") from exc

    if not isinstance(key, X25519PublicKey):
        raise KeyError_("Public key is not an X25519 key.")
    return key
