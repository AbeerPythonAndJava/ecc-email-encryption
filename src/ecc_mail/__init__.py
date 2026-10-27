"""ecc_mail — end-to-end email encryption with Elliptic Curve Cryptography.

Public API:
    generate_keypair, save_keypair, load_private_key, load_public_key
    encrypt_message, decrypt_message
"""

from ecc_mail.crypto import decrypt_message, encrypt_message
from ecc_mail.exceptions import (
    ConfigError,
    DecryptionError,
    EccMailError,
    KeyError_,
    MailError,
)
from ecc_mail.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)

__version__ = "1.0.0"

__all__ = [
    "ConfigError",
    "DecryptionError",
    "EccMailError",
    "KeyError_",
    "MailError",
    "decrypt_message",
    "encrypt_message",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "save_keypair",
]
