"""Custom exception hierarchy.

A single base class lets callers catch every library error with one
``except EccMailError`` while still distinguishing specific failures.
"""


class EccMailError(Exception):
    """Base class for all ecc_mail errors."""


class ConfigError(EccMailError):
    """Missing or invalid configuration (e.g. environment variables)."""


class KeyError_(EccMailError):
    """A key could not be generated, saved, or loaded.

    The trailing underscore avoids shadowing Python's built-in ``KeyError``.
    """


class DecryptionError(EccMailError):
    """Ciphertext is malformed, tampered with, or encrypted for another key."""


class MailError(EccMailError):
    """Sending or receiving email failed."""
