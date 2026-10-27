"""Configuration loaded from environment variables (never from source code).

The original Java project hard-coded the Gmail address and password in
``SendMailTLS.java`` and ``InboxReader.java``. Here, every secret comes from
the environment or an optional ``.env`` file that is git-ignored.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from ecc_mail.exceptions import ConfigError

logger = logging.getLogger(__name__)

try:  # python-dotenv is optional: use it if installed
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - depends on environment
    pass


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"Environment variable {name} is not set. "
            "Copy .env.example to .env and fill it in."
        )
    return value


@dataclass(frozen=True)
class MailConfig:
    """SMTP/IMAP connection settings."""

    username: str
    password: str
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "MailConfig":
        """Build a config from ``ECC_MAIL_*`` environment variables."""
        try:
            config = cls(
                username=_require("ECC_MAIL_USERNAME"),
                password=_require("ECC_MAIL_PASSWORD"),
                smtp_host=os.environ.get("ECC_MAIL_SMTP_HOST", cls.smtp_host),
                smtp_port=int(os.environ.get("ECC_MAIL_SMTP_PORT", cls.smtp_port)),
                imap_host=os.environ.get("ECC_MAIL_IMAP_HOST", cls.imap_host),
                imap_port=int(os.environ.get("ECC_MAIL_IMAP_PORT", cls.imap_port)),
            )
        except ValueError as exc:
            raise ConfigError(f"Invalid port number: {exc}") from exc
        logger.debug("Loaded mail config for %s", config.username)
        return config

    def __repr__(self) -> str:  # never leak the password into logs
        return (
            f"MailConfig(username={self.username!r}, password='***', "
            f"smtp={self.smtp_host}:{self.smtp_port}, "
            f"imap={self.imap_host}:{self.imap_port})"
        )
