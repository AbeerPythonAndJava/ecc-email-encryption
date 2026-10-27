"""Sending and receiving email over TLS.

Replaces ``SendMailTLS.java`` (SMTP + STARTTLS) and ``InboxReader.java``
(POP3S). IMAP is used for reading because it does not delete or move
messages and lets us fetch only the latest N.
"""

from __future__ import annotations

import email
import imaplib
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage, Message
from email.utils import make_msgid

from ecc_mail.config import MailConfig
from ecc_mail.exceptions import MailError

logger = logging.getLogger(__name__)


@dataclass
class InboxMessage:
    """A simplified view of a received email."""

    sender: str
    subject: str
    body: str


def send_email(config: MailConfig, to: str, subject: str, body: str) -> None:
    """Send a plain-text email via SMTP with STARTTLS."""
    msg = EmailMessage()
    msg["From"] = config.username
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid()
    msg.set_content(body)

    context = ssl.create_default_context()  # verifies the server certificate
    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.timeout) as smtp:
            smtp.starttls(context=context)
            smtp.login(config.username, config.password)
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError("SMTP login failed. For Gmail use an App Password.") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise MailError(f"Could not send email: {exc}") from exc
    logger.info("Email sent to %s", to)


def _plain_text(msg: Message) -> str:
    """Extract the first text/plain part of a (possibly multipart) message."""
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_type() == "text/plain" and not part.get_filename():
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    return ""


def fetch_inbox(config: MailConfig, limit: int = 10, folder: str = "INBOX") -> list[InboxMessage]:
    """Return the ``limit`` most recent messages (newest first)."""
    context = ssl.create_default_context()
    try:
        with imaplib.IMAP4_SSL(config.imap_host, config.imap_port, ssl_context=context) as imap:
            imap.login(config.username, config.password)
            imap.select(folder, readonly=True)
            status, data = imap.search(None, "ALL")
            if status != "OK":
                raise MailError("IMAP search failed.")
            ids = data[0].split()[-limit:][::-1]

            messages: list[InboxMessage] = []
            for msg_id in ids:
                status, fetched = imap.fetch(msg_id, "(RFC822)")
                if status != "OK" or not fetched or not isinstance(fetched[0], tuple):
                    logger.warning("Skipping message %s", msg_id)
                    continue
                parsed = email.message_from_bytes(fetched[0][1])
                messages.append(
                    InboxMessage(
                        sender=str(parsed.get("From", "")),
                        subject=str(parsed.get("Subject", "")),
                        body=_plain_text(parsed),
                    )
                )
            return messages
    except imaplib.IMAP4.error as exc:
        raise MailError(f"IMAP error (check credentials / IMAP enabled): {exc}") from exc
    except OSError as exc:
        raise MailError(f"Could not connect to IMAP server: {exc}") from exc
