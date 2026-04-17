"""SMTP wrapper built on :mod:`smtplib`.

Only two transport modes are supported:

* **SMTPS** (``smtp_starttls=False``, port 465) — implicit TLS.
* **SMTP + STARTTLS** (``smtp_starttls=True``, typically port 587) — the
  connection upgrades to TLS before authentication. Plain SMTP on port 25
  without STARTTLS is refused.

Messages are built with :class:`email.message.EmailMessage`, which encodes
headers per RFC 5322 and rejects CRLF in header values — a strong structural
defence against header-injection attacks.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from .config import AccountModel
from .safety.validation import (
    ValidationError,
    validate_email_address,
    validate_header_value,
)


def build_message(
    *,
    from_addr: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    in_reply_to: str | None = None,
    references: list[str] | None = None,
) -> EmailMessage:
    """Assemble a safe RFC 5322 message.

    All header-destined fields pass through :func:`validate_header_value`, which
    rejects CR/LF and other control characters before :class:`EmailMessage`
    performs its own header validation.
    """
    validate_email_address(from_addr, field="from")
    if not to:
        raise ValidationError("at least one recipient is required")
    for addr in to:
        validate_email_address(addr, field="to")
    for addr in cc or []:
        validate_email_address(addr, field="cc")
    for addr in bcc or []:
        validate_email_address(addr, field="bcc")
    validate_header_value(subject, field="subject")
    if in_reply_to:
        validate_header_value(in_reply_to, field="in_reply_to")
    for ref in references or []:
        validate_header_value(ref, field="references")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = " ".join(references)
    msg.set_content(body_text)
    # BCC is attached for delivery fan-out but not added as a header.
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
        del msg["Bcc"]
        msg._bcc = list(bcc)  # type: ignore[attr-defined]
    return msg


def test_login(account: AccountModel, password: str, *, timeout: float = 15.0) -> None:
    """Authenticate against the account's SMTP server and close the session.

    Used by the interactive wizard to verify the user's credentials before
    saving them. Raises the underlying :mod:`smtplib` exception on failure.
    """
    ctx = ssl.create_default_context()
    if account.smtp_starttls:
        with smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=timeout) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(account.email, password)
    else:
        with smtplib.SMTP_SSL(
            account.smtp_host, account.smtp_port, context=ctx, timeout=timeout
        ) as server:
            server.login(account.email, password)


def send(account: AccountModel, password: str, msg: EmailMessage) -> str:
    """Deliver ``msg`` via SMTP, enforcing TLS.

    Returns the message's ``Message-ID`` header so callers can log it or link
    it with follow-up tool calls.
    """
    ctx = ssl.create_default_context()
    bcc: list[str] = getattr(msg, "_bcc", [])
    recipients = [
        *[a.strip() for a in msg.get("To", "").split(",") if a.strip()],
        *[a.strip() for a in msg.get("Cc", "").split(",") if a.strip()],
        *bcc,
    ]
    if account.smtp_starttls:
        with smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(account.email, password)
            server.send_message(msg, from_addr=account.email, to_addrs=recipients)
    else:
        with smtplib.SMTP_SSL(
            account.smtp_host, account.smtp_port, context=ctx, timeout=30
        ) as server:
            server.login(account.email, password)
            server.send_message(msg, from_addr=account.email, to_addrs=recipients)
    return msg["Message-ID"]
