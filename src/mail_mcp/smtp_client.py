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
    in_reply_to: str | None = None,
    references: list[str] | None = None,
) -> EmailMessage:
    """Assemble a safe RFC 5322 message.

    All header-destined fields pass through :func:`validate_header_value`, which
    rejects CR/LF and other control characters before :class:`EmailMessage`
    performs its own header validation.

    BCC is handled separately by :func:`build_message_with_bcc`; the message
    returned here never carries a ``Bcc`` header.
    """
    validate_email_address(from_addr, field="from")
    if not to:
        raise ValidationError("at least one recipient is required")
    for addr in to:
        validate_email_address(addr, field="to")
    for addr in cc or []:
        validate_email_address(addr, field="cc")
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
    # Match the Message-ID domain to the From header so threaded replies track
    # correctly and IDs don't leak container hostnames (e.g. ``*.docker.local``).
    msg["Message-ID"] = make_msgid(domain=from_addr.rsplit("@", 1)[1])
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = " ".join(references)
    msg.set_content(body_text)
    return msg


def build_message_with_bcc(
    *,
    from_addr: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    in_reply_to: str | None = None,
    references: list[str] | None = None,
) -> tuple[EmailMessage, list[str]]:
    """Assemble a message and return it together with the BCC list.

    BCC is never added as a header (that would leak blind recipients);
    instead callers pass the returned list to :func:`send` as extra envelope
    recipients. ``build_message`` alone is safe to ``bytes()`` into a draft.
    """
    for addr in bcc or []:
        validate_email_address(addr, field="bcc")
    msg = build_message(
        from_addr=from_addr,
        to=to,
        subject=subject,
        body_text=body_text,
        cc=cc,
        in_reply_to=in_reply_to,
        references=references,
    )
    return msg, list(bcc or [])


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


def send(
    account: AccountModel,
    password: str,
    msg: EmailMessage,
    *,
    bcc: list[str] | None = None,
) -> str:
    """Deliver ``msg`` via SMTP, enforcing TLS.

    ``bcc`` entries are added to the envelope recipients but never appear as
    a header. Returns the message's ``Message-ID``.
    """
    ctx = ssl.create_default_context()
    recipients = [
        *[a.strip() for a in msg.get("To", "").split(",") if a.strip()],
        *[a.strip() for a in msg.get("Cc", "").split(",") if a.strip()],
        *(bcc or []),
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
