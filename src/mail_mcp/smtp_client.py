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

import email
import email.policy
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, formatdate, getaddresses, make_msgid, parseaddr

from .config import AccountModel
from .safety.tls import create_tls_context
from .safety.validation import (
    ValidationError,
    validate_email_address,
    validate_header_value,
)

RE_PREFIX = "Re: "
FWD_PREFIX = "Fwd: "
MAX_QUOTED_LINES = 400


def _attach_files(msg: EmailMessage, resolved_attachments: list) -> None:
    """Attach pre-validated files (:class:`ResolvedAttachment`) to ``msg``."""
    for att in resolved_attachments or []:
        data = att.path.read_bytes()
        maintype, _, subtype = att.content_type.partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=att.filename)


def build_message(
    *,
    from_addr: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    in_reply_to: str | None = None,
    references: list[str] | None = None,
    attachments: list | None = None,
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
    _attach_files(msg, attachments or [])
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
    attachments: list | None = None,
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
        attachments=attachments,
    )
    return msg, list(bcc or [])


def build_reply_message(
    *,
    from_addr: str,
    original_headers: dict[str, str],
    body_text: str,
    extra_to: list[str] | None = None,
    cc: list[str] | None = None,
    reply_all: bool = False,
    include_original_quote: bool = True,
    attachments: list | None = None,
) -> EmailMessage:
    """Assemble a reply whose threading headers match ``original_headers``.

    The subject is prefixed with ``Re: `` unless already present. ``In-Reply-To``
    is set to the original ``Message-ID`` and the new ``References`` header
    appends it to the existing chain. When ``include_original_quote`` is true
    the original body (short, quoted with ``> ``) is included — **the caller**
    provides that text; this function does not re-parse the original to avoid
    dragging adversary-controlled content back through the LLM.
    """
    recipients = _reply_recipients(from_addr, original_headers, extra_to, reply_all)
    subject_raw = original_headers.get("Subject", "") or ""
    subject = subject_raw if subject_raw.lower().startswith("re:") else f"{RE_PREFIX}{subject_raw}".strip()

    in_reply_to = _first_message_id(original_headers.get("Message-ID", ""))
    prior_refs = original_headers.get("References", "").split()
    references = prior_refs + ([in_reply_to] if in_reply_to else [])

    body = body_text.rstrip()
    if include_original_quote:
        body += "\n\n" + _quote(original_headers, body_text_limit_lines=MAX_QUOTED_LINES)
    return build_message(
        from_addr=from_addr,
        to=recipients["to"],
        cc=recipients["cc"] if reply_all else (cc or None),
        subject=subject,
        body_text=body,
        in_reply_to=in_reply_to,
        references=references or None,
        attachments=attachments,
    )


def build_forward_message(
    *,
    from_addr: str,
    to: list[str],
    original_headers: dict[str, str],
    original_raw: bytes,
    comment: str = "",
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
) -> tuple[EmailMessage, list[str]]:
    """Assemble a forward: original attached as ``message/rfc822``, never
    re-parsed into the message body.

    The caller's optional ``comment`` becomes the human-readable body; the
    original email ships as a single attachment part with ``Content-Type:
    message/rfc822``, which mail clients render as a forwarded message the
    user can unfold. This mirrors Thunderbird's "forward as attachment" and
    is the XPIA-safe forward pattern from :mod:`thegreystone/mcp-email`.
    """
    subject_raw = original_headers.get("Subject", "") or ""
    subject = subject_raw if subject_raw.lower().startswith(("fwd:", "fw:")) else f"{FWD_PREFIX}{subject_raw}".strip()
    msg, bcc_list = build_message_with_bcc(
        from_addr=from_addr,
        to=to,
        cc=cc,
        bcc=bcc,
        subject=subject,
        body_text=comment or "",
    )
    original = email.message_from_bytes(original_raw, policy=email.policy.default)
    filename = _sanitize_attachment_name(original_headers.get("Subject") or "forwarded-message") + ".eml"
    msg.add_attachment(
        original,
        filename=filename,
    )
    return msg, bcc_list


def _reply_recipients(
    from_addr: str,
    headers: dict[str, str],
    extra_to: list[str] | None,
    reply_all: bool,
) -> dict[str, list[str]]:
    reply_to = headers.get("Reply-To") or headers.get("From") or ""
    primary = [addr for _, addr in getaddresses([reply_to]) if addr]
    if not primary:
        raise ValidationError("original message has no usable Reply-To/From header")
    to_list = primary + list(extra_to or [])
    cc_list: list[str] = []
    if reply_all:
        for field in ("To", "Cc"):
            for _, addr in getaddresses([headers.get(field, "")]):
                if addr and addr.lower() != from_addr.lower() and addr not in to_list:
                    cc_list.append(addr)
    # deduplicate preserving order, exclude our own address from To
    seen: set[str] = set()
    deduped_to: list[str] = []
    for addr in to_list:
        if addr.lower() == from_addr.lower() or addr.lower() in seen:
            continue
        seen.add(addr.lower())
        deduped_to.append(addr)
    return {"to": deduped_to, "cc": cc_list}


def _first_message_id(raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    # Message-ID is `<id>` — keep the angle brackets since that's the RFC form.
    if raw.startswith("<") and raw.endswith(">"):
        return raw
    return None


def _quote(headers: dict[str, str], *, body_text_limit_lines: int) -> str:
    """Produce a short attribution header for the quoted reply body.

    We deliberately do *not* re-include the original body verbatim — the
    caller decides what to quote. This just prefixes a ``On <date>, <name>
    wrote:`` line so threading is visually clear in the draft.
    """
    date = headers.get("Date", "") or ""
    name, addr = parseaddr(headers.get("From", ""))
    who = formataddr((name, addr)) if (name or addr) else "the original sender"
    return f"On {date}, {who} wrote:\n"


def _sanitize_attachment_name(value: str) -> str:
    cleaned = "".join(c for c in value if c.isprintable() and c not in '\\/:*?"<>|\r\n\0')
    cleaned = cleaned.strip() or "forwarded-message"
    return cleaned[:60]


def test_login(account: AccountModel, password: str, *, timeout: float = 15.0) -> None:
    """Authenticate against the account's SMTP server and close the session.

    Used by the interactive wizard to verify the user's credentials before
    saving them. Raises the underlying :mod:`smtplib` exception on failure.
    """
    ctx = create_tls_context()
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
    ctx = create_tls_context()
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
