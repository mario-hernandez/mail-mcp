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
import html as _html_lib
import re
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, formatdate, getaddresses, make_msgid, parseaddr
from typing import Any

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
_CLOSING_BODY_RE = re.compile(r"</body\s*>", re.IGNORECASE)


class PartialDeliveryError(RuntimeError):
    """Raised when SMTP accepted the message for some recipients but refused others.

    ``smtplib.SMTP.send_message`` does not raise when at least one recipient
    is accepted — it returns the refused ones. We turn that into an error so
    the send tools never report a clean ``message_id`` while some recipients
    silently received nothing. ``refused`` is the ``{addr: (code, msg)}`` dict
    smtplib returns; ``message_id`` is the ID of the message that was (partly)
    sent so the caller can locate it.
    """

    def __init__(self, message_id: str, refused: dict) -> None:
        self.message_id = message_id
        self.refused = refused
        addrs = ", ".join(sorted(refused)) if refused else "(unknown)"
        super().__init__(
            f"message {message_id} was accepted for some recipients but the "
            f"server refused: {addrs}. The message may have been delivered to "
            "the others; do not retry blindly."
        )


def _has_rfc822_headers(inner: EmailMessage) -> bool:
    """Sanity check: a parsed candidate behaves like a real RFC822 message."""
    return any(inner.get(h) for h in ("From", "To", "Subject", "Date", "Message-ID"))


def _attach_files(msg: EmailMessage, resolved_attachments: list) -> None:
    """Attach pre-validated files (:class:`ResolvedAttachment`) to ``msg``.

    ``message/rfc822`` files (``.eml``) take a different path: Python's
    ``add_attachment(bytes, maintype="message", subtype="rfc822", ...)``
    silently drops the body on round-trip (CPython treats the bytes as
    opaque application content rather than parsing them as a nested
    message, and the body is lost on re-parse). The supported path is to
    pre-parse the bytes into an :class:`EmailMessage` and attach the
    object. If parsing produces something that does not look like a real
    RFC822 message we fall back to ``application/octet-stream`` so the
    bytes at least survive end-to-end.
    """
    from .safety.attachments import MAX_ATTACHMENT_BYTES, MAX_TOTAL_ATTACHMENT_BYTES
    from .safety.validation import ValidationError as _ValidationError

    running_total = 0
    for att in resolved_attachments or []:
        # Re-check the size at read time: resolve() stat'd the file earlier,
        # but it could have grown since (TOCTOU). Enforce BOTH the per-file
        # and the aggregate cap here — resolve_many's totals were computed
        # against the pre-growth sizes — so a set of files each growing to
        # just under the per-file cap can't blow past the total in memory.
        current_size = att.path.stat().st_size
        if current_size > MAX_ATTACHMENT_BYTES:
            raise _ValidationError(
                f"attachment grew past the size cap before send: "
                f"{current_size} bytes (max {MAX_ATTACHMENT_BYTES})"
            )
        running_total += current_size
        if running_total > MAX_TOTAL_ATTACHMENT_BYTES:
            raise _ValidationError(
                f"attachments grew past the total size limit before send: "
                f"{running_total} bytes (max {MAX_TOTAL_ATTACHMENT_BYTES})"
            )
        data = att.path.read_bytes()
        maintype, _, subtype = att.content_type.partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        if getattr(att, "raw_passthrough", False):
            # Forensic mode: bytes survive byte-for-byte. Force
            # ``application/octet-stream`` + base64 CTE so neither Python
            # nor the recipient's parser can re-canonicalize the body
            # (which would happen for ``message/rfc822`` and other
            # structured types). The receiver gets opaque bytes whose
            # SHA-256 matches the source on disk.
            msg.add_attachment(
                data,
                maintype="application",
                subtype="octet-stream",
                filename=att.filename,
                cte="base64",
            )
            continue
        if maintype == "message" and subtype == "rfc822":
            try:
                inner = email.message_from_bytes(data, policy=email.policy.default)
            except Exception:  # noqa: BLE001 — malformed bytes, fall through to octet-stream
                inner = None
            if inner is not None and _has_rfc822_headers(inner):
                msg.add_attachment(inner, filename=att.filename)
                continue
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=att.filename)


def carry_over_attachments(src: EmailMessage, dst: EmailMessage) -> int:
    """Copy every attachment-like part from ``src`` onto ``dst``.

    Used by :func:`update_draft` to preserve a draft's attachments when
    the caller updates only headers/body. Returns the number of parts
    carried over. ``message/rfc822`` parts are re-attached as
    :class:`EmailMessage` objects so the body survives the round-trip.
    """
    from .imap_client import _iter_attachments  # local import — avoid cycle

    count = 0
    for part in _iter_attachments(src):
        ctype = part.get_content_type()
        filename = part.get_filename()
        if ctype == "message/rfc822":
            inner_payload = part.get_payload()
            inner = (
                inner_payload[0]
                if isinstance(inner_payload, list) and inner_payload
                else None
            )
            if inner is None:
                continue
            dst.add_attachment(inner, filename=filename or None)
        else:
            payload = part.get_payload(decode=True) or b""
            maintype, _, subtype = ctype.partition("/")
            if not subtype:
                maintype, subtype = "application", "octet-stream"
            dst.add_attachment(
                payload, maintype=maintype, subtype=subtype, filename=filename or None,
            )
        # Preserve inline-image identity: an HTML alternative that references
        # ``src="cid:..."`` needs the carried part to keep its Content-ID and
        # inline disposition, or every mail client shows a broken image plus a
        # stray attachment (cid resolution is message-wide per RFC 2392, so
        # the flattened related->mixed structure still renders).
        new_part = dst.get_payload()[-1]
        cid = part.get("Content-ID")
        if cid:
            new_part["Content-ID"] = cid
        if part.get_content_disposition() == "inline":
            del new_part["Content-Disposition"]
            new_part["Content-Disposition"] = "inline"
            if filename:
                new_part.set_param("filename", filename, header="Content-Disposition")
        count += 1
    return count


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
    body_subtype: str = "plain",
    body_html: str | None = None,
) -> EmailMessage:
    """Assemble a safe RFC 5322 message.

    All header-destined fields pass through :func:`validate_header_value`, which
    rejects CR/LF and other control characters before :class:`EmailMessage`
    performs its own header validation.

    ``body_subtype`` is the text subtype of the body part (``"plain"`` by
    default; ``"html"`` to emit a ``text/html`` body). It exists so
    ``update_draft`` can preserve an HTML-only draft's body instead of
    silently flattening it to an empty text/plain part.

    ``body_html``, when non-empty, upgrades the body to
    ``multipart/alternative``: ``body_text`` becomes the text/plain
    alternative and ``body_html`` the text/html one (in that order — RFC 2046
    §5.1.4 orders alternatives by increasing faithfulness). ``body_subtype``
    is ignored in that case. Attachments are added afterwards, which wraps
    the whole thing in ``multipart/mixed``.

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
    if body_html:
        msg.set_content(body_text)
        msg.add_alternative(body_html, subtype="html")
    else:
        msg.set_content(body_text, subtype=body_subtype)
    # Attachments MUST come after the body/alternative: add_attachment() on a
    # multipart/alternative message re-wraps it in multipart/mixed, keeping
    # the alternative intact as the first part.
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
    body_html: str | None = None,
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
        body_html=body_html,
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
    body_html: str | None = None,
) -> EmailMessage:
    """Assemble a reply whose threading headers match ``original_headers``.

    The subject is prefixed with ``Re: `` unless already present. ``In-Reply-To``
    is set to the original ``Message-ID`` and the new ``References`` header
    appends it to the existing chain. When ``include_original_quote`` is true
    the original body (short, quoted with ``> ``) is included — **the caller**
    provides that text; this function does not re-parse the original to avoid
    dragging adversary-controlled content back through the LLM.

    With ``body_html`` the reply becomes ``multipart/alternative``. The
    attribution quote is appended to BOTH alternatives (HTML-escaped in the
    html one) so the two parts stay consistent — mismatched alternatives are
    a spam-filter signal and confuse recipients who switch views.
    """
    recipients = _reply_recipients(from_addr, original_headers, extra_to, reply_all)
    subject_raw = original_headers.get("Subject", "") or ""
    subject = subject_raw if subject_raw.lower().startswith("re:") else f"{RE_PREFIX}{subject_raw}".strip()

    in_reply_to = _first_message_id(original_headers.get("Message-ID", ""))
    prior_refs = original_headers.get("References", "").split()
    references = prior_refs + ([in_reply_to] if in_reply_to else [])

    body = body_text.rstrip()
    html_body = body_html
    if include_original_quote:
        quote = _quote(original_headers, body_text_limit_lines=MAX_QUOTED_LINES)
        body += "\n\n" + quote
        if html_body:
            html_body = _append_quote_html(html_body, quote)
    return build_message(
        from_addr=from_addr,
        to=recipients["to"],
        cc=recipients["cc"] if reply_all else (cc or None),
        subject=subject,
        body_text=body,
        in_reply_to=in_reply_to,
        references=references or None,
        attachments=attachments,
        body_html=html_body,
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


def _append_quote_html(body_html: str, quote_text: str) -> str:
    """Append the attribution quote to an HTML body, escaped.

    The quote contains adversary-controlled header values (From, Date), so
    every line is HTML-escaped before insertion. When the body is a complete
    document the block is inserted before the closing ``</body>`` tag to keep
    it well-formed; otherwise it is appended.
    """
    quote_html = "<br>\n".join(_html_lib.escape(line) for line in quote_text.splitlines())
    block = f'<br><br><div class="quote-attribution">{quote_html}</div>'
    # Case-insensitive search on the ORIGINAL string. Never compute the index
    # on a .lower() copy: str.lower() does not preserve length (U+0130 'İ'
    # lowers to two characters), so a lowered-string offset lands mid-tag and
    # corrupts the HTML.
    matches = list(_CLOSING_BODY_RE.finditer(body_html))
    if matches:
        idx = matches[-1].start()
        return body_html[:idx] + block + body_html[idx:]
    return body_html + block


def looks_like_html(text: str) -> bool:
    """Cheap heuristic: does ``text`` look like an HTML document?

    Deliberately narrow — only ``<!doctype`` / ``<html`` prefixes — so it
    never misfires on prose that merely mentions markup. The write tools use
    it to warn when a caller passes HTML in ``body`` without ``body_html``
    (the message would deliver as raw source in a text/plain part, with no
    error anywhere).
    """
    return text.lstrip()[:64].lower().startswith(("<!doctype", "<html"))


def _sanitize_attachment_name(value: str) -> str:
    cleaned = "".join(c for c in value if c.isprintable() and c not in '\\/:*?"<>|\r\n\0')
    cleaned = cleaned.strip() or "forwarded-message"
    return cleaned[:60]


def _smtp_authenticate(server: smtplib.SMTP, account: AccountModel, credential: Any) -> None:
    """Authenticate an already-open SMTP session with password or XOAUTH2.

    Kept small and side-effect-only: callers hand us an already-EHLO'd
    server and we leave it ready to ``send_message``. The OAuth branch
    uses :meth:`smtplib.SMTP.auth` with a callback that returns the raw
    XOAUTH2 SASL string. Per ``smtplib`` documentation the callback's
    return value is base64-encoded by ``smtplib`` itself before being
    sent on the wire — so we MUST hand back the raw SASL bytes, not a
    pre-encoded string. (Until v0.3.7 we double-encoded, which made
    Microsoft 365 SMTP OAuth fail even when token acquisition and IMAP
    OAuth worked.)
    """
    from .credentials import AuthCredential  # local import avoids a cycle

    if isinstance(credential, AuthCredential):
        if credential.kind == "oauth2":
            from . import oauth

            xoauth2 = oauth.build_xoauth2(credential.username, credential.secret)
            # ``smtplib.SMTP.auth`` (CPython smtplib.py) calls the callback
            # with the server challenge and base64-encodes whatever it
            # returns. Returning a string-decoded ASCII view of the raw
            # SASL bytes is the supported shape — anything already base64
            # would be encoded a second time and rejected as
            # ``535 5.7.3 Authentication unsuccessful``.
            sasl = xoauth2.decode("ascii")
            server.auth("XOAUTH2", lambda _challenge="": sasl, initial_response_ok=True)
            return
        server.login(credential.username, credential.secret)
        return
    # Legacy str path (password). Preserved for the wizard's pre-save check.
    server.login(account.email, credential)


def test_login(account: AccountModel, credential: Any, *, timeout: float = 15.0) -> None:
    """Authenticate against the account's SMTP server and close the session.

    Used by the interactive wizard to verify the user's credentials before
    saving them. Accepts either a raw password string or an
    :class:`AuthCredential`. Raises the underlying :mod:`smtplib` exception
    on failure.
    """
    ctx = create_tls_context()
    if account.smtp_starttls:
        with smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=timeout) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            _smtp_authenticate(server, account, credential)
    else:
        with smtplib.SMTP_SSL(
            account.smtp_host, account.smtp_port, context=ctx, timeout=timeout
        ) as server:
            _smtp_authenticate(server, account, credential)


def send(
    account: AccountModel,
    credential: Any,
    msg: EmailMessage,
    *,
    bcc: list[str] | None = None,
) -> str:
    """Deliver ``msg`` via SMTP, enforcing TLS.

    ``credential`` is either a raw password string or an
    :class:`AuthCredential` (password or OAuth2). ``bcc`` entries are added
    to the envelope recipients but never appear as a header. Returns the
    message's ``Message-ID``.
    """
    ctx = create_tls_context()
    # Extract envelope recipients with getaddresses, NOT a naive comma-split:
    # a display name containing a comma (``"Smith, John" <john@x>``) would be
    # fragmented into bogus recipients by ``split(",")``. Messages built by
    # build_message join validated bare addresses, but send_draft re-sends a
    # draft that may have been edited in a mail client with display names.
    recipients = [
        addr for _, addr in getaddresses([msg.get("To", ""), msg.get("Cc", "")]) if addr
    ]
    recipients.extend(bcc or [])
    if account.smtp_starttls:
        with smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            _smtp_authenticate(server, account, credential)
            refused = server.send_message(msg, from_addr=account.email, to_addrs=recipients)
    else:
        with smtplib.SMTP_SSL(
            account.smtp_host, account.smtp_port, context=ctx, timeout=30
        ) as server:
            _smtp_authenticate(server, account, credential)
            refused = server.send_message(msg, from_addr=account.email, to_addrs=recipients)
    # ``send_message`` returns a (possibly empty) dict of recipients the server
    # refused. It does NOT raise when *some* recipients are accepted and others
    # rejected — it just returns them here. Surfacing this prevents the
    # send-path sibling of the silent-attachment-drop bug: reporting a
    # message_id as full success while some recipients silently got nothing.
    if refused:
        raise PartialDeliveryError(msg["Message-ID"], refused)
    return msg["Message-ID"]
