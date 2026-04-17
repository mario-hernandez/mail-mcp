"""IMAP wrapper built on :mod:`imapclient`.

Design notes
------------
* TLS is mandatory: connections must use ``SSL`` (implicit) or ``STARTTLS``.
  The default :func:`ssl.create_default_context` certificate chain is always
  used — there is no knob to disable verification.
* Searches are performed with structured criteria (``imapclient`` accepts
  typed lists like ``['SUBJECT', 'hello', 'SINCE', date]``) to eliminate
  an entire class of IMAP-injection bugs by construction.
* Message bodies are truncated before they reach the LLM context, attachments
  are size-capped, and the rendered content is wrapped by the XPIA guard in
  the tool layer.
* Destructive actions (move, flag, delete) live in this module but are only
  exercised by tools that are themselves gated behind ``MAIL_MCP_WRITE_ENABLED``.
"""

from __future__ import annotations

import email
import email.policy
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime
from email.message import EmailMessage
from typing import Any

from imapclient import IMAPClient, SocketTimeout

from .config import AccountModel
from .safety.tls import create_tls_context
from .safety.validation import (
    ValidationError,
    clamp_int,
    escape_imap_quoted,
    validate_header_value,
    validate_mailbox_name,
)

MAX_BODY_CHARS = 16_000
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_BATCH_UIDS = 100

_IMAP_CONNECT_TIMEOUT = float(os.environ.get("MAIL_MCP_IMAP_CONNECT_TIMEOUT", "15"))
_IMAP_READ_TIMEOUT = float(os.environ.get("MAIL_MCP_IMAP_READ_TIMEOUT", "30"))


@dataclass
class EmailHeader:
    uid: int
    subject: str
    from_: str
    to: list[str]
    cc: list[str]
    date: str | None
    flags: list[str]


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    index: int


@dataclass
class EmailBody:
    header: EmailHeader
    text: str
    html_rendered: str | None
    attachments: list[Attachment] = field(default_factory=list)
    truncated: bool = False


@contextmanager
def connect(account: AccountModel, password: str):
    """Open an authenticated IMAP connection with TLS enforced."""
    ctx = create_tls_context()
    if not account.imap_use_ssl:
        raise ValidationError("IMAP connections must use SSL/TLS (imap_use_ssl=true)")
    client = IMAPClient(
        account.imap_host,
        port=account.imap_port,
        ssl=True,
        ssl_context=ctx,
        timeout=SocketTimeout(connect=_IMAP_CONNECT_TIMEOUT, read=_IMAP_READ_TIMEOUT),
    )
    try:
        client.login(account.email, password)
        yield client
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001, S110 — best-effort teardown, errors are informational only
            pass


@dataclass
class FolderInfo:
    name: str
    delimiter: str
    flags: list[str]
    special_use: str | None  # "\\Drafts", "\\Trash", "\\Sent", "\\Junk", "\\Archive", ...


def list_folders(
    client: IMAPClient,
    *,
    pattern: str = "*",
    subscribed_only: bool = False,
) -> list[FolderInfo]:
    """List folders, optionally filtered by IMAP pattern or subscription state.

    ``pattern`` uses IMAP LIST wildcards: ``*`` matches any characters
    including the hierarchy delimiter, ``%`` matches any characters except the
    delimiter. Defaults to ``*`` (everything).
    """
    raw = (
        client.list_sub_folders(pattern=pattern)
        if subscribed_only
        else client.list_folders(pattern=pattern)
    )
    specials = {b"\\Drafts", b"\\Trash", b"\\Sent", b"\\Junk", b"\\Archive", b"\\All", b"\\Flagged", b"\\Important"}
    out: list[FolderInfo] = []
    for flags, delim, name in raw:
        flag_strs = [_flag_to_str(f) for f in flags]
        special_bytes = next((f for f in flags if f in specials), None)
        special = _flag_to_str(special_bytes) if special_bytes else None
        delim_str = delim.decode() if isinstance(delim, bytes) else (delim or "")
        out.append(FolderInfo(name=name, delimiter=delim_str, flags=flag_strs, special_use=special))
    out.sort(key=lambda f: f.name)
    return out


def detect_special_mailboxes(client: IMAPClient) -> dict[str, str]:
    """Return a ``{special_use: mailbox_name}`` map using RFC 6154 SPECIAL-USE.

    Used by the setup wizard to auto-detect localised mailboxes so that
    ``save_draft`` and ``delete_emails`` work on non-English accounts
    (Gmail ``[Gmail]/Drafts``, iCloud ``Borradores``, IONOS ``Papelera``,
    ...).
    """
    found: dict[str, str] = {}
    for info in list_folders(client):
        if info.special_use and info.special_use not in found:
            found[info.special_use] = info.name
    return found


def _flag_to_str(flag: Any) -> str:
    if isinstance(flag, bytes):
        try:
            return flag.decode()
        except UnicodeDecodeError:
            return flag.decode("latin-1", errors="replace")
    return str(flag)


def _build_criteria(
    *,
    mailbox: str,
    unseen: bool | None,
    flagged: bool | None,
    from_: str | None,
    to: str | None,
    subject: str | None,
    body_contains: str | None,
    since: date | None,
    before: date | None,
) -> list[Any]:
    validate_mailbox_name(mailbox)
    criteria: list[Any] = []
    if unseen is True:
        criteria.append("UNSEEN")
    elif unseen is False:
        criteria.append("SEEN")
    if flagged is True:
        criteria.append("FLAGGED")
    elif flagged is False:
        criteria.append("UNFLAGGED")
    if from_:
        validate_header_value(from_, field="from")
        criteria.extend(["FROM", escape_imap_quoted(from_)])
    if to:
        validate_header_value(to, field="to")
        criteria.extend(["TO", escape_imap_quoted(to)])
    if subject:
        validate_header_value(subject, field="subject")
        criteria.extend(["SUBJECT", escape_imap_quoted(subject)])
    if body_contains:
        validate_header_value(body_contains, field="body_contains", max_length=2000)
        criteria.extend(["BODY", escape_imap_quoted(body_contains)])
    if since:
        criteria.extend(["SINCE", since])
    if before:
        criteria.extend(["BEFORE", before])
    if not criteria:
        criteria.append("ALL")
    return criteria


def search(
    client: IMAPClient,
    *,
    mailbox: str,
    limit: int = 50,
    offset: int = 0,
    unseen: bool | None = None,
    flagged: bool | None = None,
    from_: str | None = None,
    to: str | None = None,
    subject: str | None = None,
    body_contains: str | None = None,
    since: date | None = None,
    before: date | None = None,
) -> tuple[int, list[EmailHeader]]:
    """Search a mailbox and return ``(total_matches, page_of_headers)``.

    ``total_matches`` is the pre-pagination count of UIDs matching the
    criteria; ``page_of_headers`` is the ``limit``-sized slice after
    ``offset``, newest first.
    """
    limit = clamp_int(limit, low=1, high=500, field="limit")
    offset = clamp_int(offset, low=0, high=10_000, field="offset")
    client.select_folder(mailbox, readonly=True)
    criteria = _build_criteria(
        mailbox=mailbox,
        unseen=unseen,
        flagged=flagged,
        from_=from_,
        to=to,
        subject=subject,
        body_contains=body_contains,
        since=since,
        before=before,
    )
    all_uids = client.search(criteria)
    total = len(all_uids)
    uids = sorted(all_uids, reverse=True)[offset : offset + limit]
    if not uids:
        return total, []
    fetched = client.fetch(uids, ["ENVELOPE", "FLAGS", "INTERNALDATE"])
    headers: list[EmailHeader] = []
    for uid in uids:
        item = fetched.get(uid)
        if not item:
            continue
        env = item.get(b"ENVELOPE")
        flags = [f.decode(errors="replace") for f in item.get(b"FLAGS", ())]
        subject_val = _decode(env.subject) if env and env.subject else ""
        from_val = _format_address(env.from_[0]) if env and env.from_ else ""
        to_val = [_format_address(a) for a in (env.to or [])] if env else []
        cc_val = [_format_address(a) for a in (env.cc or [])] if env else []
        date_val = item.get(b"INTERNALDATE")
        headers.append(
            EmailHeader(
                uid=int(uid),
                subject=subject_val,
                from_=from_val,
                to=to_val,
                cc=cc_val,
                date=date_val.isoformat() if isinstance(date_val, datetime) else None,
                flags=flags,
            )
        )
    return total, headers


def fetch_raw_message(
    client: IMAPClient,
    *,
    mailbox: str,
    uid: int,
) -> tuple[bytes, dict[str, str]]:
    """Fetch a message's raw RFC822 bytes plus a small set of headers.

    Used by ``forward_draft`` to attach the original as ``message/rfc822``
    without re-parsing its body into the LLM context, and by ``reply_draft``
    to pull ``Message-ID`` / ``References`` / ``Subject`` / ``From`` /
    ``Reply-To`` so it can thread the reply correctly.
    """
    validate_mailbox_name(mailbox)
    client.select_folder(mailbox, readonly=True)
    fetched = client.fetch([uid], ["RFC822"])
    item = fetched.get(uid)
    if not item:
        raise RuntimeError(f"uid {uid} not found in {mailbox!r}")
    raw: bytes = item[b"RFC822"]
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    headers = {
        name: str(msg.get(name, ""))
        for name in ("Message-ID", "References", "In-Reply-To", "Subject", "From", "To", "Cc", "Reply-To", "Date")
    }
    return raw, headers


def get_message(
    client: IMAPClient,
    *,
    mailbox: str,
    uid: int,
    max_chars: int = MAX_BODY_CHARS,
) -> EmailBody:
    validate_mailbox_name(mailbox)
    max_chars = clamp_int(max_chars, low=100, high=64_000, field="max_chars")
    client.select_folder(mailbox, readonly=True)
    fetched = client.fetch([uid], ["RFC822", "FLAGS", "INTERNALDATE"])
    item = fetched.get(uid)
    if not item:
        raise RuntimeError(f"uid {uid} not found in {mailbox!r}")
    raw = item[b"RFC822"]
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    text, html_rendered, attachments = _extract_parts(msg)
    truncated = False
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True
    header = EmailHeader(
        uid=int(uid),
        subject=msg.get("Subject", ""),
        from_=msg.get("From", ""),
        to=[a.strip() for a in msg.get("To", "").split(",") if a.strip()],
        cc=[a.strip() for a in msg.get("Cc", "").split(",") if a.strip()],
        date=msg.get("Date"),
        flags=[f.decode(errors="replace") for f in item.get(b"FLAGS", ())],
    )
    return EmailBody(
        header=header,
        text=text,
        html_rendered=html_rendered,
        attachments=attachments,
        truncated=truncated,
    )


def download_attachment(
    client: IMAPClient,
    *,
    mailbox: str,
    uid: int,
    index: int,
    max_bytes: int = MAX_ATTACHMENT_BYTES,
) -> tuple[str, str, bytes]:
    validate_mailbox_name(mailbox)
    max_bytes = clamp_int(max_bytes, low=1, high=MAX_ATTACHMENT_BYTES, field="max_bytes")
    client.select_folder(mailbox, readonly=True)
    fetched = client.fetch([uid], ["RFC822"])
    item = fetched.get(uid)
    if not item:
        raise RuntimeError(f"uid {uid} not found in {mailbox!r}")
    msg: EmailMessage = email.message_from_bytes(item[b"RFC822"], policy=email.policy.default)  # type: ignore[assignment]
    for i, part in enumerate(_iter_attachments(msg)):
        if i != index:
            continue
        payload = part.get_payload(decode=True) or b""
        if len(payload) > max_bytes:
            raise RuntimeError(
                f"attachment exceeds max_bytes={max_bytes} (got {len(payload)})"
            )
        return (
            part.get_filename() or f"attachment-{index}",
            part.get_content_type() or "application/octet-stream",
            payload,
        )
    raise RuntimeError(f"attachment index {index} not found on uid {uid}")


def save_draft(client: IMAPClient, *, account: AccountModel, message_bytes: bytes) -> int:
    """Append a pre-built MIME message to the drafts mailbox."""
    validate_mailbox_name(account.drafts_mailbox)
    return int(client.append(account.drafts_mailbox, message_bytes, flags=[b"\\Draft"]))


def copy_uids(
    client: IMAPClient,
    *,
    source: str,
    destination: str,
    uids: list[int],
) -> int:
    """COPY UIDs to ``destination`` without removing them from ``source``."""
    validate_mailbox_name(source)
    validate_mailbox_name(destination)
    if not uids:
        return 0
    if len(uids) > MAX_BATCH_UIDS:
        raise ValidationError(f"batch too large (max {MAX_BATCH_UIDS} uids)")
    client.select_folder(source, readonly=False)
    client.copy(uids, destination)
    return len(uids)


def get_quota(client: IMAPClient, *, folder: str = "INBOX") -> dict[str, int | None]:
    """Return ``{"used_kb": int, "limit_kb": int | None}`` for the folder's quota root.

    If the server does not advertise QUOTA we return ``{"used_kb": None,
    "limit_kb": None}`` rather than raising — callers can show "unknown".
    """
    validate_mailbox_name(folder)
    try:
        roots, _ = client.get_quota_root(folder)
    except Exception:  # noqa: BLE001 — provider may not implement QUOTA
        return {"used_kb": None, "limit_kb": None}
    if not roots:
        return {"used_kb": None, "limit_kb": None}
    quotas = client.get_quota(roots[0])
    storage = next((q for q in quotas if getattr(q, "resource", "") == "STORAGE"), None)
    if storage is None:
        return {"used_kb": None, "limit_kb": None}
    return {"used_kb": int(storage.usage), "limit_kb": int(storage.limit)}


def thread_references(
    client: IMAPClient,
    *,
    mailbox: str,
    since_days: int = 90,
) -> list[list[int]]:
    """Return a nested UID list grouped by thread using the THREAD extension.

    Falls back to an empty list when the server lacks ``THREAD=REFERENCES``;
    the caller handles reconstruction from headers.
    """
    validate_mailbox_name(mailbox)
    caps = client.capabilities()
    if b"THREAD=REFERENCES" not in caps:
        return []
    client.select_folder(mailbox, readonly=True)
    from datetime import date as _date
    from datetime import timedelta

    criteria = ["SINCE", _date.today() - timedelta(days=max(1, since_days))]
    try:
        tree = client.thread("REFERENCES", "UTF-8", criteria)
    except Exception:  # noqa: BLE001 — server may reject unsupported charset
        return []
    flat: list[list[int]] = []

    def _walk(node: Any) -> list[int]:
        if isinstance(node, int):
            return [node]
        out: list[int] = []
        for item in node:
            out.extend(_walk(item))
        return out

    for group in tree:
        flat.append(_walk(group))
    return flat


def fetch_headers(
    client: IMAPClient,
    *,
    mailbox: str,
    uids: list[int],
) -> list[EmailHeader]:
    """Fetch ENVELOPE-level headers for the given UIDs, in order."""
    validate_mailbox_name(mailbox)
    if not uids:
        return []
    client.select_folder(mailbox, readonly=True)
    fetched = client.fetch(uids, ["ENVELOPE", "FLAGS", "INTERNALDATE"])
    out: list[EmailHeader] = []
    for uid in uids:
        item = fetched.get(uid)
        if not item:
            continue
        env = item.get(b"ENVELOPE")
        flags = [f.decode(errors="replace") for f in item.get(b"FLAGS", ())]
        subject_val = _decode(env.subject) if env and env.subject else ""
        from_val = _format_address(env.from_[0]) if env and env.from_ else ""
        to_val = [_format_address(a) for a in (env.to or [])] if env else []
        cc_val = [_format_address(a) for a in (env.cc or [])] if env else []
        date_val = item.get(b"INTERNALDATE")
        out.append(
            EmailHeader(
                uid=int(uid),
                subject=subject_val,
                from_=from_val,
                to=to_val,
                cc=cc_val,
                date=date_val.isoformat() if isinstance(date_val, datetime) else None,
                flags=flags,
            )
        )
    return out


def move_uids(
    client: IMAPClient,
    *,
    source: str,
    destination: str,
    uids: list[int],
) -> int:
    validate_mailbox_name(source)
    validate_mailbox_name(destination)
    if not uids:
        return 0
    if len(uids) > MAX_BATCH_UIDS:
        raise ValidationError(f"batch too large (max {MAX_BATCH_UIDS} uids)")
    client.select_folder(source, readonly=False)
    client.move(uids, destination)
    return len(uids)


def create_folder(client: IMAPClient, *, mailbox: str) -> None:
    """Create an IMAP folder. Idempotent: succeeds if the folder already exists."""
    validate_mailbox_name(mailbox)
    if client.folder_exists(mailbox):
        return
    client.create_folder(mailbox)


def rename_folder(client: IMAPClient, *, old_name: str, new_name: str) -> None:
    validate_mailbox_name(old_name, field="old_name")
    validate_mailbox_name(new_name, field="new_name")
    if not client.folder_exists(old_name):
        raise RuntimeError(f"folder {old_name!r} does not exist")
    if client.folder_exists(new_name):
        raise RuntimeError(f"folder {new_name!r} already exists")
    client.rename_folder(old_name, new_name)


def delete_folder(client: IMAPClient, *, mailbox: str, allow_non_empty: bool) -> int:
    """Delete an IMAP folder. Refuses non-empty folders unless explicitly allowed.

    Returns the count of messages that were inside the folder before deletion
    (0 for the safe empty-folder path).
    """
    validate_mailbox_name(mailbox)
    if not client.folder_exists(mailbox):
        raise RuntimeError(f"folder {mailbox!r} does not exist")
    status = client.folder_status(mailbox, what=["MESSAGES"])
    count = int(status.get(b"MESSAGES", 0))
    if count and not allow_non_empty:
        raise RuntimeError(
            f"folder {mailbox!r} is not empty ({count} messages). "
            "Pass confirm=true to allow deletion of a non-empty folder."
        )
    client.delete_folder(mailbox)
    return count


def set_flags(
    client: IMAPClient,
    *,
    mailbox: str,
    uids: list[int],
    add: list[str] | None = None,
    remove: list[str] | None = None,
) -> int:
    validate_mailbox_name(mailbox)
    if not uids:
        return 0
    if len(uids) > MAX_BATCH_UIDS:
        raise ValidationError(f"batch too large (max {MAX_BATCH_UIDS} uids)")
    client.select_folder(mailbox, readonly=False)
    if add:
        client.add_flags(uids, [f.encode() for f in add])
    if remove:
        client.remove_flags(uids, [f.encode() for f in remove])
    return len(uids)


def delete_uids(
    client: IMAPClient,
    *,
    mailbox: str,
    uids: list[int],
    trash_mailbox: str,
    permanent: bool,
) -> int:
    """Move to Trash by default; only expunge when ``permanent=True``.

    Permanent deletion is irreversible and is gated by the caller both via the
    ``permanent`` flag and by the ``MAIL_MCP_ALLOW_PERMANENT_DELETE`` env var.
    """
    validate_mailbox_name(mailbox)
    validate_mailbox_name(trash_mailbox)
    if not uids:
        return 0
    if len(uids) > MAX_BATCH_UIDS:
        raise ValidationError(f"batch too large (max {MAX_BATCH_UIDS} uids)")
    if permanent:
        client.select_folder(mailbox, readonly=False)
        client.add_flags(uids, [b"\\Deleted"])
        client.expunge()
        return len(uids)
    return move_uids(client, source=mailbox, destination=trash_mailbox, uids=uids)


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return value.decode("latin-1", errors="replace")
    return str(value) if value is not None else ""


def _format_address(addr: Any) -> str:
    if addr is None:
        return ""
    mailbox = _decode(addr.mailbox) if addr.mailbox else ""
    host = _decode(addr.host) if addr.host else ""
    name = _decode(addr.name) if addr.name else ""
    email_repr = f"{mailbox}@{host}" if mailbox and host else mailbox or host
    return f"{name} <{email_repr}>".strip() if name else email_repr


def _extract_parts(msg: EmailMessage) -> tuple[str, str | None, list[Attachment]]:
    text_part = ""
    html_part: str | None = None
    attachments: list[Attachment] = []
    idx = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if disposition == "attachment" or (part.get_filename() and ctype != "text/plain"):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=part.get_filename() or f"attachment-{idx}",
                    content_type=ctype,
                    size=len(payload),
                    index=idx,
                )
            )
            idx += 1
            continue
        if ctype == "text/plain" and not text_part:
            text_part = _safe_get_content(part)
        elif ctype == "text/html" and html_part is None:
            html_part = _safe_get_content(part)
    return text_part, html_part, attachments


def _safe_get_content(part: EmailMessage) -> str:
    """Decode a text MIME part, tolerating unknown or malformed charsets."""
    try:
        if hasattr(part, "get_content"):
            return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError):
        pass
    raw = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    for candidate in (charset, "utf-8", "latin-1"):
        try:
            return raw.decode(candidate, errors="strict")
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("latin-1", errors="replace")


def _iter_attachments(msg: EmailMessage):
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment" or (
            part.get_filename() and part.get_content_type() != "text/plain"
        ):
            yield part
