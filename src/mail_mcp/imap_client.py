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
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime
from email.message import EmailMessage
from html.parser import HTMLParser
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
def connect(account: AccountModel, credential: Any):
    """Open an authenticated IMAP connection with TLS enforced.

    ``credential`` is either a raw password string (legacy path, still used
    by tests and by the wizard pre-save) or an :class:`AuthCredential`
    whose ``kind`` selects the login mechanism. Accepting both keeps the
    rich test suite working without any per-test plumbing change.
    """
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
        _imap_authenticate(client, account, credential)
        yield client
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001, S110 — best-effort teardown, errors are informational only
            pass


def _imap_authenticate(client: IMAPClient, account: AccountModel, credential: Any) -> None:
    """Log in to ``client`` using either a password or an OAuth access token.

    Isolated so the caller's ``with`` statement stays readable and so new
    auth kinds can be added here without touching the context manager.
    """
    from .credentials import AuthCredential  # local import avoids a cycle

    if isinstance(credential, AuthCredential):
        if credential.kind == "oauth2":
            client.oauth2_login(credential.username, credential.secret)
            return
        client.login(credential.username, credential.secret)
        return
    # Legacy str path — kept so tests that call connect(acct, "password")
    # directly keep working.
    client.login(account.email, credential)


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


# Localised system-mailbox names — RFC 6154 SPECIAL-USE is the canonical
# signal, these lists are the last-resort fallbacks for servers that do
# not advertise it. Order matters: check English first (covers Gmail /
# Fastmail / iCloud / generic Cyrus), then the localisations Outlook /
# Exchange / IONOS / GMX use.
_LOCALISED_DRAFTS_FALLBACKS = (
    "Drafts",
    "Borradores",       # Spanish — Outlook 365 ES, IONOS ES
    "Brouillons",       # French — Outlook 365 FR
    "Entwürfe",         # German — Outlook 365 DE, GMX, Web.de
    "Bozze",            # Italian
    "Rascunhos",        # Portuguese
    "Concepten",        # Dutch
    "Utkast",           # Swedish / Norwegian
    "Черновики",        # Russian
    "下書き",            # Japanese
    "草稿",              # Chinese
    "[Gmail]/Drafts",   # Gmail folder-style
    "INBOX.Drafts",     # Cyrus / Dovecot INBOX-prefixed
    "INBOX.Borradores",
    "INBOX.Brouillons",
    "INBOX.Entwürfe",
)

_LOCALISED_TRASH_FALLBACKS = (
    "Trash",
    "Deleted Items",                # Exchange / Outlook English
    "Papelera",                     # Spanish (IONOS, generic)
    "Elementos eliminados",         # Outlook 365 ES
    "Corbeille",                    # French generic
    "Éléments supprimés",           # Outlook 365 FR
    "Papierkorb",                   # German (GMX, Web.de)
    "Gelöschte Elemente",           # Outlook 365 DE
    "Cestino",                      # Italian
    "Posta eliminata",              # Outlook 365 IT
    "Lixo",                         # Portuguese (PT)
    "Lixeira",                      # Portuguese (BR)
    "Itens Excluídos",              # Outlook 365 PT-BR
    "Prullenbak",                   # Dutch
    "Verwijderde items",            # Outlook 365 NL
    "Papperskorgen",                # Swedish
    "Søppel",                       # Norwegian
    "Корзина",                      # Russian
    "Удалённые",                    # Outlook 365 RU
    "ゴミ箱",                        # Japanese
    "回收站",                        # Chinese (CN)
    "已删除邮件",                     # Outlook 365 CN
    "[Gmail]/Trash",
    "INBOX.Trash",
    "INBOX.Papelera",
    "INBOX.Corbeille",
    "INBOX.Papierkorb",
)


def _resolve_special_mailbox(
    client: IMAPClient,
    *,
    hint: str | None,
    configured: str,
    special_use_flag: str,
    fallbacks: tuple[str, ...],
    label: str,
) -> str:
    """Internal resolver shared by drafts and trash lookups.

    The single ``LIST *`` issued for SPECIAL-USE detection is reused for
    all existence checks, so the helper costs one extra IMAP round-trip
    in the worst case.

    Resolution order:

    1. ``hint`` if supplied and that folder exists on the server.
    2. The folder advertised with the requested SPECIAL-USE flag — the
       canonical RFC 6154 signal, and the one the user's mail client
       treats as authoritative. This wins over a potentially-stale
       configured name (a localised account can carry both a residual
       English folder from migration AND a SPECIAL-USE-flagged real
       mailbox; picking the flagged one keeps the user's mail-client
       view consistent).
    3. ``configured`` if it exists on the server.
    4. The first match from ``fallbacks``.
    """
    folders = {f.name: f for f in list_folders(client)}

    def _exists(name: str) -> bool:
        return name in folders

    if hint and _exists(hint):
        return hint
    for f in folders.values():
        if f.special_use == special_use_flag:
            return f.name
    if configured and _exists(configured):
        return configured
    for name in fallbacks:
        if _exists(name):
            return name
    raise RuntimeError(
        f"no {label} mailbox found on the server. Tried RFC 6154 "
        f"SPECIAL-USE {special_use_flag}, the configured name "
        f"{configured!r}, and the common localised fallbacks. Inspect "
        "`mail-mcp doctor` and re-run `mail-mcp init` to refresh the "
        "SPECIAL-USE detection, or pass an explicit `mailbox=` argument."
    )


def resolve_drafts_mailbox(
    client: IMAPClient,
    account: AccountModel,
    *,
    hint: str | None = None,
) -> str:
    """Return the actual drafts mailbox name on the server.

    The wizard normally writes the SPECIAL-USE-discovered name to
    ``account.drafts_mailbox`` at setup time, but accounts that predate
    that detection logic — or servers that did not advertise SPECIAL-USE
    during the initial probe — can end up with the literal default
    ``"Drafts"`` in their config. APPEND then fails with ``[TRYCREATE]
    folder does not exist`` on any non-English mailbox.

    See :func:`_resolve_special_mailbox` for the resolution order
    (hint → SPECIAL-USE \\Drafts → configured name → localised fallback).
    """
    return _resolve_special_mailbox(
        client,
        hint=hint,
        configured=(account.drafts_mailbox or "").strip(),
        special_use_flag="\\Drafts",
        fallbacks=_LOCALISED_DRAFTS_FALLBACKS,
        label="drafts",
    )


def resolve_trash_mailbox(
    client: IMAPClient,
    account: AccountModel,
    *,
    hint: str | None = None,
) -> str:
    """Return the actual trash mailbox name on the server.

    Mirrors :func:`resolve_drafts_mailbox` for the ``\\Trash`` SPECIAL-USE
    flag. Localised Outlook / Exchange accounts use names like
    ``Papelera`` (ES), ``Elementos eliminados`` (Outlook ES),
    ``Corbeille`` (FR), ``Éléments supprimés`` (Outlook FR), or
    ``Papierkorb`` (DE) — which a stale account config of ``"Trash"``
    will not match. Without resolution, ``delete_emails(permanent=false)``
    silently moves messages into a literal ``Trash`` folder the server
    will sometimes auto-create on first use, separate from the mailbox
    the user's mail client treats as their trash.
    """
    return _resolve_special_mailbox(
        client,
        hint=hint,
        configured=(account.trash_mailbox or "").strip(),
        special_use_flag="\\Trash",
        fallbacks=_LOCALISED_TRASH_FALLBACKS,
        label="trash",
    )


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
        ctype = part.get_content_type() or "application/octet-stream"
        if ctype == "message/rfc822":
            # Embedded forwarded message — serialise the inner Message back to
            # RFC822 bytes so the caller receives a valid ``.eml`` they can
            # open in any mail client.
            inner_payload = part.get_payload()
            inner = inner_payload[0] if isinstance(inner_payload, list) and inner_payload else None
            payload = inner.as_bytes() if inner is not None else b""
            # Prefer the part's own filename header; fall back to the inner
            # Subject so the saved file still has a meaningful name when no
            # explicit filename was attached.
            filename = part.get_filename() or _eml_filename_from_subject(
                inner.get("Subject", "") if inner is not None else ""
            )
        else:
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename() or f"attachment-{index}"
        if len(payload) > max_bytes:
            raise RuntimeError(
                f"attachment exceeds max_bytes={max_bytes} (got {len(payload)})"
            )
        return (filename, ctype, payload)
    raise RuntimeError(f"attachment index {index} not found on uid {uid}")


_APPENDUID_RE = re.compile(rb"APPENDUID\s+\d+\s+(\d+)")


def save_draft(
    client: IMAPClient, *, account: AccountModel, message_bytes: bytes,
) -> tuple[str, int]:
    """Append a pre-built MIME message to the drafts mailbox.

    Returns ``(mailbox, uid)`` where ``mailbox`` is the actual server
    folder used — not necessarily ``account.drafts_mailbox``, which can
    be a stale default like ``"Drafts"`` when the real mailbox is
    ``Borradores`` / ``Brouillons`` / ``Entwürfe``. Surfacing the
    resolved name lets callers report it in their tool result so
    downstream ``update_draft`` / ``send_draft`` / ``get_email`` calls
    target the right folder.

    Servers that advertise UIDPLUS (RFC 4315) reply with
    ``[APPENDUID <uidvalidity> <uid>] APPEND completed.``; ``imapclient``
    forwards the raw response bytes, so we extract the trailing UID
    token. Fallback for non-UIDPLUS servers: interpret the response as
    a bare integer, or return UID 0 when neither shape is recognised.

    The drafts mailbox is resolved at runtime via
    :func:`resolve_drafts_mailbox` (SPECIAL-USE first, configured name,
    localised fallback), so accounts whose stored ``drafts_mailbox`` is
    the literal default ``"Drafts"`` still APPEND correctly on servers
    where the real mailbox is named ``Borradores`` / ``Brouillons`` /
    ``Entwürfe`` / etc.
    """
    drafts_mailbox = resolve_drafts_mailbox(client, account)
    validate_mailbox_name(drafts_mailbox)
    raw = client.append(drafts_mailbox, message_bytes, flags=[b"\\Draft"])
    if isinstance(raw, int):
        return drafts_mailbox, raw
    data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode()
    m = _APPENDUID_RE.search(bytes(data))
    if m:
        return drafts_mailbox, int(m.group(1))
    try:
        return drafts_mailbox, int(bytes(data).strip())
    except (TypeError, ValueError):
        return drafts_mailbox, 0


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
        # ``get_quota_root`` returns ``(MailboxQuotaRoots, list[Quota])`` in
        # imapclient 3.x; the quotas are included, so no second call is
        # needed. Some servers advertise the capability but respond with an
        # empty list (Gmail, some Dovecot configs) — treated as "unknown".
        _roots, quotas = client.get_quota_root(folder)
    except Exception:  # noqa: BLE001 — provider may not implement QUOTA
        return {"used_kb": None, "limit_kb": None}
    storage = next((q for q in (quotas or []) if getattr(q, "resource", "") == "STORAGE"), None)
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


class UIDPlusRequired(RuntimeError):
    """Raised when an operation needs RFC 4315 UIDPLUS but the server lacks it.

    Carries a stable ``code`` so callers (and the MCP error classifier) can
    branch on it programmatically. The ``mark_deleted`` fallback is the
    safe alternative for caller-side mutations like ``update_draft`` /
    ``send_draft`` that only intend to remove a single UID they just
    created — leaving a ``\\Deleted``-flagged duplicate is preferable to
    expunging unrelated messages another client has already flagged.
    """

    code = "UIDPLUS_REQUIRED_FOR_SAFE_EXPUNGE"


def _has_uidplus(client: IMAPClient) -> bool:
    """True when the server advertises RFC 4315 UIDPLUS in its capabilities."""
    try:
        caps = client.capabilities()
    except Exception:  # noqa: BLE001 — be conservative on capability probes
        return False
    return b"UIDPLUS" in caps


def safe_uid_expunge(client: IMAPClient, *, uids: list[int]) -> None:
    """Expunge exactly the supplied UIDs from the currently-selected mailbox.

    Bare ``EXPUNGE`` removes every message already flagged ``\\Deleted`` in
    the selected mailbox — including messages another client (Outlook,
    a phone app, a previous failed run) flagged earlier. RFC 4315
    ``UID EXPUNGE`` (UIDPLUS) is the only way to expunge a specific set
    safely. We refuse to fall back to bare ``EXPUNGE`` because that would
    silently reintroduce the very bug this helper exists to prevent.
    """
    if not _has_uidplus(client):
        raise UIDPlusRequired(
            "server does not advertise UIDPLUS, so EXPUNGE cannot be "
            "scoped to specific UIDs without risking unrelated messages "
            "another client has already flagged \\Deleted."
        )
    client.uid_expunge(uids)


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

    The expunge step uses :func:`safe_uid_expunge`, which requires the
    server to advertise RFC 4315 UIDPLUS. Without UIDPLUS the previous
    bare ``EXPUNGE`` would have removed every other message the user (or
    another mail client) had marked ``\\Deleted`` in the same folder.
    Failing closed is the right default: callers that only want to
    remove a single UID they just created can catch
    :class:`UIDPlusRequired` and fall back to mark-deleted-without-expunge.
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
        safe_uid_expunge(client, uids=uids)
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


class _HTMLTextExtractor(HTMLParser):
    """Render an HTML body to a readable plain-text approximation.

    Not a full reflow engine — designed to give the LLM something legible
    when a message is single-part ``text/html`` with no ``text/plain``
    alternative (typical of Outlook 'Forward inline'). Block-level tags
    flush a newline; ``<br>`` flushes a newline; the contents of
    ``<script>``, ``<style>``, ``<head>`` and ``<title>`` are dropped.
    """

    _BLOCK_TAGS = frozenset({
        "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
        "blockquote", "pre", "hr", "table", "thead", "tbody", "tfoot",
        "address", "article", "aside", "footer", "header", "nav", "section",
    })
    _SKIP_TAGS = frozenset({"script", "style", "head", "title"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._buf: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "br":
            self._buf.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag in self._BLOCK_TAGS:
            self._buf.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._buf.append(data)

    def get_text(self) -> str:
        text = "".join(self._buf)
        # Normalise line endings (HTML source frequently carries CRLF that
        # otherwise survives as literal ``\r\n`` in the rendered text).
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Collapse runs of inline whitespace and limit blank-line clusters.
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r" *\n *", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _html_to_text(html: str) -> str:
    """Best-effort HTML → plain-text fallback for HTML-only messages."""
    if not html:
        return ""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 — parser is best-effort, don't crash get_email
        return html
    return parser.get_text()


def _is_text_attachment(part: EmailMessage) -> bool:
    """Heuristic: is a ``text/plain`` part actually a downloadable attachment?

    Some senders attach ``.txt`` files with no Content-Disposition header, and
    we don't want to either capture them as the message body or quietly drop
    them. Treat any ``text/plain`` with a filename as an attachment.
    """
    return bool(part.get_filename())


def _is_attachment_leaf(part: EmailMessage) -> bool:
    """True for non-text leaves and text leaves marked as attachments."""
    disposition = (part.get_content_disposition() or "").lower()
    ctype = part.get_content_type()
    if disposition == "attachment":
        return True
    if ctype.startswith("text/") and not _is_text_attachment(part):
        return False
    return bool(part.get_filename()) or not ctype.startswith("text/")


def _format_forward_divider(inner: EmailMessage) -> str:
    """Produce a human-readable divider preceding a forwarded message body."""
    return (
        "\n\n--- Forwarded message ---\n"
        f"From: {inner.get('From', '')}\n"
        f"Date: {inner.get('Date', '')}\n"
        f"Subject: {inner.get('Subject', '')}\n"
        f"To: {inner.get('To', '')}\n\n"
    )


def _eml_filename_from_subject(subject: str) -> str:
    """Sanitise a forwarded message's Subject into a safe ``.eml`` filename."""
    cleaned = "".join(
        c for c in (subject or "") if c.isprintable() and c not in '\\/:*?"<>|\r\n\0'
    ).strip()
    base = (cleaned or "forwarded-message")[:60]
    return f"{base}.eml"


def _extract_parts(msg: EmailMessage) -> tuple[str, str | None, list[Attachment]]:
    """Render a message's body and enumerate its top-level attachments.

    Forward-as-attachment messages (Outlook/Exchange style with a
    ``message/rfc822`` part) are unfolded so:

    * the inner text/plain (or a text rendering of inner text/html) is
      appended to the outer body with a "--- Forwarded message ---" divider;
    * the ``message/rfc822`` part is *also* surfaced as a virtual attachment
      with ``content_type=message/rfc822`` so callers can ``download_attachment``
      it as ``.eml`` for full-fidelity inspection.

    Attachments belonging to the *inner* forwarded message are intentionally
    NOT promoted to the outer attachment list — they are children of the
    embedded ``.eml`` and a caller that needs them will download the ``.eml``
    and parse it locally. This keeps the index space unambiguous.
    """
    text_chunks: list[str] = []
    html_chunks: list[str] = []
    attachments: list[Attachment] = []
    counter = [0]

    def _next_index() -> int:
        i = counter[0]
        counter[0] = i + 1
        return i

    def _collect_inner_text(part: EmailMessage) -> None:
        """Walk a forwarded ``message/rfc822``'s body for text only.

        Does not register attachments — those belong to the nested ``.eml``
        and are reachable by downloading it. Nested forwards inside this
        forward have their *headers* announced via a divider but their
        bodies are not unfolded again, to bound output size and recursion.
        """
        ctype = part.get_content_type()
        if ctype == "message/rfc822":
            inner_payload = part.get_payload()
            inner = inner_payload[0] if isinstance(inner_payload, list) and inner_payload else None
            if inner is not None:
                text_chunks.append(_format_forward_divider(inner))
            return
        if part.is_multipart():
            for child in part.iter_parts():
                _collect_inner_text(child)
            return
        if _is_attachment_leaf(part):
            return
        if ctype == "text/plain":
            text_chunks.append(_safe_get_content(part))
        elif ctype == "text/html":
            html_chunks.append(_safe_get_content(part))

    def _visit(part: EmailMessage) -> None:
        ctype = part.get_content_type()

        if ctype == "message/rfc822":
            inner_payload = part.get_payload()
            inner = inner_payload[0] if isinstance(inner_payload, list) and inner_payload else None
            if inner is None:
                return
            try:
                inner_bytes = inner.as_bytes()
            except Exception:  # noqa: BLE001 — defensive, malformed nested message
                inner_bytes = b""
            # Prefer the part's own filename header (Content-Disposition
            # ``filename=`` or Content-Type ``name=``); fall back to the inner
            # Subject only when no explicit filename was attached. This lets
            # ``save_draft(attachments=[{"filename": "evidence.eml", ...}])``
            # round-trip the user-chosen name instead of overwriting it with
            # ``forwarded-message.eml``.
            attachments.append(
                Attachment(
                    filename=part.get_filename() or _eml_filename_from_subject(
                        inner.get("Subject", "")
                    ),
                    content_type="message/rfc822",
                    size=len(inner_bytes),
                    index=_next_index(),
                )
            )
            text_chunks.append(_format_forward_divider(inner))
            _collect_inner_text(inner)
            return

        if part.is_multipart():
            for child in part.iter_parts():
                _visit(child)
            return

        if _is_attachment_leaf(part):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=part.get_filename() or f"attachment-{counter[0]}",
                    content_type=ctype,
                    size=len(payload),
                    index=_next_index(),
                )
            )
            return

        if ctype == "text/plain":
            text_chunks.append(_safe_get_content(part))
        elif ctype == "text/html":
            html_chunks.append(_safe_get_content(part))

    _visit(msg)
    text = "".join(text_chunks).strip()
    html = "\n".join(html_chunks) if html_chunks else None
    # Single-part text/html messages (common from Outlook 'Forward inline')
    # have no text/plain alternative. Render the HTML so the body field is
    # not silently empty.
    if not text and html:
        text = _html_to_text(html)
    return text, html, attachments


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
    """Yield top-level attachment-like parts in the same order as :func:`_extract_parts`.

    Includes ``message/rfc822`` parts so a caller can download a forwarded
    message as ``.eml``. Inner attachments of a forwarded message are NOT
    yielded; they belong to the nested ``.eml`` and are reachable only by
    parsing that file.
    """
    def _walk_top_level(part: EmailMessage):
        ctype = part.get_content_type()
        if ctype == "message/rfc822":
            yield part
            return
        if part.is_multipart():
            for child in part.iter_parts():
                yield from _walk_top_level(child)
            return
        if _is_attachment_leaf(part):
            yield part

    yield from _walk_top_level(msg)
