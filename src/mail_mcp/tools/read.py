"""Read-only tools: list folders, search, get a message, handle attachments.

Every message body returned to the LLM is wrapped by the XPIA guard so an
attacker cannot smuggle instructions through the email content.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .. import imap_client
from ..config import Config
from ..credentials import resolve_auth
from ..safety.guards import sanitize_header, wrap_untrusted
from ..safety.paths import default_download_root, prepare_download_path
from .schemas import (
    AccountInfoInput,
    DownloadAttachmentInput,
    GetEmailInput,
    GetEmailRawInput,
    GetQuotaInput,
    GetThreadInput,
    ListAccountsInput,
    ListAttachmentsInput,
    ListDraftsInput,
    ListFoldersInput,
    SearchInput,
    SpecialFoldersInput,
)


def _resolve(cfg: Config, alias: str | None):
    acct = cfg.account(alias)
    return acct, resolve_auth(acct)


def _sanitize_header_dict(header: dict) -> dict:
    """Apply ``sanitize_header`` to every attacker-controlled header value.

    Subjects, addresses and filenames reach the LLM as plain text: a crafted
    email could otherwise smuggle instructions that look like trusted system
    prompts rather than untrusted payload.
    """
    return {
        **header,
        "subject": sanitize_header(header.get("subject", "")),
        "from_": sanitize_header(header.get("from_", "")),
        "to": [sanitize_header(a) for a in header.get("to", [])],
        "cc": [sanitize_header(a) for a in header.get("cc", [])],
    }


def _sanitize_attachment(att: dict) -> dict:
    return {**att, "filename": sanitize_header(att.get("filename", ""), max_length=255)}


def list_folders(cfg: Config, params: ListFoldersInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        folders = imap_client.list_folders(
            c,
            pattern=params.pattern or "*",
            subscribed_only=params.subscribed_only,
        )
    return {
        "account": acct.alias,
        "count": len(folders),
        "folders": [
            {
                "name": f.name,
                "delimiter": f.delimiter,
                "flags": f.flags,
                "special_use": f.special_use,
            }
            for f in folders
        ],
    }


def search(cfg: Config, params: SearchInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        total, headers = imap_client.search(
            c,
            mailbox=params.mailbox,
            limit=params.limit,
            offset=params.offset,
            unseen=params.unseen,
            flagged=params.flagged,
            from_=params.from_,
            to=params.to,
            subject=params.subject,
            body_contains=params.body_contains,
            since=params.since,
            before=params.before,
        )
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "total": total,
        "offset": params.offset,
        "returned": len(headers),
        "results": [_sanitize_header_dict(asdict(h)) for h in headers],
    }


def get_email(cfg: Config, params: GetEmailInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        body = imap_client.get_message(
            c,
            mailbox=params.mailbox,
            uid=params.uid,
            max_chars=params.max_chars,
        )
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "header": _sanitize_header_dict(asdict(body.header)),
        "attachments": [_sanitize_attachment(asdict(a)) for a in body.attachments],
        "truncated": body.truncated,
        "body": wrap_untrusted(body.text),
    }


def get_email_raw(cfg: Config, params: GetEmailRawInput) -> dict:
    """Return the message's raw RFC822 source as decoded text.

    The escape hatch for unusual MIME structures (forwarded messages embedded
    as ``message/rfc822``, broken multiparts, exotic encodings). Truncates at
    ``max_bytes`` and wraps the rendered text in the untrusted-content
    envelope. The full bytes are also written to disk under
    ``~/Downloads/mail-mcp/<alias>/`` as a ``.eml`` so the caller can read or
    parse them locally without burning tokens on a re-fetch.
    """
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        raw, headers = imap_client.fetch_raw_message(
            c, mailbox=params.mailbox, uid=params.uid,
        )
    truncated = len(raw) > params.max_bytes
    rendered_bytes = raw[: params.max_bytes] if truncated else raw
    rendered = rendered_bytes.decode("utf-8", errors="replace")
    root: Path = default_download_root()
    target = prepare_download_path(
        root,
        acct.alias,
        f"raw-uid-{params.uid}.eml",
    )
    target.write_bytes(raw)
    target.chmod(0o600)
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "uid": params.uid,
        "bytes": len(raw),
        "truncated": truncated,
        "saved_path": str(target),
        "headers": _sanitize_header_dict(headers),
        "raw": wrap_untrusted(rendered),
    }


def list_attachments(cfg: Config, params: ListAttachmentsInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        body = imap_client.get_message(
            c, mailbox=params.mailbox, uid=params.uid, max_chars=100
        )
    return {
        "account": acct.alias,
        "uid": params.uid,
        "attachments": [_sanitize_attachment(asdict(a)) for a in body.attachments],
    }


def list_accounts(cfg: Config, _params: ListAccountsInput) -> dict:
    default = cfg.model.default_alias
    return {
        "count": len(cfg.model.accounts),
        "default": default,
        "accounts": [
            {"alias": a.alias, "email": a.email, "is_default": a.alias == default}
            for a in cfg.model.accounts
        ],
    }


def get_account_info(cfg: Config, params: AccountInfoInput) -> dict:
    acct = cfg.account(params.account)
    return {
        "alias": acct.alias,
        "email": acct.email,
        "imap": {"host": acct.imap_host, "port": acct.imap_port, "ssl": acct.imap_use_ssl},
        "smtp": {"host": acct.smtp_host, "port": acct.smtp_port, "starttls": acct.smtp_starttls},
        "drafts_mailbox": acct.drafts_mailbox,
        "trash_mailbox": acct.trash_mailbox,
        "is_default": acct.alias == cfg.model.default_alias,
    }


def get_special_folders(cfg: Config, params: SpecialFoldersInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        specials = imap_client.detect_special_mailboxes(c)
    return {"account": acct.alias, "special_folders": specials}


def get_quota(cfg: Config, params: GetQuotaInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        quota = imap_client.get_quota(c, folder=params.folder)
    return {"account": acct.alias, "folder": params.folder, **quota}


def list_drafts(cfg: Config, params: ListDraftsInput) -> dict:
    """List messages from the account's drafts mailbox.

    The mailbox is resolved at call time via
    :func:`imap_client.resolve_drafts_mailbox` (SPECIAL-USE first, then
    configured value, then localised fallbacks). This keeps
    ``list_drafts`` consistent with ``save_draft`` / ``update_draft`` —
    a draft created in ``Borradores`` shows up in this listing even
    when the account config still carries the literal default
    ``"Drafts"``.
    """
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        drafts_mailbox = imap_client.resolve_drafts_mailbox(c, acct)
        total, headers = imap_client.search(
            c,
            mailbox=drafts_mailbox,
            limit=params.limit,
            offset=params.offset,
        )
    return {
        "account": acct.alias,
        "mailbox": drafts_mailbox,
        "total": total,
        "offset": params.offset,
        "returned": len(headers),
        "results": [_sanitize_header_dict(h.__dict__) for h in headers],
    }


def get_thread(cfg: Config, params: GetThreadInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        # 1) find which thread the UID belongs to, then return that thread's UIDs.
        groups = imap_client.thread_references(
            c, mailbox=params.mailbox, since_days=params.since_days,
        )
        target: list[int] | None = None
        for group in groups:
            if params.uid in group:
                target = group
                break
        if target is None:
            # Fallback: confirm the UID exists and return it as a singleton thread.
            imap_client.fetch_raw_message(c, mailbox=params.mailbox, uid=params.uid)
            target = [params.uid]
            notes = ["server did not advertise THREAD=REFERENCES; returning the message alone"]
        else:
            notes = []
        target = sorted(target)[: params.max_messages]
        messages = imap_client.fetch_headers(c, mailbox=params.mailbox, uids=target)
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "thread_size": len(target),
        "returned": len(messages),
        "messages": [_sanitize_header_dict(m.__dict__) for m in messages],
        "notes": notes,
    }


def download_attachment(cfg: Config, params: DownloadAttachmentInput) -> dict:
    acct, creds = _resolve(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        filename, ctype, payload = imap_client.download_attachment(
            c,
            mailbox=params.mailbox,
            uid=params.uid,
            index=params.index,
        )
    root: Path = default_download_root()
    target = prepare_download_path(root, acct.alias, params.filename or filename)
    target.write_bytes(payload)
    target.chmod(0o600)
    return {
        "account": acct.alias,
        "uid": params.uid,
        "path": str(target),
        "bytes": len(payload),
        "content_type": ctype,
    }
