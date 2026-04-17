"""Read-only tools: list folders, search, get a message, handle attachments.

Every message body returned to the LLM is wrapped by the XPIA guard so an
attacker cannot smuggle instructions through the email content.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
from pathlib import Path

from .. import imap_client
from ..config import Config
from ..keyring_store import get_password
from ..safety.guards import wrap_untrusted
from ..safety.paths import default_download_root, prepare_download_path
from .schemas import (
    DownloadAttachmentInput,
    GetEmailInput,
    ListAttachmentsInput,
    ListFoldersInput,
    SearchInput,
)


def _resolve(cfg: Config, alias: str | None):
    acct = cfg.account(alias)
    password = get_password(acct.alias, acct.email)
    return acct, password


def list_folders(cfg: Config, params: ListFoldersInput) -> dict:
    acct, password = _resolve(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        folders = imap_client.list_folders(c)
    return {"account": acct.alias, "folders": folders}


def search(cfg: Config, params: SearchInput) -> dict:
    acct, password = _resolve(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        headers = imap_client.search(
            c,
            mailbox=params.mailbox,
            limit=params.limit,
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
        "count": len(headers),
        "results": [asdict(h) for h in headers],
    }


def get_email(cfg: Config, params: GetEmailInput) -> dict:
    acct, password = _resolve(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        body = imap_client.get_message(
            c,
            mailbox=params.mailbox,
            uid=params.uid,
            max_chars=params.max_chars,
        )
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "header": asdict(body.header),
        "attachments": [asdict(a) for a in body.attachments],
        "truncated": body.truncated,
        "body": wrap_untrusted(body.text),
    }


def list_attachments(cfg: Config, params: ListAttachmentsInput) -> dict:
    acct, password = _resolve(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        body = imap_client.get_message(
            c, mailbox=params.mailbox, uid=params.uid, max_chars=100
        )
    return {
        "account": acct.alias,
        "uid": params.uid,
        "attachments": [asdict(a) for a in body.attachments],
    }


def download_attachment(cfg: Config, params: DownloadAttachmentInput) -> dict:
    acct, password = _resolve(cfg, params.account)
    with imap_client.connect(acct, password) as c:
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
        "preview_base64": base64.b64encode(payload[:2048]).decode("ascii"),
    }
