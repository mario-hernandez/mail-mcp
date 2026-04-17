"""Organising tools: move, flag, delete.

These are destructive (or, in the case of flags, state-changing) operations.
They are registered only when ``MAIL_MCP_WRITE_ENABLED=true``; permanent
deletion additionally requires ``MAIL_MCP_ALLOW_PERMANENT_DELETE=true`` and an
explicit ``confirm=true`` in the tool call.
"""

from __future__ import annotations

import os

from .. import imap_client
from ..config import Config
from ..keyring_store import get_password
from .schemas import (
    CreateFolderInput,
    DeleteEmailInput,
    DeleteFolderInput,
    MarkFlagsInput,
    MoveEmailInput,
    RenameFolderInput,
)


class OperationDisabled(RuntimeError):
    """Raised when a destructive tool is invoked without the required gates."""


def _auth(cfg: Config, alias: str | None):
    acct = cfg.account(alias)
    return acct, get_password(acct.alias, acct.email)


def create_folder(cfg: Config, params: CreateFolderInput) -> dict:
    acct, password = _auth(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        imap_client.create_folder(c, mailbox=params.mailbox)
    return {"account": acct.alias, "mailbox": params.mailbox, "status": "created"}


def rename_folder(cfg: Config, params: RenameFolderInput) -> dict:
    acct, password = _auth(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        imap_client.rename_folder(c, old_name=params.old_name, new_name=params.new_name)
    return {
        "account": acct.alias,
        "old_name": params.old_name,
        "new_name": params.new_name,
        "status": "renamed",
    }


def delete_folder(cfg: Config, params: DeleteFolderInput) -> dict:
    acct, password = _auth(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        removed = imap_client.delete_folder(
            c, mailbox=params.mailbox, allow_non_empty=params.confirm,
        )
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "status": "deleted",
        "messages_lost": removed,
    }


def move_email(cfg: Config, params: MoveEmailInput) -> dict:
    acct, password = _auth(cfg, params.account)
    with imap_client.connect(acct, password) as c:
        moved = imap_client.move_uids(
            c, source=params.source, destination=params.destination, uids=params.uids
        )
    return {
        "account": acct.alias,
        "moved": moved,
        "source": params.source,
        "destination": params.destination,
    }


def mark(cfg: Config, params: MarkFlagsInput) -> dict:
    acct, password = _auth(cfg, params.account)
    add: list[str] = []
    remove: list[str] = []
    if params.mark_read is True:
        add.append("\\Seen")
    elif params.mark_read is False:
        remove.append("\\Seen")
    if params.mark_flagged is True:
        add.append("\\Flagged")
    elif params.mark_flagged is False:
        remove.append("\\Flagged")
    with imap_client.connect(acct, password) as c:
        affected = imap_client.set_flags(
            c,
            mailbox=params.mailbox,
            uids=params.uids,
            add=add or None,
            remove=remove or None,
        )
    return {"account": acct.alias, "affected": affected}


def delete_email(cfg: Config, params: DeleteEmailInput) -> dict:
    acct, password = _auth(cfg, params.account)
    if params.permanent:
        allow_perm = (
            os.environ.get("MAIL_MCP_ALLOW_PERMANENT_DELETE", "false").lower() == "true"
        )
        if not allow_perm:
            raise OperationDisabled(
                "Permanent delete is disabled. Set "
                "MAIL_MCP_ALLOW_PERMANENT_DELETE=true to enable it."
            )
        if not params.confirm:
            raise OperationDisabled(
                "Permanent delete requires the caller to pass confirm=true."
            )
    with imap_client.connect(acct, password) as c:
        affected = imap_client.delete_uids(
            c,
            mailbox=params.mailbox,
            uids=params.uids,
            trash_mailbox=acct.trash_mailbox,
            permanent=params.permanent,
        )
    return {
        "account": acct.alias,
        "affected": affected,
        "mode": "permanent" if params.permanent else "trash",
    }
