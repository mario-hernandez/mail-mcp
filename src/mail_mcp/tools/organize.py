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
from ..credentials import resolve_auth
from .schemas import (
    CopyEmailInput,
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
    return acct, resolve_auth(acct)


def create_folder(cfg: Config, params: CreateFolderInput) -> dict:
    acct, creds = _auth(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        imap_client.create_folder(c, mailbox=params.mailbox)
    return {"account": acct.alias, "mailbox": params.mailbox, "status": "created"}


def rename_folder(cfg: Config, params: RenameFolderInput) -> dict:
    acct, creds = _auth(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        imap_client.rename_folder(c, old_name=params.old_name, new_name=params.new_name)
    return {
        "account": acct.alias,
        "old_name": params.old_name,
        "new_name": params.new_name,
        "status": "renamed",
    }


def delete_folder(cfg: Config, params: DeleteFolderInput) -> dict:
    acct, creds = _auth(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        removed = imap_client.delete_folder(
            c, mailbox=params.mailbox, allow_non_empty=params.confirm,
        )
    return {
        "account": acct.alias,
        "mailbox": params.mailbox,
        "status": "deleted",
        "messages_lost": removed,
    }


def copy_email(cfg: Config, params: CopyEmailInput) -> dict:
    acct, creds = _auth(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
        copied = imap_client.copy_uids(
            c, source=params.source, destination=params.destination, uids=params.uids,
        )
    return {
        "account": acct.alias,
        "copied": copied,
        "source": params.source,
        "destination": params.destination,
    }


def move_email(cfg: Config, params: MoveEmailInput) -> dict:
    acct, creds = _auth(cfg, params.account)
    with imap_client.connect(acct, creds) as c:
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
    acct, creds = _auth(cfg, params.account)
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
    with imap_client.connect(acct, creds) as c:
        affected = imap_client.set_flags(
            c,
            mailbox=params.mailbox,
            uids=params.uids,
            add=add or None,
            remove=remove or None,
        )
    return {"account": acct.alias, "affected": affected}


def delete_email(cfg: Config, params: DeleteEmailInput) -> dict:
    acct, creds = _auth(cfg, params.account)
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
    with imap_client.connect(acct, creds) as c:
        # For trash-mode delete, resolve the actual trash mailbox at call
        # time. ``acct.trash_mailbox`` is just a hint; servers in Spanish /
        # French / German use ``Papelera`` / ``Corbeille`` / ``Papierkorb``
        # (or Outlook 365's ``Elementos eliminados`` / ``Éléments
        # supprimés`` / ``Gelöschte Elemente``) and a stale literal
        # ``"Trash"`` would either fail or land messages in a folder the
        # user's mail client does not treat as their trash. Permanent
        # delete does not consult Trash so we skip resolution there.
        if params.permanent:
            trash = acct.trash_mailbox  # not used; kept for delete_uids signature
        else:
            trash = imap_client.resolve_trash_mailbox(c, acct)
        affected = imap_client.delete_uids(
            c,
            mailbox=params.mailbox,
            uids=params.uids,
            trash_mailbox=trash,
            permanent=params.permanent,
        )
    response = {
        "account": acct.alias,
        "affected": affected,
        "mode": "permanent" if params.permanent else "trash",
    }
    if not params.permanent:
        response["trash_mailbox"] = trash
    return response
