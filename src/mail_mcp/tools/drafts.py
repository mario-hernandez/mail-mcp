"""Draft creation tools — the preferred write path.

Creating a draft is the safest mutating operation offered by this server: the
message lands in the user's Drafts mailbox where a human reviews and sends it
from their own email client. Any automation built on top of this server should
prefer ``save_draft`` / ``reply_draft`` / ``forward_draft`` over
``send_email`` wherever possible.
"""

from __future__ import annotations

from .. import imap_client, smtp_client
from ..config import Config
from ..keyring_store import get_password
from .schemas import ForwardDraftInput, ReplyDraftInput, SaveDraftInput


def save_draft(cfg: Config, params: SaveDraftInput) -> dict:
    acct = cfg.account(params.account)
    password = get_password(acct.alias, acct.email)
    msg = smtp_client.build_message(
        from_addr=acct.email,
        to=params.to,
        cc=params.cc,
        subject=params.subject,
        body_text=params.body,
        in_reply_to=params.in_reply_to,
        references=params.references,
    )
    # BCC is deliberately not persisted on a draft: the user's mail client
    # will re-enter BCC at send time. Drafts with BCC headers break some
    # providers' threading.
    with imap_client.connect(acct, password) as c:
        draft_uid = imap_client.save_draft(c, account=acct, message_bytes=bytes(msg))
    return {
        "account": acct.alias,
        "mailbox": acct.drafts_mailbox,
        "uid": int(draft_uid),
        "message_id": msg["Message-ID"],
    }


def reply_draft(cfg: Config, params: ReplyDraftInput) -> dict:
    acct = cfg.account(params.account)
    password = get_password(acct.alias, acct.email)
    with imap_client.connect(acct, password) as c:
        _raw, headers = imap_client.fetch_raw_message(
            c, mailbox=params.mailbox, uid=params.uid,
        )
        msg = smtp_client.build_reply_message(
            from_addr=acct.email,
            original_headers=headers,
            body_text=params.body,
            extra_to=params.extra_to,
            cc=params.cc,
            reply_all=params.reply_all,
            include_original_quote=params.include_original_quote,
        )
        draft_uid = imap_client.save_draft(c, account=acct, message_bytes=bytes(msg))
    return {
        "account": acct.alias,
        "mailbox": acct.drafts_mailbox,
        "uid": int(draft_uid),
        "message_id": msg["Message-ID"],
        "in_reply_to": msg.get("In-Reply-To"),
        "subject": msg.get("Subject"),
    }


def forward_draft(cfg: Config, params: ForwardDraftInput) -> dict:
    acct = cfg.account(params.account)
    password = get_password(acct.alias, acct.email)
    with imap_client.connect(acct, password) as c:
        raw, headers = imap_client.fetch_raw_message(
            c, mailbox=params.mailbox, uid=params.uid,
        )
        msg, _bcc = smtp_client.build_forward_message(
            from_addr=acct.email,
            to=params.to,
            original_headers=headers,
            original_raw=raw,
            comment=params.comment,
            cc=params.cc,
            bcc=params.bcc,
        )
        draft_uid = imap_client.save_draft(c, account=acct, message_bytes=bytes(msg))
    return {
        "account": acct.alias,
        "mailbox": acct.drafts_mailbox,
        "uid": int(draft_uid),
        "message_id": msg["Message-ID"],
        "subject": msg.get("Subject"),
        "attached": "original message attached as message/rfc822",
    }
