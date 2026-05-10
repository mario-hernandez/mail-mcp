"""Draft creation tools — the preferred write path.

Creating a draft is the safest mutating operation offered by this server: the
message lands in the user's Drafts mailbox where a human reviews and sends it
from their own email client. Any automation built on top of this server should
prefer ``save_draft`` / ``reply_draft`` / ``forward_draft`` over
``send_email`` wherever possible.
"""

from __future__ import annotations

from .. import imap_client, smtp_client
from ..config import AccountModel, Config
from ..credentials import resolve_auth
from ..safety.attachments import resolve_many
from ..safety.validation import ValidationError
from .schemas import (
    ForwardDraftInput,
    ReplyDraftInput,
    SaveDraftInput,
    SendDraftInput,
    UpdateDraftInput,
)


def _drafts_mailbox_strict(
    client, account: AccountModel, override: str | None, *, tool: str,
) -> str:
    """Resolve the drafts mailbox and refuse caller-supplied non-drafts overrides.

    ``update_draft`` and ``send_draft`` both end with a permanent delete
    of the source UID. Without this check, a caller (or a prompt-injected
    model on a default-visible draft tool) could pass
    ``mailbox="INBOX"`` plus an arbitrary UID and the handler would
    happily APPEND a copy to Drafts and then UID-expunge the original
    from INBOX — bypassing ``MAIL_MCP_WRITE_ENABLED``,
    ``MAIL_MCP_ALLOW_PERMANENT_DELETE``, and the per-call ``confirm=true``
    that ``delete_emails`` requires for the same primitive. That is a
    trust-boundary violation in a tool the user expects to operate
    only on drafts.

    The strict resolution: always derive the drafts mailbox from server
    state (SPECIAL-USE \\Drafts → configured value → localised list).
    If the caller provided ``override``, it must equal that resolved
    name; anything else raises :class:`ValidationError` with a clear
    explanation. Pre-flight fails before any IMAP fetch / append /
    delete, so a rejected call mutates nothing.
    """
    resolved = imap_client.resolve_drafts_mailbox(client, account)
    if override is not None and override != resolved:
        raise ValidationError(
            f"{tool} only operates on the account's drafts mailbox. "
            f"Resolved drafts mailbox is {resolved!r}; got "
            f"mailbox={override!r}. Pass mailbox=None (the default) to "
            "let the server-side SPECIAL-USE detection pick the right "
            "folder, or pass exactly the resolved name above."
        )
    return resolved


def save_draft(cfg: Config, params: SaveDraftInput) -> dict:
    acct = cfg.account(params.account)
    creds = resolve_auth(acct)
    attachments = resolve_many(params.attachments) if params.attachments else []
    msg = smtp_client.build_message(
        from_addr=acct.email,
        to=params.to,
        cc=params.cc,
        subject=params.subject,
        body_text=params.body,
        in_reply_to=params.in_reply_to,
        references=params.references,
        attachments=attachments,
    )
    # BCC is deliberately not persisted on a draft: the user's mail client
    # will re-enter BCC at send time. Drafts with BCC headers break some
    # providers' threading.
    with imap_client.connect(acct, creds) as c:
        drafts_mailbox, draft_uid = imap_client.save_draft(
            c, account=acct, message_bytes=bytes(msg),
        )
    return {
        "account": acct.alias,
        "mailbox": drafts_mailbox,
        "uid": int(draft_uid),
        "message_id": msg["Message-ID"],
    }


def reply_draft(cfg: Config, params: ReplyDraftInput) -> dict:
    acct = cfg.account(params.account)
    creds = resolve_auth(acct)
    with imap_client.connect(acct, creds) as c:
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
        drafts_mailbox, draft_uid = imap_client.save_draft(
            c, account=acct, message_bytes=bytes(msg),
        )
    return {
        "account": acct.alias,
        "mailbox": drafts_mailbox,
        "uid": int(draft_uid),
        "message_id": msg["Message-ID"],
        "in_reply_to": msg.get("In-Reply-To"),
        "subject": msg.get("Subject"),
    }


def update_draft(cfg: Config, params: UpdateDraftInput) -> dict:
    """Replace a draft in place via APPEND-then-DELETE.

    IMAP has no UPDATE. The safe ordering is: build the new message, APPEND
    it (new UID), only then mark the old UID deleted and expunge. A failure
    in the APPEND step leaves the original draft untouched; a failure in the
    delete step leaves a harmless duplicate rather than data loss.

    Attachment semantics:

    * ``attachments`` omitted (``None``) — the original draft's attachments
      are carried over unchanged. This matches the implicit "preserve"
      behaviour that ``preserve_message_id`` / ``in_reply_to`` already use
      for header-bound fields.
    * ``attachments=[]`` — explicitly clear all attachments.
    * ``attachments=[spec, ...]`` — replace the attachment set with the
      supplied list.
    """
    import email as _email
    import email.policy as _policy

    acct = cfg.account(params.account)
    creds = resolve_auth(acct)
    with imap_client.connect(acct, creds) as c:
        mailbox = _drafts_mailbox_strict(c, acct, params.mailbox, tool="update_draft")
        raw, headers = imap_client.fetch_raw_message(
            c, mailbox=mailbox, uid=params.uid,
        )
        original = _email.message_from_bytes(raw, policy=_policy.default)
        if params.to is not None:
            new_to = params.to
        else:
            new_to = [a.strip() for a in original.get("To", "").split(",") if a.strip()]
        if params.cc is not None:
            new_cc = params.cc
        else:
            extracted_cc = [a.strip() for a in original.get("Cc", "").split(",") if a.strip()]
            new_cc = extracted_cc or None
        new_subject = params.subject if params.subject is not None else original.get("Subject", "")
        if params.body is not None:
            new_body = params.body
        else:
            new_body = original.get_body(preferencelist=("plain",))
            new_body = new_body.get_content() if new_body else ""
        in_reply_to = params.in_reply_to if params.in_reply_to is not None else original.get("In-Reply-To")
        references = params.references if params.references is not None else (
            original.get("References", "").split() or None
        )
        new_attachments = (
            resolve_many(params.attachments) if params.attachments else []
        )
        msg = smtp_client.build_message(
            from_addr=acct.email,
            to=new_to,
            cc=new_cc,
            subject=new_subject,
            body_text=new_body,
            in_reply_to=in_reply_to,
            references=references,
            attachments=new_attachments,
        )
        if params.attachments is None:
            # Preserve the original's attachments — caller did not opt in to
            # a replacement set. Empty list means "explicitly clear", which
            # is honoured by passing ``[]`` to ``resolve_many`` above.
            smtp_client.carry_over_attachments(original, msg)
        if params.preserve_message_id and original.get("Message-ID"):
            del msg["Message-ID"]
            msg["Message-ID"] = original["Message-ID"]
        new_drafts_mailbox, new_uid = imap_client.save_draft(
            c, account=acct, message_bytes=bytes(msg),
        )
        warning = _delete_old_draft_uid_safely(
            c, mailbox=mailbox, uid=params.uid, trash_mailbox=acct.trash_mailbox,
        )
    response = {
        "account": acct.alias,
        "mailbox": new_drafts_mailbox,
        "old_uid": params.uid,
        "new_uid": int(new_uid),
        "message_id": msg["Message-ID"],
    }
    if warning:
        response["warning"] = warning
    return response


def _delete_old_draft_uid_safely(
    client, *, mailbox: str, uid: int, trash_mailbox: str,
) -> str | None:
    """Delete the previous draft UID, falling back to mark-deleted on no-UIDPLUS.

    ``update_draft`` and ``send_draft`` both APPEND a new copy and then
    have to remove the old UID. Bare ``EXPUNGE`` would risk wiping
    unrelated ``\\Deleted``-flagged messages in the same folder, and the
    safe ``UID EXPUNGE`` requires RFC 4315 UIDPLUS. When the server does
    not advertise UIDPLUS we fall back to flagging the old UID
    ``\\Deleted`` without expunging — the user sees a duplicate the next
    time their mail client re-syncs, which is recoverable; expunging
    other people's messages is not.
    """
    try:
        imap_client.delete_uids(
            client,
            mailbox=mailbox,
            uids=[uid],
            trash_mailbox=trash_mailbox,
            permanent=True,
        )
        return None
    except imap_client.UIDPlusRequired:
        client.select_folder(mailbox, readonly=False)
        client.add_flags([uid], [b"\\Deleted"])
        return (
            f"server does not advertise UIDPLUS; the previous draft "
            f"(uid={uid}) has been flagged \\Deleted but not expunged "
            "to avoid removing unrelated messages another client may "
            "have flagged. Your mail client will hide it on next sync."
        )


def send_draft(cfg: Config, params: SendDraftInput) -> dict:
    """Send an existing draft via SMTP, then remove it from Drafts.

    Gated identically to ``send_email`` — requires both env gates plus
    ``confirm=true`` and counts against the per-account rate limit.
    """
    from .send import SendDisabled, _check_rate_limit, is_enabled

    if not is_enabled():
        raise SendDisabled(
            "send_draft is registered but disabled by env-var gate.",
            code=SendDisabled.NOT_ENABLED,
        )
    if not params.confirm:
        raise SendDisabled(
            "send_draft requires confirm=true on the call (per-tool safety, "
            "not a configuration issue).",
            code=SendDisabled.REQUIRES_CONFIRM,
        )

    import email as _email
    import email.policy as _policy

    acct = cfg.account(params.account)
    _check_rate_limit(acct.alias)
    creds = resolve_auth(acct)
    with imap_client.connect(acct, creds) as c:
        mailbox = _drafts_mailbox_strict(c, acct, params.mailbox, tool="send_draft")
        raw, _headers = imap_client.fetch_raw_message(
            c, mailbox=mailbox, uid=params.uid,
        )
        msg = _email.message_from_bytes(raw, policy=_policy.default)
        # Strip any X-* or transport headers the IMAP server added
        for hdr in ("X-Mozilla-Draft-Info", "X-Mozilla-Keys"):
            if hdr in msg:
                del msg[hdr]
        message_id = smtp_client.send(acct, creds, msg)
        warning = _delete_old_draft_uid_safely(
            c, mailbox=mailbox, uid=params.uid, trash_mailbox=acct.trash_mailbox,
        )
    response: dict = {
        "account": acct.alias,
        "message_id": message_id,
        "draft_uid": params.uid,
        "status": "sent",
    }
    if warning:
        response["warning"] = warning
    return response


def forward_draft(cfg: Config, params: ForwardDraftInput) -> dict:
    acct = cfg.account(params.account)
    creds = resolve_auth(acct)
    with imap_client.connect(acct, creds) as c:
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
        drafts_mailbox, draft_uid = imap_client.save_draft(
            c, account=acct, message_bytes=bytes(msg),
        )
    return {
        "account": acct.alias,
        "mailbox": drafts_mailbox,
        "uid": int(draft_uid),
        "message_id": msg["Message-ID"],
        "subject": msg.get("Subject"),
        "attached": "original message attached as message/rfc822",
    }
