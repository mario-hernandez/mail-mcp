"""Pydantic input schemas for MCP tools.

Keeping schema definitions out of the tool-handler files makes it easy to
audit the full external surface of the server in one place.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field


class _AccountScoped(BaseModel):
    account: str | None = Field(
        default=None,
        description="Account alias. Defaults to the configured default account.",
    )


class ListFoldersInput(_AccountScoped):
    pattern: str | None = Field(
        default=None,
        description=(
            "IMAP LIST pattern. Defaults to '*' (everything). "
            "Use '%' to list only top-level folders, 'INBOX/%' to list children of INBOX, etc."
        ),
        max_length=255,
    )
    subscribed_only: bool = Field(
        default=False,
        description="If true, list only mailboxes the user has subscribed to.",
    )


class SearchInput(_AccountScoped):
    mailbox: str = Field(
        default="INBOX",
        description="IMAP mailbox to search in.",
        max_length=255,
    )
    limit: int = Field(
        default=50, ge=1, le=500,
        description="Maximum number of headers to return in this page.",
    )
    offset: int = Field(
        default=0, ge=0, le=10_000,
        description="Skip this many matches before returning; use for pagination.",
    )
    unseen: bool | None = Field(default=None, description="True for UNSEEN, False for SEEN.")
    flagged: bool | None = Field(default=None, description="True for FLAGGED, False for UNFLAGGED.")
    from_: str | None = Field(default=None, alias="from", description="Match the From header.")
    to: str | None = Field(default=None, description="Match the To header.")
    subject: str | None = Field(default=None, description="Match a substring in the Subject.")
    body_contains: str | None = Field(default=None, description="Match a substring in the body.")
    since: date | None = Field(default=None, description="Only messages received on or after this date.")
    before: date | None = Field(default=None, description="Only messages received before this date.")

    model_config = {"populate_by_name": True}


class GetEmailInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255)
    uid: int = Field(ge=1)
    max_chars: int = Field(default=16_000, ge=100, le=64_000)


class ListAttachmentsInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255)
    uid: int = Field(ge=1)


class DownloadAttachmentInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255)
    uid: int = Field(ge=1)
    index: int = Field(ge=0)
    filename: str = Field(min_length=1, max_length=255)


class SaveDraftInput(_AccountScoped):
    to: list[str] = Field(min_length=1, max_length=50)
    subject: str = Field(max_length=998)
    body: str = Field(max_length=200_000)
    cc: list[str] | None = None
    bcc: list[str] | None = None
    in_reply_to: str | None = None
    references: list[str] | None = None


class SendEmailInput(SaveDraftInput):
    confirm: bool = Field(
        default=False,
        description="Must be true to actually send. Acts as an explicit guard.",
    )


class ReplyDraftInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255, description="Mailbox holding the original message.")
    uid: int = Field(ge=1, description="UID of the original message within the mailbox.")
    body: str = Field(max_length=200_000, description="The reply body you want to draft.")
    reply_all: bool = Field(
        default=False,
        description="If true, address all recipients of the original (minus your own address).",
    )
    extra_to: list[str] | None = Field(default=None, description="Extra recipients to append to the reply's To field.")
    cc: list[str] | None = Field(default=None, description="Explicit Cc list when reply_all is false.")
    include_original_quote: bool = Field(
        default=True,
        description="Prefix the draft with a 'On <date>, <sender> wrote:' attribution.",
    )


class ForwardDraftInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255, description="Mailbox holding the original message.")
    uid: int = Field(ge=1, description="UID of the message to forward.")
    to: list[str] = Field(min_length=1, max_length=50, description="Recipients of the forward.")
    comment: str = Field(
        default="",
        max_length=50_000,
        description="Optional note prepended as the forward's body. The original is attached as message/rfc822.",
    )
    cc: list[str] | None = None
    bcc: list[str] | None = None


class MoveEmailInput(_AccountScoped):
    source: str = Field(default="INBOX", max_length=255)
    destination: str = Field(max_length=255)
    uids: list[int] = Field(min_length=1, max_length=100)


class MarkFlagsInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255)
    uids: list[int] = Field(min_length=1, max_length=100)
    mark_read: bool | None = None
    mark_flagged: bool | None = None


class DeleteEmailInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255)
    uids: list[int] = Field(min_length=1, max_length=100)
    permanent: bool = Field(
        default=False,
        description=(
            "When false (default) messages are moved to Trash. When true the "
            "messages are expunged and cannot be recovered; additionally the "
            "server must be started with MAIL_MCP_ALLOW_PERMANENT_DELETE=true."
        ),
    )
    confirm: bool = Field(default=False)
