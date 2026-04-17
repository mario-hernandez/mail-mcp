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
    pass


class SearchInput(_AccountScoped):
    mailbox: str = Field(default="INBOX", max_length=255)
    limit: int = Field(default=50, ge=1, le=500)
    unseen: bool | None = None
    flagged: bool | None = None
    from_: str | None = Field(default=None, alias="from")
    to: str | None = None
    subject: str | None = None
    body_contains: str | None = None
    since: date | None = None
    before: date | None = None

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
