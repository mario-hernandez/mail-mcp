"""MCP server wiring.

Tools are registered conditionally: read-only tools are always available,
destructive tools only when ``MAIL_MCP_WRITE_ENABLED=true``, and the explicit
``send_email`` tool only when ``MAIL_MCP_SEND_ENABLED=true``. Conditional
*registration* — rather than a runtime flag inside a single handler — means
the disabled tools are not even visible to the LLM, which materially reduces
the prompt-injection surface.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from .config import Config, load
from .safety.redaction import sanitize_error
from .tools import drafts, organize, read, send
from .tools.schemas import (
    CreateFolderInput,
    DeleteEmailInput,
    DeleteFolderInput,
    DownloadAttachmentInput,
    ForwardDraftInput,
    GetEmailInput,
    ListAttachmentsInput,
    ListFoldersInput,
    MarkFlagsInput,
    MoveEmailInput,
    RenameFolderInput,
    ReplyDraftInput,
    SaveDraftInput,
    SearchInput,
    SendEmailInput,
)

log = logging.getLogger("mail_mcp")


def write_enabled() -> bool:
    return os.environ.get("MAIL_MCP_WRITE_ENABLED", "false").lower() == "true"


def build_server(cfg: Config | None = None) -> Server:
    cfg = cfg or load()
    server: Server = Server("mail-mcp")

    readonly_tools: list[tuple[Tool, type, Any]] = [
        (
            Tool(
                name="list_folders",
                description="List all IMAP folders for the account.",
                inputSchema=ListFoldersInput.model_json_schema(),
                annotations={"readOnlyHint": True},
            ),
            ListFoldersInput,
            read.list_folders,
        ),
        (
            Tool(
                name="search_emails",
                description=(
                    "Search emails in a mailbox. Criteria are passed to IMAP "
                    "as structured tokens to prevent injection."
                ),
                inputSchema=SearchInput.model_json_schema(),
                annotations={"readOnlyHint": True},
            ),
            SearchInput,
            read.search,
        ),
        (
            Tool(
                name="get_email",
                description=(
                    "Fetch one email. The body is wrapped in an untrusted-content "
                    "block to resist prompt injection."
                ),
                inputSchema=GetEmailInput.model_json_schema(),
                annotations={"readOnlyHint": True},
            ),
            GetEmailInput,
            read.get_email,
        ),
        (
            Tool(
                name="list_attachments",
                description="List attachments (metadata only) for an email.",
                inputSchema=ListAttachmentsInput.model_json_schema(),
                annotations={"readOnlyHint": True},
            ),
            ListAttachmentsInput,
            read.list_attachments,
        ),
        (
            Tool(
                name="download_attachment",
                description=(
                    "Download an attachment to the local mail-mcp downloads "
                    "directory (~/Downloads/mail-mcp/<account>/)."
                ),
                inputSchema=DownloadAttachmentInput.model_json_schema(),
                annotations={"readOnlyHint": True},
            ),
            DownloadAttachmentInput,
            read.download_attachment,
        ),
        (
            Tool(
                name="save_draft",
                description=(
                    "Build a MIME message and store it in the Drafts mailbox. "
                    "Preferred write path — the human reviews the draft in "
                    "their own email client before sending."
                ),
                inputSchema=SaveDraftInput.model_json_schema(),
                annotations={"readOnlyHint": False, "destructiveHint": False},
            ),
            SaveDraftInput,
            drafts.save_draft,
        ),
        (
            Tool(
                name="reply_draft",
                description=(
                    "Draft a reply to an existing message. Threading headers "
                    "(In-Reply-To, References, Subject 'Re: …') are derived "
                    "from the original; the original body is NOT re-read into "
                    "the model context, only an attribution header is added."
                ),
                inputSchema=ReplyDraftInput.model_json_schema(),
                annotations={"readOnlyHint": False, "destructiveHint": False},
            ),
            ReplyDraftInput,
            drafts.reply_draft,
        ),
        (
            Tool(
                name="forward_draft",
                description=(
                    "Draft a forward of an existing message. The original is "
                    "attached verbatim as message/rfc822 — its body and "
                    "attachments are never re-parsed through the LLM, "
                    "neutralising prompt-injection carried inside forwarded "
                    "content."
                ),
                inputSchema=ForwardDraftInput.model_json_schema(),
                annotations={"readOnlyHint": False, "destructiveHint": False},
            ),
            ForwardDraftInput,
            drafts.forward_draft,
        ),
    ]

    write_tools: list[tuple[Tool, type, Any]] = [
        (
            Tool(
                name="move_email",
                description="Move one or more messages between mailboxes.",
                inputSchema=MoveEmailInput.model_json_schema(),
                annotations={"destructiveHint": True},
            ),
            MoveEmailInput,
            organize.move_email,
        ),
        (
            Tool(
                name="mark_emails",
                description="Set or clear read/flagged state on messages.",
                inputSchema=MarkFlagsInput.model_json_schema(),
                annotations={"destructiveHint": False},
            ),
            MarkFlagsInput,
            organize.mark,
        ),
        (
            Tool(
                name="delete_emails",
                description=(
                    "Move messages to Trash (default) or permanently delete "
                    "them. Permanent deletion requires "
                    "MAIL_MCP_ALLOW_PERMANENT_DELETE=true plus confirm=true."
                ),
                inputSchema=DeleteEmailInput.model_json_schema(),
                annotations={"destructiveHint": True},
            ),
            DeleteEmailInput,
            organize.delete_email,
        ),
        (
            Tool(
                name="create_folder",
                description=(
                    "Create an IMAP folder. Idempotent: succeeds silently if "
                    "the folder already exists."
                ),
                inputSchema=CreateFolderInput.model_json_schema(),
                annotations={"destructiveHint": False, "idempotentHint": True},
            ),
            CreateFolderInput,
            organize.create_folder,
        ),
        (
            Tool(
                name="rename_folder",
                description="Rename an IMAP folder. Fails if the destination already exists.",
                inputSchema=RenameFolderInput.model_json_schema(),
                annotations={"destructiveHint": False},
            ),
            RenameFolderInput,
            organize.rename_folder,
        ),
        (
            Tool(
                name="delete_folder",
                description=(
                    "Delete an IMAP folder. Refuses non-empty folders unless "
                    "confirm=true is passed — deleting a folder with messages "
                    "is irreversible on most providers."
                ),
                inputSchema=DeleteFolderInput.model_json_schema(),
                annotations={"destructiveHint": True},
            ),
            DeleteFolderInput,
            organize.delete_folder,
        ),
    ]

    send_tool: list[tuple[Tool, type, Any]] = [
        (
            Tool(
                name="send_email",
                description=(
                    "Send an email via SMTP. Gated by environment variables "
                    "and requires confirm=true. Prefer save_draft unless you "
                    "really intend to send without human review."
                ),
                inputSchema=SendEmailInput.model_json_schema(),
                annotations={"destructiveHint": True, "openWorldHint": True},
            ),
            SendEmailInput,
            send.send_email,
        ),
    ]

    registered = list(readonly_tools)
    if write_enabled():
        registered.extend(write_tools)
        if send.is_enabled():
            registered.extend(send_tool)

    tool_map = {tool.name: (schema, handler) for tool, schema, handler in registered}

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [tool for tool, _s, _h in registered]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        entry = tool_map.get(name)
        if entry is None:
            payload = {
                "error": {
                    **sanitize_error(RuntimeError(f"unknown tool {name!r}")),
                    "code": "UNKNOWN_TOOL",
                }
            }
            return [TextContent(type="text", text=json.dumps(payload))]
        schema, handler = entry
        started = time.perf_counter()
        try:
            parsed = schema.model_validate(arguments or {})
            # Hand the synchronous IMAP/SMTP work off to a worker thread so
            # the stdio event loop can dispatch other tool calls in parallel.
            result = await asyncio.to_thread(handler, cfg, parsed)
        except Exception as exc:  # noqa: BLE001 - surfaced to caller sanitised
            duration = int((time.perf_counter() - started) * 1000)
            log.warning(
                "tool=%s outcome=error duration_ms=%d type=%s",
                name, duration, exc.__class__.__name__,
            )
            payload = {"error": _classify(exc)}
            return [TextContent(type="text", text=json.dumps(payload))]
        duration = int((time.perf_counter() - started) * 1000)
        log.info("tool=%s outcome=ok duration_ms=%d", name, duration)
        return [TextContent(type="text", text=json.dumps(result, default=str))]

    return server


def _classify(exc: BaseException) -> dict[str, Any]:
    """Tag an exception with a stable error code and a remediation hint.

    The LLM sees the returned dict inside ``{"error": ...}``. A stable
    ``code`` lets agents branch programmatically without sniffing free-text
    messages, and ``hint`` gives them a concrete next action to try.
    """
    base = sanitize_error(exc)
    cls = exc.__class__.__name__
    lower = str(exc).lower()
    code = "INTERNAL_ERROR"
    hint: str | None = None
    retryable = False

    if cls == "RateLimited":
        code = "RATE_LIMITED"
        hint = (
            "The per-account hourly send ceiling was reached. "
            "Raise MAIL_MCP_SEND_HOURLY_LIMIT or wait ~1 hour."
        )
        retryable = True
    elif cls in {"SendDisabled", "OperationDisabled"}:
        code = "PERMISSION_DENIED"
        hint = (
            "This tool is gated behind an environment flag. "
            "Start the server with the required env var, e.g. "
            "MAIL_MCP_WRITE_ENABLED=true, and re-register the MCP client."
        )
    elif cls == "ValidationError" or "validation" in lower:
        code = "VALIDATION_ERROR"
        hint = "Review the tool schema and resubmit with corrected arguments."
    elif "authentication" in lower or "badcredentials" in lower or cls in {"LoginError", "SMTPAuthenticationError"}:
        code = "AUTH_FAILED"
        hint = (
            "Credentials were rejected. For Gmail / iCloud / Outlook.com "
            "generate an app-specific password; re-run `mail-mcp init` if "
            "unsure."
        )
    elif "certificate" in lower or "ssl" in lower or "tls" in lower:
        code = "TLS_ERROR"
        hint = (
            "The server's TLS certificate could not be validated. Fix the "
            "certificate chain on the server side; mail-mcp does not offer "
            "a verification bypass."
        )
    elif "timeout" in lower or cls in {"TimeoutError", "socket.timeout"}:
        code = "TIMEOUT"
        hint = "The network call timed out. Retry; if it persists the server may be offline."
        retryable = True
    elif "not found" in lower or cls == "RuntimeError" and "uid" in lower:
        code = "NOT_FOUND"
        hint = "The UID or mailbox does not exist. Call search_emails or list_folders first."
    elif "unreachable" in lower or "resolve" in lower or "nodename" in lower:
        code = "NETWORK_UNREACHABLE"
        hint = "Host could not be resolved or reached. Check connectivity and host configuration."
        retryable = True

    return {**base, "code": code, "hint": hint, "retryable": retryable}


async def run_stdio() -> None:
    logging.basicConfig(
        level=os.environ.get("MAIL_MCP_LOG_LEVEL", "WARNING").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    cfg = load()
    try:
        default_alias = cfg.account().alias
    except RuntimeError:
        default_alias = "(none)"
    log.warning(
        "mail-mcp %s ready on stdio | account=%s | write=%s | send=%s",
        __version__,
        default_alias,
        write_enabled(),
        send.is_enabled(),
    )
    server = build_server(cfg=cfg)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
