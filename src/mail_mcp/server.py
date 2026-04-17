"""MCP server wiring.

Tools are registered conditionally: read-only tools are always available,
destructive tools only when ``MAIL_MCP_WRITE_ENABLED=true``, and the explicit
``send_email`` tool only when ``MAIL_MCP_SEND_ENABLED=true``. Conditional
*registration* — rather than a runtime flag inside a single handler — means
the disabled tools are not even visible to the LLM, which materially reduces
the prompt-injection surface.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from .config import Config, load
from .safety.redaction import sanitize_error
from .tools import drafts, organize, read, send
from .tools.schemas import (
    DeleteEmailInput,
    DownloadAttachmentInput,
    GetEmailInput,
    ListAttachmentsInput,
    ListFoldersInput,
    MarkFlagsInput,
    MoveEmailInput,
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
            payload = {"error": sanitize_error(RuntimeError(f"unknown tool {name!r}"))}
            return [TextContent(type="text", text=json.dumps(payload))]
        schema, handler = entry
        try:
            parsed = schema.model_validate(arguments or {})
            result = handler(cfg, parsed)
        except Exception as exc:  # noqa: BLE001 - surfaced to caller sanitised
            log.error("tool %s failed: %s", name, exc.__class__.__name__)
            payload = {"error": sanitize_error(exc)}
            return [TextContent(type="text", text=json.dumps(payload))]
        return [TextContent(type="text", text=json.dumps(result, default=str))]

    return server


async def run_stdio() -> None:
    logging.basicConfig(
        level=os.environ.get("MAIL_MCP_LOG_LEVEL", "WARNING").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    log.info("mail-mcp %s starting (stdio)", __version__)
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
