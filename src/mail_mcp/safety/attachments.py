"""Filesystem-sourced email attachments.

Resolving an LLM-supplied attachment path has to refuse two specific attacks:

* **Path traversal** — ``/etc/passwd`` dressed up as an attachment would
  happily exfiltrate data to the recipient. We resolve the path (following
  symlinks, ``strict=True``) and check that the result is a descendant of a
  small allowlist rooted at the user's home.
* **Size amplification** — a 2 GB file would blow up the SMTP session. Per
  file and per message caps are enforced before we open the file for read.
"""

from __future__ import annotations

import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path

from .guards import sanitize_header
from .validation import ValidationError

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 50 * 1024 * 1024


def _allowed_roots() -> list[Path]:
    roots = [
        Path.home() / "Downloads",
        Path.home() / "Documents" / "mail-mcp-outbox",
    ]
    extra = os.environ.get("MAIL_MCP_ATTACHMENT_DIR")
    if extra:
        roots.append(Path(extra).expanduser())
    tmp = Path(os.environ.get("TMPDIR", "/tmp"))  # noqa: S108 — opt-in allowlist root, not a secret sink
    roots.append(tmp)
    return [r.expanduser() for r in roots]


@dataclass
class ResolvedAttachment:
    path: Path
    filename: str
    content_type: str
    size: int
    raw_passthrough: bool = False


def resolve(
    *,
    raw_path: str,
    filename_override: str | None,
    content_type_override: str | None,
    raw_passthrough: bool = False,
) -> ResolvedAttachment:
    if not raw_path:
        raise ValidationError("attachment path must not be empty")
    try:
        resolved = Path(raw_path).expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValidationError(f"attachment not found: {raw_path}") from exc
    if resolved.is_dir():
        raise ValidationError(f"attachment is a directory, not a file: {raw_path}")
    allowed = False
    for root in _allowed_roots():
        try:
            root_resolved = root.resolve(strict=False)
        except OSError:
            continue
        try:
            if resolved.is_relative_to(root_resolved):
                allowed = True
                break
        except ValueError:
            continue
    if not allowed:
        raise ValidationError(
            "attachment path is outside the allowed directories "
            "(~/Downloads, ~/Documents/mail-mcp-outbox, $TMPDIR, or $MAIL_MCP_ATTACHMENT_DIR)"
        )
    size = resolved.stat().st_size
    if size > MAX_ATTACHMENT_BYTES:
        raise ValidationError(
            f"attachment too large: {size} bytes (max {MAX_ATTACHMENT_BYTES})"
        )
    filename = sanitize_header(filename_override or resolved.name, max_length=255)
    if not filename or filename in {".", ".."}:
        raise ValidationError("attachment filename is invalid after sanitisation")
    if content_type_override:
        ctype = content_type_override
    else:
        guessed, _ = mimetypes.guess_type(filename)
        ctype = guessed or "application/octet-stream"
    return ResolvedAttachment(
        path=resolved,
        filename=filename,
        content_type=ctype,
        size=size,
        raw_passthrough=raw_passthrough,
    )


def resolve_many(specs) -> list[ResolvedAttachment]:
    """Validate and resolve all attachment specs, enforcing the total-size cap."""
    if not specs:
        return []
    resolved: list[ResolvedAttachment] = []
    total = 0
    for spec in specs:
        if isinstance(spec, dict):
            raw_path = spec.get("path")
            filename = spec.get("filename")
            ctype = spec.get("content_type")
            raw_pt = bool(spec.get("raw_passthrough", False))
        else:
            raw_path = getattr(spec, "path", None)
            filename = getattr(spec, "filename", None)
            ctype = getattr(spec, "content_type", None)
            raw_pt = bool(getattr(spec, "raw_passthrough", False))
        res = resolve(
            raw_path=raw_path,
            filename_override=filename,
            content_type_override=ctype,
            raw_passthrough=raw_pt,
        )
        total += res.size
        if total > MAX_TOTAL_ATTACHMENT_BYTES:
            raise ValidationError(
                f"attachments exceed total size limit ({total} > {MAX_TOTAL_ATTACHMENT_BYTES})"
            )
        resolved.append(res)
    return resolved
