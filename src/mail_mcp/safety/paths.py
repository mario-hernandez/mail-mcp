"""Filesystem allowlist for attachment saves.

Every write to local disk is anchored under a single base directory and
resolved symlink-safely so an LLM tool call can never escape via ``..`` or
by referencing a symbolic link that points outside the sandbox.
"""

from __future__ import annotations

import os
from pathlib import Path

from .validation import ValidationError


def default_download_root() -> Path:
    """Resolve the default attachment-save root (``~/Downloads/mail-mcp``)."""
    return Path(os.path.expanduser("~/Downloads/mail-mcp")).resolve()


def safe_join(base: Path, *parts: str) -> Path:
    """Join ``parts`` under ``base`` and verify containment after resolution.

    Rejects ``..`` segments, absolute parts, or any path that escapes ``base``
    once symlinks are resolved.
    """
    base = base.resolve()
    for part in parts:
        if not part:
            raise ValidationError("empty path segment")
        if os.path.isabs(part):
            raise ValidationError(f"absolute path segment not allowed: {part!r}")
        if ".." in Path(part).parts:
            raise ValidationError(f"'..' path traversal not allowed: {part!r}")
    candidate = base.joinpath(*parts).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValidationError("resolved path escapes download root") from exc
    return candidate


def prepare_download_path(base: Path, account: str, filename: str) -> Path:
    """Prepare a safe download destination and ensure parent dirs exist.

    Filenames are reduced to their basename to neutralise any directory
    component supplied by the caller or recovered from an email's MIME part.
    """
    sanitized = Path(filename).name
    if not sanitized or sanitized in {".", ".."}:
        raise ValidationError(f"invalid attachment filename: {filename!r}")
    target = safe_join(base, account, sanitized)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return target
