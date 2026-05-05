"""``.eml`` (``message/rfc822``) attachments must round-trip with their bytes.

Bug #1: ``save_draft(attachments=[{path: x.eml, filename: 'evidence.eml'}])``
used to shrink a multi-hundred-KiB ``.eml`` to a 44-byte placeholder and
overwrite the user-supplied filename with ``forwarded-message.eml``. Root
cause: ``EmailMessage.add_attachment(bytes, maintype="message",
subtype="rfc822", ...)`` is not supported by Python's email module — the
body is dropped on serialise/parse round-trip. The fix pre-parses the
bytes into an :class:`EmailMessage` and attaches the object via
``add_attachment(message_obj, filename=...)``.
"""

from __future__ import annotations

import email
import email.policy
import tempfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from mail_mcp import imap_client, smtp_client
from mail_mcp.safety.attachments import ResolvedAttachment


def _make_eml_on_disk(*, body_repeat: int = 10) -> tuple[Path, int]:
    inner = EmailMessage(policy=email.policy.default)
    inner["From"] = "victim@example.com"
    inner["To"] = "phisher@example.com"
    inner["Subject"] = "Original phishing message"
    inner["Date"] = "Tue, 5 May 2026 10:00:00 +0200"
    inner.set_content(("preserved evidence body. " * body_repeat).strip())
    fh = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    fh.write(inner.as_bytes())
    fh.close()
    p = Path(fh.name)
    return p, p.stat().st_size


def test_save_draft_eml_attachment_preserves_bytes_and_filename():
    """Pin the regression: bytes survive end-to-end, filename is honoured."""
    src_path, src_size = _make_eml_on_disk(body_repeat=200)
    try:
        assert src_size > 1_000  # plenty of body to lose if the bug came back
        resolved = ResolvedAttachment(
            path=src_path,
            filename="evidence.eml",
            content_type="message/rfc822",
            size=src_size,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["someone@example.com"],
            subject="Evidence",
            body_text="See attached.",
            attachments=[resolved],
        )
        # Round-trip through the wire to mimic what an IMAP server returns.
        parsed = email.message_from_bytes(bytes(draft), policy=email.policy.default)
        _text, _html, atts = imap_client._extract_parts(parsed)
        assert len(atts) == 1
        a = atts[0]
        assert a.filename == "evidence.eml"
        assert a.content_type == "message/rfc822"
        # Bytes survived: size is at least the body we put in.
        assert a.size > 1_000, f"attachment shrunk to {a.size} bytes — bug returned"
    finally:
        src_path.unlink(missing_ok=True)


def test_download_attachment_returns_original_filename_and_bytes():
    """``download_attachment`` for a message/rfc822 part keeps the user's filename."""
    from unittest.mock import MagicMock

    src_path, _ = _make_eml_on_disk()
    try:
        resolved = ResolvedAttachment(
            path=src_path,
            filename="my-evidence.eml",
            content_type="message/rfc822",
            size=src_path.stat().st_size,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["someone@example.com"],
            subject="Evidence",
            body_text="See attached.",
            attachments=[resolved],
        )
        wire = bytes(draft)

        fake_client = MagicMock()
        fake_client.fetch.return_value = {7: {b"RFC822": wire}}
        filename, ctype, payload = imap_client.download_attachment(
            fake_client, mailbox="Drafts", uid=7, index=0,
        )
        assert filename == "my-evidence.eml"
        assert ctype == "message/rfc822"
        # Re-parsing the downloaded bytes must yield a real RFC822 message.
        re_parsed = email.message_from_bytes(payload, policy=email.policy.default)
        assert re_parsed["From"] == "victim@example.com"
        assert re_parsed["Subject"] == "Original phishing message"
    finally:
        src_path.unlink(missing_ok=True)


def test_attach_files_falls_back_to_octet_stream_for_malformed_eml():
    """Garbage labelled as message/rfc822 still survives end-to-end."""
    fh = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    fh.write(b"not a real RFC822 message at all, just garbage" * 5)
    fh.close()
    try:
        size = Path(fh.name).stat().st_size
        resolved = ResolvedAttachment(
            path=Path(fh.name),
            filename="garbage.eml",
            content_type="message/rfc822",
            size=size,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["someone@example.com"],
            subject="garbage",
            body_text="see attached",
            attachments=[resolved],
        )
        # Body survives — that's the correctness invariant.
        parsed = email.message_from_bytes(bytes(draft), policy=email.policy.default)
        for part in parsed.walk():
            if part.get_content_disposition() == "attachment":
                payload = part.get_payload(decode=True) or b""
                assert b"garbage" in payload
                return
        pytest.fail("attachment part not found")
    finally:
        Path(fh.name).unlink(missing_ok=True)
