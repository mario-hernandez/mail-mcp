"""``raw_passthrough`` — byte-identity preservation for forensic use cases.

When SHA-256 byte-equality matters (chain-of-custody, eIDAS sealing,
notarised evidence preservation), the receiver of an attachment must be
able to verify that the bytes match the source on disk. The default
attach path canonicalises ``message/rfc822`` (CRLF normalisation,
header re-folding) so the SHA-256 changes by a few hundred bytes,
which is fine for sharing evidence with CERTs that compare headers but
not for forensic chains of custody.

``AttachmentSpec.raw_passthrough=True`` forces ``application/octet-stream``
with base64 CTE regardless of file type, guaranteeing byte-identity
end-to-end through the MCP.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import tempfile
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock

from mail_mcp import imap_client, smtp_client
from mail_mcp.safety.attachments import ResolvedAttachment


def _make_eml_on_disk(*, body_repeat: int = 50) -> tuple[Path, bytes, str]:
    inner = EmailMessage(policy=email.policy.default)
    inner["From"] = "victim@example.com"
    inner["To"] = "phisher@example.com"
    inner["Subject"] = "phishing evidence"
    inner["Date"] = "Tue, 5 May 2026 10:00:00 +0200"
    inner.set_content(("evidence body line. " * body_repeat).strip())
    fh = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    fh.write(inner.as_bytes())
    fh.close()
    p = Path(fh.name)
    src = p.read_bytes()
    return p, src, hashlib.sha256(src).hexdigest()


def test_raw_passthrough_preserves_sha256_end_to_end():
    """The headline guarantee: SHA-256(downloaded) == SHA-256(source-on-disk)."""
    path, src_bytes, src_sha = _make_eml_on_disk()
    try:
        resolved = ResolvedAttachment(
            path=path,
            filename="evidence.eml",
            content_type="message/rfc822",  # would canonicalise without the flag
            size=len(src_bytes),
            raw_passthrough=True,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["cert@example.com"],
            subject="Evidence",
            body_text="See attached. Hash on file.",
            attachments=[resolved],
        )
        wire = bytes(draft)

        fake_client = MagicMock()
        fake_client.fetch.return_value = {1: {b"RFC822": wire}}
        filename, ctype, payload = imap_client.download_attachment(
            fake_client, mailbox="Drafts", uid=1, index=0,
        )
        # Filename round-trips. Content-type is forced to octet-stream because
        # the byte-identity guarantee is only honest with an opaque type.
        assert filename == "evidence.eml"
        assert ctype == "application/octet-stream"
        assert payload == src_bytes
        assert hashlib.sha256(payload).hexdigest() == src_sha
    finally:
        path.unlink(missing_ok=True)


def test_raw_passthrough_forces_octet_stream_even_with_explicit_message_rfc822():
    """If the user passes raw_passthrough=True, content_type override is overridden."""
    path, src_bytes, src_sha = _make_eml_on_disk(body_repeat=10)
    try:
        # Caller asks for message/rfc822 AND raw_passthrough — we honour the
        # byte-identity guarantee by ignoring the content_type override.
        resolved = ResolvedAttachment(
            path=path,
            filename="x.eml",
            content_type="message/rfc822",
            size=len(src_bytes),
            raw_passthrough=True,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["cert@example.com"],
            subject="x",
            body_text="b",
            attachments=[resolved],
        )
        parsed = email.message_from_bytes(bytes(draft), policy=email.policy.default)
        for part in parsed.walk():
            if part.get_content_disposition() == "attachment":
                # On the wire, ctype is forced to octet-stream.
                assert part.get_content_type() == "application/octet-stream"
                assert (part.get("Content-Transfer-Encoding") or "").lower() == "base64"
                return
        raise AssertionError("attachment part not found in draft")
    finally:
        path.unlink(missing_ok=True)


def test_raw_passthrough_default_false_keeps_existing_behaviour():
    """Regression guard: default off means .eml still arrives as message/rfc822."""
    path, src_bytes, _ = _make_eml_on_disk(body_repeat=5)
    try:
        resolved = ResolvedAttachment(
            path=path,
            filename="evidence.eml",
            content_type="message/rfc822",
            size=len(src_bytes),
            # raw_passthrough not set — default False
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["someone@example.com"],
            subject="x",
            body_text="b",
            attachments=[resolved],
        )
        parsed = email.message_from_bytes(bytes(draft), policy=email.policy.default)
        for part in parsed.walk():
            if part.get_content_disposition() == "attachment":
                # Without the flag, .eml still arrives as message/rfc822.
                assert part.get_content_type() == "message/rfc822"
                return
        raise AssertionError("attachment part not found in draft")
    finally:
        path.unlink(missing_ok=True)


def test_raw_passthrough_preserves_arbitrary_binary_byte_identity():
    """Same guarantee for non-eml binary content — random bytes survive intact."""
    import os
    blob = os.urandom(8192)
    src_sha = hashlib.sha256(blob).hexdigest()
    fh = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    fh.write(blob)
    fh.close()
    path = Path(fh.name)
    try:
        resolved = ResolvedAttachment(
            path=path,
            filename="evidence.bin",
            content_type="application/octet-stream",
            size=len(blob),
            raw_passthrough=True,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["someone@example.com"],
            subject="x",
            body_text="b",
            attachments=[resolved],
        )
        fake_client = MagicMock()
        fake_client.fetch.return_value = {1: {b"RFC822": bytes(draft)}}
        _filename, _ctype, payload = imap_client.download_attachment(
            fake_client, mailbox="Drafts", uid=1, index=0,
        )
        assert hashlib.sha256(payload).hexdigest() == src_sha
    finally:
        path.unlink(missing_ok=True)


def test_resolve_many_propagates_raw_passthrough_from_dict_spec():
    """The flag must reach ResolvedAttachment from both dict and pydantic specs."""
    from mail_mcp.safety.attachments import resolve_many

    fh = tempfile.NamedTemporaryFile(
        suffix=".bin",
        dir=Path.home() / "Downloads",
        delete=False,
    )
    fh.write(b"x" * 100)
    fh.close()
    path = Path(fh.name)
    try:
        # Dict path (LLM-style payload)
        out_dict = resolve_many([
            {"path": str(path), "raw_passthrough": True},
        ])
        assert out_dict[0].raw_passthrough is True

        # Default off
        out_default = resolve_many([{"path": str(path)}])
        assert out_default[0].raw_passthrough is False
    finally:
        path.unlink(missing_ok=True)
