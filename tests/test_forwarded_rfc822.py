"""Forward-as-attachment (``message/rfc822``) handling.

Outlook / Exchange's "Forward as attachment" wraps the original message as a
``message/rfc822`` MIME part. Before v0.3.3 the body extractor stopped at the
cover note and the rfc822 part was neither captured as text nor exposed as an
attachment, so downstream callers saw ``body=""`` and ``attachments=[]``. These
tests pin the recovered behaviour: the inner body is appended to the outer
body with a divider, the rfc822 is exposed as a virtual attachment, and
``download_attachment`` serialises it back to ``.eml`` bytes.
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage

from mail_mcp.imap_client import _extract_parts, _iter_attachments


def _build_forward_as_attachment(
    *,
    cover: str = "FYI, see attached.",
    inner_subject: str = "Original subject — q1 numbers",
    inner_body: str = "This is the ORIGINAL message body that should be readable.",
) -> EmailMessage:
    inner = EmailMessage(policy=email.policy.default)
    inner["From"] = "alice@example.com"
    inner["To"] = "bob@example.com"
    inner["Subject"] = inner_subject
    inner["Date"] = "Wed, 01 Apr 2026 10:00:00 +0200"
    inner.set_content(inner_body)

    outer = EmailMessage(policy=email.policy.default)
    outer["From"] = "carol@example.com"
    outer["To"] = "dave@example.com"
    outer["Subject"] = "Fwd: q1 numbers"
    outer.set_content(cover)
    outer.add_attachment(inner, filename="original.eml")
    return email.message_from_bytes(outer.as_bytes(), policy=email.policy.default)  # type: ignore[return-value]


def test_extract_parts_includes_inner_forwarded_body():
    msg = _build_forward_as_attachment()
    text, _html, _att = _extract_parts(msg)
    assert "FYI, see attached." in text
    assert "--- Forwarded message ---" in text
    assert "From: alice@example.com" in text
    assert "Subject: Original subject — q1 numbers" in text
    assert "This is the ORIGINAL message body that should be readable." in text


def test_extract_parts_exposes_rfc822_as_virtual_attachment():
    """The forwarded part is surfaced with the explicit filename when set."""
    msg = _build_forward_as_attachment()
    _text, _html, attachments = _extract_parts(msg)
    assert len(attachments) == 1
    att = attachments[0]
    assert att.content_type == "message/rfc822"
    # The fixture pins ``filename="original.eml"`` on the rfc822 part —
    # prefer that over deriving from the inner Subject.
    assert att.filename == "original.eml"
    assert att.size > 0
    assert att.index == 0


def test_extract_parts_falls_back_to_inner_subject_when_no_filename():
    """If the rfc822 part has no filename header, derive one from the Subject."""
    inner = EmailMessage(policy=email.policy.default)
    inner["From"] = "x@e.com"
    inner["To"] = "y@e.com"
    inner["Subject"] = "Untagged forward subject"
    inner.set_content("body")

    outer = EmailMessage(policy=email.policy.default)
    outer["From"] = "a@e.com"
    outer["To"] = "b@e.com"
    outer["Subject"] = "Fwd"
    outer.set_content("see below")
    # Attach without an explicit filename — the rfc822 part will have no
    # ``Content-Disposition: attachment; filename=...`` header.
    outer.add_attachment(inner)
    parsed = email.message_from_bytes(outer.as_bytes(), policy=email.policy.default)

    _text, _html, atts = _extract_parts(parsed)
    assert len(atts) == 1
    assert atts[0].filename.endswith(".eml")
    assert "Untagged forward subject" in atts[0].filename


def test_extract_parts_handles_empty_cover_note():
    """A forward with no human-readable cover should still surface the inner text."""
    msg = _build_forward_as_attachment(cover="")
    text, _html, _att = _extract_parts(msg)
    assert "This is the ORIGINAL message body that should be readable." in text


def test_iter_attachments_yields_rfc822_part():
    msg = _build_forward_as_attachment()
    parts = list(_iter_attachments(msg))
    assert len(parts) == 1
    assert parts[0].get_content_type() == "message/rfc822"


def test_extract_parts_does_not_promote_inner_attachments_to_outer():
    """Attachments inside the forwarded message stay scoped to the .eml."""
    inner = EmailMessage(policy=email.policy.default)
    inner["From"] = "a@e.com"
    inner["To"] = "b@e.com"
    inner["Subject"] = "with attached pdf"
    inner.set_content("body")
    inner.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="invoice.pdf")

    outer = EmailMessage(policy=email.policy.default)
    outer["From"] = "c@e.com"
    outer["To"] = "d@e.com"
    outer["Subject"] = "Fwd"
    outer.set_content("see attached")
    outer.add_attachment(inner, filename="forwarded.eml")
    parsed = email.message_from_bytes(outer.as_bytes(), policy=email.policy.default)

    _text, _html, attachments = _extract_parts(parsed)
    # Only the rfc822 wrapper appears; invoice.pdf belongs to the inner .eml.
    assert len(attachments) == 1
    assert attachments[0].content_type == "message/rfc822"


def test_extract_parts_normal_email_unchanged():
    """A plain message with one PDF attachment behaves exactly as before."""
    msg = EmailMessage(policy=email.policy.default)
    msg["From"] = "x@e.com"
    msg["To"] = "y@e.com"
    msg["Subject"] = "invoice"
    msg.set_content("Please see the invoice.")
    msg.add_attachment(b"%PDF-1.4 ...", maintype="application", subtype="pdf", filename="invoice.pdf")
    parsed = email.message_from_bytes(msg.as_bytes(), policy=email.policy.default)

    text, _html, attachments = _extract_parts(parsed)
    assert "Please see the invoice." in text
    assert "Forwarded message" not in text
    assert len(attachments) == 1
    assert attachments[0].content_type == "application/pdf"
    assert attachments[0].filename == "invoice.pdf"


def test_download_attachment_serialises_rfc822_part():
    """``imap_client.download_attachment`` must return valid .eml bytes for rfc822."""
    from unittest.mock import MagicMock

    msg = _build_forward_as_attachment()
    raw = msg.as_bytes()

    fake_client = MagicMock()
    fake_client.fetch.return_value = {123: {b"RFC822": raw}}

    from mail_mcp import imap_client

    filename, ctype, payload = imap_client.download_attachment(
        fake_client, mailbox="INBOX", uid=123, index=0,
    )
    assert ctype == "message/rfc822"
    assert filename.endswith(".eml")
    # Payload must be a parseable RFC822 message.
    parsed = email.message_from_bytes(payload, policy=email.policy.default)
    assert parsed["Subject"] == "Original subject — q1 numbers"
    assert "This is the ORIGINAL message body" in parsed.get_content()
