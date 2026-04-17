"""Sample message specs for the `populated_inbox` fixture.

Each entry in :data:`SAMPLE_EMAILS` is a ``dict`` whose keys map 1:1 onto the
keyword arguments accepted by the :func:`deliver` helper defined in
``tests/integration/conftest.py``. The `deliver()` helper opens an SMTPS
session against GreenMail, builds an :class:`email.message.EmailMessage`, and
drops the result into the test account's INBOX — no IMAP APPEND tricks.

Scenarios covered
-----------------

The seed list is deliberately diverse so a single `populated_inbox` fixture can
feed read-path, write-path and threading tests without each test file re-rolling
its own delivery code:

1-3. **Stripe thread** (3 messages) — invoice from stripe → reply from the test
     account → Stripe follow-up. The messages share an explicit ``message_id``
     / ``in_reply_to`` / ``references`` chain so threading can be asserted
     deterministically; ``message_id`` values are under the sender's domain
     (``stripe.com`` / ``localhost``) to match how real MUAs mint IDs.

4.   **Newsletter** from ``news@promo.example`` with a promotional subject —
     lets tests exercise sender-based filtering and provides one HTML-containing
     message (the Stripe follow-up is plain-text).

5.   **Message with a 1 KB PDF attachment** — the payload is a minimal
     PDF-1.4-looking byte blob (``b"%PDF-1.4\\n" + b"\\x00" * 1000``). Enough
     for attachment listing / size / download tests; not a valid PDF, but
     GreenMail and ``email.message`` don't parse the bytes.

6.   **HTML-only marketing message** — covers the "text/html alternative
     present" code path in :func:`mail_mcp.imap_client._extract_parts`.

7.   **UTF-8 subject** ("Résumé — accént test") — non-ASCII subject line.

8.   **Emoji subject** ("🎉 Party time! 🎊") — non-BMP emoji surrogate
     handling.

9.   **Last-year dated message** — explicit ``Date`` header from one year ago
     so date-range search tests have something older than "today".

10.  **Meant-to-be-flagged / unread message** — carries no flag delivery
     hints. **See note on flags below.**

Flag / seen state limitations
-----------------------------

GreenMail (and SMTP in general) gives no way for the *sender* to pre-set IMAP
flags on a delivered message. The server decides; typically newly-delivered
messages land with ``\\Recent`` and no ``\\Seen``. Tests that need
``\\Flagged`` or a guaranteed-``\\Seen``-off state must set them themselves
after delivery, e.g. via ``imap_client.set_flags(...)`` or
``client.add_flags([uid], [b"\\Flagged"])``. Entry #10 in the list is the
"pick this one to flag" candidate — its subject is distinctive enough to find
with SEARCH once the inbox is populated.
"""

from __future__ import annotations

import time
from email.utils import formatdate, make_msgid

# --- Stripe thread (3 messages, explicit thread IDs) -------------------------

_STRIPE_ROOT_MID = make_msgid(domain="stripe.com")
_STRIPE_REPLY_MID = make_msgid(domain="localhost")
_STRIPE_FOLLOWUP_MID = make_msgid(domain="stripe.com")

# --- Last-year date (pre-computed once at import time) -----------------------

# Subtract ~365 days' worth of seconds from "now" and format as RFC 5322.
# This lands us safely in the prior calendar year regardless of when the test
# runs, so SEARCH SINCE/BEFORE tests can rely on "at least one old message".
_ONE_YEAR_AGO = formatdate(timeval=time.time() - 365 * 24 * 3600, usegmt=True)

# --- The seed list -----------------------------------------------------------

SAMPLE_EMAILS: list[dict] = [
    # 1. Stripe invoice (thread root)
    {
        "from_": "billing@stripe.com",
        "subject": "Your Stripe invoice #INV-2026-001 is ready",
        "body": (
            "Hi,\n\n"
            "Your invoice for April is now available. Total due: $42.00.\n\n"
            "Thanks,\nStripe Billing"
        ),
        "message_id": _STRIPE_ROOT_MID,
    },
    # 2. User reply to invoice (same thread)
    {
        "from_": "other@localhost.local",  # simulating the user's own address
        "subject": "Re: Your Stripe invoice #INV-2026-001 is ready",
        "body": "Got it, thanks — paying today.\n",
        "message_id": _STRIPE_REPLY_MID,
        "in_reply_to": _STRIPE_ROOT_MID,
        "references": [_STRIPE_ROOT_MID],
    },
    # 3. Stripe follow-up (same thread, confirms payment)
    {
        "from_": "billing@stripe.com",
        "subject": "Re: Your Stripe invoice #INV-2026-001 is ready",
        "body": "Payment received. Thank you!\n",
        "message_id": _STRIPE_FOLLOWUP_MID,
        "in_reply_to": _STRIPE_REPLY_MID,
        "references": [_STRIPE_ROOT_MID, _STRIPE_REPLY_MID],
    },
    # 4. Newsletter
    {
        "from_": "news@promo.example",
        "subject": "Weekly deals inside — 30% off everything",
        "body": (
            "This week only: every product, 30% off. Unsubscribe at the "
            "bottom of this email.\n"
        ),
    },
    # 5. Message with a 1 KB PDF attachment
    {
        "from_": "reports@company.example",
        "subject": "Monthly report attached",
        "body": "Please find this month's report attached.\n",
        "attachment": ("report.pdf", b"%PDF-1.4\n" + b"\x00" * 1000),
    },
    # 6. HTML-only marketing message
    {
        "from_": "marketing@brand.example",
        "subject": "New feature announcement",
        "body": "New feature announcement — see HTML part for the full post.\n",
        "html": (
            "<html><body>"
            "<h1>Big news!</h1>"
            "<p>We just shipped something <b>amazing</b>.</p>"
            "</body></html>"
        ),
    },
    # 7. UTF-8 accented subject
    {
        "from_": "friend@example.com",
        "subject": "Résumé — accént test with ñ and ü",
        "body": "Testing UTF-8 subject decoding. ¡Hola!\n",
    },
    # 8. Emoji subject (non-BMP code points)
    {
        "from_": "party@example.com",
        "subject": "🎉 Party time! 🎊 Don't miss it 🥳",
        "body": "Bring snacks.\n",
    },
    # 9. Old message (Date header from ~1 year ago)
    {
        "from_": "archive@example.com",
        "subject": "Old archive message from last year",
        "body": "This should land in the inbox but look old in SEARCH SINCE/BEFORE.\n",
        # deliver() will forward `date` into the EmailMessage's Date header
        "date": _ONE_YEAR_AGO,
    },
    # 10. "To-be-flagged-by-the-test" placeholder — distinctive subject
    #     so tests can locate it after delivery and call set_flags() /
    #     remove \Seen themselves. GreenMail won't honour any flag hint
    #     passed in at SMTP time.
    {
        "from_": "support@example.com",
        "subject": "IMPORTANT please star this message",
        "body": "Tests should find this by subject and set \\Flagged / clear \\Seen on it.\n",
    },
]
