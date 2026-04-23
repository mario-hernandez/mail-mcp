"""Email send tool — gated behind multiple explicit signals.

Sending email from an LLM-driven tool call is the single highest-risk action
this server can perform: an attacker who lands a prompt injection inside an
incoming email could otherwise exfiltrate private mail to a destination of
their choice in a single turn. Four gates defend against that:

1. ``MAIL_MCP_WRITE_ENABLED=true`` must be set for write tools to be
   registered at all (checked in ``server.py``).
2. ``MAIL_MCP_SEND_ENABLED=true`` must additionally be set for ``send_email``
   to appear. Users who only need draft creation never expose this surface.
3. The tool itself requires the caller to pass ``confirm=true``.
4. A per-account hourly rate limit caps the blast radius of a successful
   prompt injection (default 10/h, overridden by
   ``MAIL_MCP_SEND_HOURLY_LIMIT``). The bucket is process-local; restarting
   the MCP server resets it.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque

from .. import smtp_client
from ..config import Config
from ..credentials import resolve_auth
from .schemas import SendEmailInput


class SendDisabled(RuntimeError):
    """Raised when send is invoked without the full gating chain engaged."""


class RateLimited(RuntimeError):
    """Raised when the per-account hourly send ceiling has been hit."""


_WINDOW_SECONDS = 3600.0
_DEFAULT_LIMIT = 10
_send_history: dict[str, deque[float]] = defaultdict(deque)


def is_enabled() -> bool:
    """True when both the write and send environment gates are engaged."""
    return (
        os.environ.get("MAIL_MCP_WRITE_ENABLED", "false").lower() == "true"
        and os.environ.get("MAIL_MCP_SEND_ENABLED", "false").lower() == "true"
    )


def _hourly_limit() -> int:
    raw = os.environ.get("MAIL_MCP_SEND_HOURLY_LIMIT", str(_DEFAULT_LIMIT))
    try:
        limit = int(raw)
    except ValueError:
        return _DEFAULT_LIMIT
    return max(1, limit)


def _check_rate_limit(alias: str) -> None:
    limit = _hourly_limit()
    bucket = _send_history[alias]
    now = time.monotonic()
    cutoff = now - _WINDOW_SECONDS
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= limit:
        raise RateLimited(
            f"send_email rate limit reached ({limit}/hour for '{alias}'). "
            "Raise MAIL_MCP_SEND_HOURLY_LIMIT or wait for the oldest entry to expire."
        )
    bucket.append(now)


def _reset_for_tests() -> None:
    _send_history.clear()


def send_email(cfg: Config, params: SendEmailInput) -> dict:
    if not is_enabled():
        raise SendDisabled(
            "send_email is disabled. Set MAIL_MCP_WRITE_ENABLED=true and "
            "MAIL_MCP_SEND_ENABLED=true in the server environment to enable it."
        )
    if not params.confirm:
        raise SendDisabled("send_email requires the caller to pass confirm=true.")
    acct = cfg.account(params.account)
    _check_rate_limit(acct.alias)
    creds = resolve_auth(acct)
    msg, bcc = smtp_client.build_message_with_bcc(
        from_addr=acct.email,
        to=params.to,
        cc=params.cc,
        bcc=params.bcc,
        subject=params.subject,
        body_text=params.body,
        in_reply_to=params.in_reply_to,
        references=params.references,
    )
    message_id = smtp_client.send(acct, creds, msg, bcc=bcc)
    return {
        "account": acct.alias,
        "message_id": message_id,
        "recipients": {
            "to": params.to,
            "cc": params.cc or [],
            "bcc": params.bcc or [],
        },
    }
