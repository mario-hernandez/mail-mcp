"""Email send tool — gated behind multiple explicit signals.

Sending email from an LLM-driven tool call is the single highest-risk action
this server can perform: an attacker who lands a prompt injection inside an
incoming email could otherwise exfiltrate private mail to a destination of
their choice in a single turn. Three gates defend against that:

1. ``MAIL_MCP_WRITE_ENABLED=true`` must be set for write tools to be
   registered at all (checked in ``server.py``).
2. ``MAIL_MCP_SEND_ENABLED=true`` must additionally be set for ``send_email``
   to appear. Users who only need draft creation never expose this surface.
3. The tool itself requires the caller to pass ``confirm=true`` in the
   arguments, documented prominently in the schema.
"""

from __future__ import annotations

import os

from .. import smtp_client
from ..config import Config
from ..keyring_store import get_password
from .schemas import SendEmailInput


class SendDisabled(RuntimeError):
    """Raised when send is invoked without the full gating chain engaged."""


def is_enabled() -> bool:
    """True when both the write and send environment gates are engaged."""
    return (
        os.environ.get("MAIL_MCP_WRITE_ENABLED", "false").lower() == "true"
        and os.environ.get("MAIL_MCP_SEND_ENABLED", "false").lower() == "true"
    )


def send_email(cfg: Config, params: SendEmailInput) -> dict:
    if not is_enabled():
        raise SendDisabled(
            "send_email is disabled. Set MAIL_MCP_WRITE_ENABLED=true and "
            "MAIL_MCP_SEND_ENABLED=true in the server environment to enable it."
        )
    if not params.confirm:
        raise SendDisabled("send_email requires the caller to pass confirm=true.")
    acct = cfg.account(params.account)
    password = get_password(acct.alias, acct.email)
    msg = smtp_client.build_message(
        from_addr=acct.email,
        to=params.to,
        cc=params.cc,
        bcc=params.bcc,
        subject=params.subject,
        body_text=params.body,
        in_reply_to=params.in_reply_to,
        references=params.references,
    )
    message_id = smtp_client.send(acct, password, msg)
    return {
        "account": acct.alias,
        "message_id": message_id,
        "recipients": {
            "to": params.to,
            "cc": params.cc or [],
            "bcc": params.bcc or [],
        },
    }
