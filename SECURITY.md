# Security policy

`mail-mcp` is intended to be a small, auditable MCP server that AI assistants can use to reason about a user's mailbox without shipping credentials off-device and without giving the model free rein over destructive actions.

## Reporting a vulnerability

Please email **m@mariohernandez.es** with the subject prefix `[mail-mcp]`. Include:

- a description of the issue
- a reproducer or proof of concept
- the commit hash you tested against

Do not file public GitHub issues for security reports. Coordinated disclosure is appreciated; responses usually land within 72 hours.

## Controls

- **Credentials stay in the OS keyring.** macOS Keychain, Linux Secret Service, Windows Credential Manager via [`keyring`](https://pypi.org/project/keyring/). The config file stores only host/port/user/alias.
- **TLS is mandatory.** IMAP uses implicit TLS (port 993 by default); SMTP uses STARTTLS (587) or implicit TLS (465). Certificate verification cannot be silently disabled.
- **IMAP searches use structured criteria.** User input never gets concatenated into a SEARCH string — the `imapclient` criteria list is typed and escaped.
- **Email headers are built with `email.message.EmailMessage`.** Subject/To/From/Cc are additionally validated against `\r\n` and control characters before construction, so an LLM cannot inject a `Bcc:` header by stuffing `\r\n` into a user-visible field.
- **Destructive tools are gated.**
  - `save_draft` is the preferred write path — the human reviews the draft in their mail client before sending.
  - All mutating tools require `MAIL_MCP_WRITE_ENABLED=true`; when unset the tools are *not registered*, so the LLM cannot even enumerate them.
  - `send_email` additionally requires `MAIL_MCP_SEND_ENABLED=true` plus `confirm=true` in the arguments.
  - `delete_emails` defaults to moving to Trash; `permanent=true` requires `MAIL_MCP_ALLOW_PERMANENT_DELETE=true` and `confirm=true`.
- **Prompt-injection guard.** Email bodies surfaced to the LLM are wrapped in a `<untrusted_email_content>` envelope with an explicit warning. Closing-tag breakouts and zero-width characters are neutralised before wrapping.
- **Bounded outputs.** Body chars ≤ 64k (default 16k), attachments ≤ 25 MiB, batch UIDs ≤ 100, search results ≤ 500.
- **Filesystem allowlist.** Attachment downloads are anchored under `~/Downloads/mail-mcp/<account>/` and resolved symlink-safely; `..` and absolute paths are rejected.
- **Error sanitisation.** Exceptions are surfaced to the LLM as `{type, message}` with substrings around `LOGIN`/`PASS`/`XOAUTH2` redacted.
- **Zero outbound network beyond your IMAP/SMTP servers.** No telemetry, no update checks, no relays, no third-party APIs.

## Threat model (summary)

In scope:

- Cross-prompt injection attacks carried inside email bodies/subjects.
- Credential theft from disk, logs, or process listings.
- Man-in-the-middle attacks on IMAP/SMTP transport.
- CRLF / header injection originating from LLM tool arguments.
- Path traversal attempts on attachment saves.
- Exfiltration via `forward`/`send` to attacker-controlled destinations.

Out of scope:

- A compromised operating system or user account.
- Bugs in the LLM client that ignores the untrusted-content envelope — we mitigate but cannot eliminate.
- Denial-of-service attacks against the remote IMAP/SMTP provider.
