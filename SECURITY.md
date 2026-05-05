# Security policy

`mail-mcp` is intended to be a small, auditable MCP server that AI assistants can use to reason about a user's mailbox without shipping credentials off-device and without giving the model free rein over destructive actions.

## Reporting a vulnerability

Please email **developer@supera.dev** with the subject prefix `[mail-mcp]`. Include:

- a description of the issue
- a reproducer or proof of concept
- the commit hash you tested against

Do not file public GitHub issues for security reports. Coordinated disclosure is appreciated; responses usually land within 72 hours.

## Keychain UX on macOS

The first time `mail-mcp` reads a password from your macOS Keychain you will see a standard Apple prompt along the lines of *"python wants to access the mail-mcp:&lt;alias&gt; entry in your keychain"*. Pick **Always Allow** once and future invocations from the same Python interpreter proceed silently. If you reinstall Python (brew, pyenv, a new venv) the interpreter's code signature changes and the prompt returns — this is expected behaviour for every tool that uses `keyring` on macOS.

Items are namespaced under `mail-mcp:<alias>` so they never collide with credentials created by Apple Mail, `git credential-osxkeychain`, or other tools.

## Autoconfig network traffic

`mail-mcp init` may, in this order, perform a handful of HTTPS requests and DNS lookups to auto-detect your provider:

1. HTTPS GET to `autoconfig.<your-domain>/mail/config-v1.1.xml` (if the provider publishes one).
2. HTTPS GET to `<your-domain>/.well-known/autoconfig/mail/config-v1.1.xml`.
3. HTTPS GET to `autoconfig.thunderbird.net/v1.1/<your-domain>` — the Mozilla ISPDB. **The domain alone is sent**, never the full email address.
4. DNS `MX` and `SRV` lookups via your system resolver.

HTTPS is non-negotiable — HTTP URLs are rejected. Every call is capped at three seconds. Skip networking entirely with the wizard's "autodetect failed — enter manually" fallback if you are on an isolated network.

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
- **Error sanitisation.** Exceptions are surfaced to the LLM as `{type, message}` with `XOAUTH2` / `AUTH PLAIN` / `AUTH LOGIN` blobs, IMAP `LOGIN "user" "pass"` traces, `password=…` / `secret=…` / `token=…` / `api-key=…` key-value pairs, and HTTP `Authorization: Bearer <token>` (plus the bare `Bearer <jwt>` form) redacted, alongside emails and hostnames.
- **XML hardening.** Provider autoconfig responses are parsed through [`defusedxml`](https://pypi.org/project/defusedxml/), defending against billion-laughs and external-entity (XXE) attacks regardless of what the response-size cap allows through.
- **OAuth refresh-token recovery.** When Microsoft returns `invalid_grant` (revoked refresh token, password rotation, conditional-access policy), the dead token is removed from the OS keyring and the in-memory access-token cache for that account is cleared, so the next call surfaces a clean "re-run `mail-mcp init`" instead of silently looping the same revoked token.
- **Forensic mode for attachments.** `AttachmentSpec.raw_passthrough=true` forces `application/octet-stream` + base64 CTE for an attachment, guaranteeing `SHA-256(received) == SHA-256(source-on-disk)` end-to-end. Useful for chain-of-custody preservation.
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
