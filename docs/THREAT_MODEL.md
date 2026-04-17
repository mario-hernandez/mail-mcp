# Threat model

A short walk-through of how `mail-mcp` is meant to hold up against specific adversaries. This is a living document; PRs are welcome.

## Trust boundaries

```
+--------------------+         +------------------+         +----------------+
|     LLM client     |  stdio  |     mail-mcp     |  TLS    |  IMAP / SMTP   |
| (Claude / Codex)   | <-----> |  (this process)  | <-----> |    provider    |
+--------------------+         +------------------+         +----------------+
                                         |
                                   Keychain / Secret
                                   Service / Credential
                                   Manager
```

* Everything outside the `mail-mcp` box is untrusted input: the LLM may be prompt-injected, email bodies are attacker-controlled, network paths can be MITMed.
* Inside the box, code is small enough to audit end-to-end.

## Adversaries and mitigations

### 1. An attacker who sends you email

Goal: smuggle instructions to the model so it forwards mail, leaks contacts, or deletes things.

Mitigations:

- Email bodies are wrapped in `<untrusted_email_content>` with a warning prefix (`src/mail_mcp/safety/guards.py`). The closing tag is escaped if it appears in the body so the attacker cannot break out.
- Zero-width characters (U+200B, U+200C, U+FEFF, etc.) are stripped before wrapping.
- `forward` is not implemented in v0.1. Forwarding through `save_draft` goes to the user's Drafts folder, which the human reviews manually before sending.
- `send_email` requires an environment flag *plus* `confirm=true` *plus* the LLM picking a recipient the user did not attack with.

### 2. A prompt-injected LLM

Goal: exfiltrate mail by writing a draft to the attacker, or delete emails to cover tracks.

Mitigations:

- Mutating tools are registered only when `MAIL_MCP_WRITE_ENABLED=true`. If you never set it, the model *cannot see* the write tools and cannot call them.
- `send_email` requires a second env flag (`MAIL_MCP_SEND_ENABLED=true`), which is not needed for the common draft/review workflow.
- `delete_emails` defaults to Trash; permanent delete requires a third env flag and explicit `confirm=true`.
- Structured IMAP SEARCH (no string concat) prevents the LLM from crafting queries that bypass filters.

### 3. A passive network attacker

Goal: learn the user's password or read email in transit.

Mitigations:

- TLS is non-optional. The code path that would allow `ssl=False` for IMAP raises a `ValidationError` during `connect()`.
- STARTTLS is forced for SMTP 587. Plain SMTP is refused.
- Certificate verification uses `ssl.create_default_context()` and is never overridden.

### 4. Malware running as your user

Goal: read credentials from disk or steal them from memory.

Mitigations (partial — a compromised user account is near-impossible to defend against):

- Credentials live only in the OS keyring, never in project-managed files. `~/.config/mail-mcp/config.json` stores only host/port/alias/email and is written with mode `0o600`.
- Passwords are fetched just-in-time for an operation and not cached in any long-lived structure.
- Attachment downloads go to `~/Downloads/mail-mcp/<account>/` with file mode `0o600`.

### 5. An LLM tool call with malicious paths/UIDs

Goal: path traversal out of the download dir, batch-delete the whole mailbox.

Mitigations:

- `safe_join` anchors every write to the download root and rejects `..` and absolute paths.
- Batch operations are capped at 100 UIDs per call; destructive batch deletion requires explicit confirmation.

### 6. A supply-chain attack on dependencies

Goal: ship a malicious version of `imapclient`, `keyring`, or an indirect dep.

Mitigations:

- Minimal dep tree (four direct dependencies). The build is reproducible via `uv.lock` / `requirements.lock`.
- No `postinstall`/`preinstall` hooks.
- Dependabot is recommended (add via `.github/dependabot.yml`) if you fork.

## Known limits

- This server does **not** implement OAuth2. Providers that require it (Gmail, Outlook) need an app password or will not work until a future version adds OAuth.
- The untrusted-content wrapper is a *mitigation*, not a guarantee. A sufficiently capable model, or one not trained to respect the envelope, may still be influenced by the content.
- `imapclient` logs its own wire traffic at DEBUG. We set the module logger to WARNING by default; do not raise it on production systems.
