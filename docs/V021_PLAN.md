# v0.2.1 — plan synthesised from the 9-agent improvement review

## Critical analysis — the 9 angles in one table

| Angle | Top finding | Verdict |
|---|---|---|
| Security | IMAP `timeout=None` hangs forever, XPIA wrap misses subjects/filenames, `sanitize_error` leaks emails+hostnames AND over-scrubs `AUTHENTICATIONFAILED`, no rate-limit on `send_email` | **Critical — fix now** |
| Tool surface | `list_attachments` redundant, `reply_draft`+`forward_draft` missing, `search.count` lies, `filename` param in `download_attachment` is a foot-gun | **Fix + add defer-safely** |
| Performance | `call_tool` is async but runs handlers synchronously → three parallel tool calls serialise, also `imapclient` default timeout is `None` | **Critical — wrap in `asyncio.to_thread`, add `SocketTimeout`** |
| Errors/observability | Structured error codes with `hint`+`retryable`, `mail-mcp doctor` already promised in roadmap but not built | **Ship doctor + hints** |
| Reliability | Drafts/Trash hard-coded — silently broken on non-English accounts (Gmail, iCloud ES, IONOS ES all localise), encoding fallback missing, `make_msgid` uses container hostname | **Fix SPECIAL-USE autodetect + encoding fallback** |
| Distribution | Single-source version, `CHANGELOG.md`, publish to PyPI manually (biggest single perception win), `uv.lock` commit | **User authorisation needed for PyPI; do the single-source + changelog now** |
| Documentation | `TROUBLESHOOTING.md`, honest provider status table (M365 basic-auth is off — current table over-promises), env-vars in one place, per-provider app-password guides | **Ship TROUBLESHOOTING + provider status fix** |
| Competitive positioning | "the email MCP that installs itself and survives an audit" — every roadmap item evaluated against (a) zero-friction onboarding and (b) auditable-trust. Reject: Gmail OAuth in-tree, HTTP transport, calendar, scheduler, Gradio | **Strategic compass, not a feature list** |
| Developer ergonomics | Parameter descriptions + examples on tools, startup banner, no-args → help, public API surface, config schema versioning | **All low-effort; ship the cluster** |

## Rejected explicitly (do not do, now or later)

- Migrate IMAP layer to `aioimaplib` — the `to_thread` wrap captures 100% of the parallelism benefit with 0% of the migration risk.
- Embed any OAuth `client_id`/`client_secret` in the binary (Google or Microsoft).
- Reuse Thunderbird's `client_id` — legal and supply-chain liability.
- Gradio UI — telemetry phone-home anti-pattern flagged in the peer audit.
- Zero-config relay — catastrophic privacy pattern (from the `n24q02m` peer).
- Calendar / scheduler / IMAP IDLE long-running watcher — breaks the stdio contract.
- HTTP transport — widens attack surface for no gain at this stage.
- PDF text extraction in-tree — `pdf-parse`/`pypdf`/`lopdf` all have DoS history; keep a `read_attachment` that returns bytes and let users pipe elsewhere.
- `ping_mail` as an MCP tool — `list_folders` already serves as a cheap ping; adding more surface for the LLM to enumerate is net-negative.
- Full audit log with rotation — defer until a real compliance need surfaces.
- Connection pool — defer until multi-account lands and the tests matrix can prove it.
- Shell completion — nice-to-have but power-users rarely run this twice a week.
- README competitor comparison table — reputational hazard; `SYNTHESIS.md` is the right place for that depth.
- Spanish README, ADR directory, CODE_OF_CONDUCT — premature for a single-author v0.x project.

## What ships in v0.2.1 (this commit)

### Critical (security, correctness)
1. IMAP `SocketTimeout(connect=15, read=30)` — prevents indefinite hangs.
2. Wrap tool handlers with `asyncio.to_thread` — unblocks concurrent calls.
3. Extend `sanitize_error` to redact email addresses and hostnames, and stop over-scrubbing `AUTHENTICATIONFAILED` / `BADCREDENTIALS`.
4. `wrap_untrusted_header` applied to `subject`, `from`, `to`, `cc`, `attachment.filename` wherever they cross into LLM context.
5. `make_msgid(domain=<account_domain>)` so Message-ID matches the From header.
6. Robust charset fallback in `_extract_parts` (try declared charset, then `latin-1 errors=replace`).

### High-value additions
7. `list_folders(pattern, subscribed_only)` now returns `flags` + `delimiter` per folder.
8. `search_emails` reports pre-limit `total` and accepts `offset` for pagination.
9. `mail-mcp doctor` diagnostic command (keyring backend, account reachability, MCP-client registration, env-var state).
10. SPECIAL-USE autodetect for Drafts/Trash mailboxes during `mail-mcp init` — fixes localised mailboxes silently breaking drafts/delete.

### DX polish
11. Startup banner on `serve` (stderr) with account + gate state.
12. `mail-mcp` with no args prints help instead of arg-parser error.
13. `## Environment variables` table in README.
14. Parameter `description=` filled in on every schema field the LLM sees.

### Documentation
15. `CHANGELOG.md` scaffold (Keep a Changelog).
16. `docs/TROUBLESHOOTING.md` with the top-5 day-1 failures.
17. Provider status table in README reflects reality (M365 basic-auth → OAuth2 in v0.2.2, not today).

## Deferred to v0.2.2 (all clearly scoped, just not now)

- `reply_draft` tool + `forward_draft` via `message/rfc822` attachment.
- Rate limit on `send_email`.
- Single-source version via `hatch` dynamic.
- Publish 0.1.0 → PyPI (requires explicit user authorisation on version bump).
- Commit `uv.lock` for reproducibility (needs `uv` in the author's environment).
- UIDVALIDITY in message IDs.
- BODY.PEEK-based attachment download (avoid full RFC822 refetch).
- Remove `list_attachments` (redundant), remove `DownloadAttachmentInput.filename` (foot-gun).
- Connection pool (opt-in), audit log (opt-in).
- `mail_`-prefixed tool names with deprecation window.
- Per-provider `docs/providers/gmail.md`, `docs/providers/icloud.md`.

## Non-goals confirmed

`ROADMAP.md` already lists these; the 9-agent review confirmed them:

- OAuth2 in v0.1 — defer.
- Multi-account runtime switch — v0.3.
- HTTP/SSE transport — v0.3 or later, if ever.
- Web UI — never.
- Calendar integration — never.
- PDF text extraction — never (delegate to user space).
