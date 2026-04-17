# Roadmap — onboarding, imports, OAuth

_Consolidated from a 10-agent parallel research sweep; the full notes live in
`SYNTHESIS.md`. The overall goal of v0.2 is to remove friction from getting a
new account wired up: detect what the user already has, fill what we can, and
ask only for what we must._

> **Release snapshot (2026-04-17)**
> * v0.2.0 shipped the interactive wizard + 5-tier autoconfig waterfall.
> * v0.2.1 pivoted to security hardening and onboarding polish (see
>   [`CHANGELOG.md`](CHANGELOG.md)). Importers were deferred to v0.2.2.
> * v0.2.2 (in progress) covers the Thunderbird and Apple Mail importers,
>   Microsoft 365 OAuth2, and the `reply_draft` / `forward_draft` tools.

## One-line summary per angle

| Angle | Verdict | Priority |
|---|---|---|
| **Autoconfig / autodiscover** (ISPDB, SRV, Autodiscover, MX presets) | **Adopt — highest ROI** | v0.2.0 |
| **CLI wizard** (`questionary` + `rich`) | **Adopt** as `mail-mcp[cli]` extra | v0.2.0 |
| **Thunderbird importer** (`prefs.js` + `logins.json` via NSS) | **Adopt — highest-ROI importer** (cross-platform) | v0.2.1 |
| **Apple Mail importer** (`Accounts4.sqlite` + Keychain) | Adopt with caveats (OAuth accounts can't be carried over) | v0.2.1 |
| **Password-manager importers** (Bitwarden, KeePassXC first; 1Password later) | Adopt | v0.2.2 |
| **OAuth2 for Microsoft 365** (`msal`, loopback PKCE) | Adopt as `mail-mcp[oauth-microsoft]` extra | v0.2.2 |
| **OAuth2 for Gmail** | **Document two paths** (BYO Google Cloud project, or `email-oauth2-proxy` local proxy). **Do not** embed a shared `client_id`. | docs-only |
| **Keychain depth** (trusted apps, Internet vs Generic password) | Keep current design (`keyring` + Generic). Document the first-launch prompt. | v0.2.0 |
| **Hybrid OAuth via pasted refresh token** | BYO-token is a defensible fallback. Never reuse Mozilla/Thunderbird `client_id`. | v0.3 |
| **Outlook for Mac importer** | **Discard** — New Outlook (95%+ of users since Oct 2025) is an OAuth-to-Microsoft web wrapper with no local IMAP creds. | — |

## What the 10 agents agreed on

1. **The autodiscover problem is already solved in OSS.** Thunderbird's ISPDB (163+ providers, MPL-2.0, 248 KB on disk if embedded) plus RFC 6186 SRV records plus a 5-entry MX preset table cover ~99% of users given only `email + password`. The `myl-discovery` package (GPL-3.0) encapsulates the full waterfall; we will reimplement the algorithm (≈150 LoC) to keep our license MIT and our dependency tree boring.
2. **Client-credential storage on macOS is fine as-is.** Using `keyring` with Generic Password entries namespaced `mail-mcp:<alias>` is the right call. Do *not* migrate to Internet Password hoping for Mail.app interop — Mail.app's ACL blocks third parties anyway. Do *not* add `pyobjc-framework-Security` (+18 MB) for no gain. Do document the "first-run Keychain prompt, pick Always Allow" behaviour in SECURITY.md.
3. **Do not embed any OAuth `client_id`/`client_secret` in the binary.** Three repos in our previous audit did this; two got dinged for it. Google requires per-user Cloud projects if you want to be above-board; Microsoft bends and allows public-client `msal` flows with no secret. So: Microsoft, yes, in-tree. Google: BYO project or local proxy (`simonrob/email-oauth2-proxy`). Thunderbird's `client_id` is legally unsafe to reuse and Google can revoke it for everyone if abused.
4. **The unique value of `mail-mcp` vs existing tools is detection across clients.** Nobody in OSS has shipped a multi-source importer (Apple Mail, Thunderbird, Outlook, mutt, mbsync) into a single wizard. Thunderbird's own internal `accountcreation` code is the gold standard for the autodiscover waterfall but is embedded in a JS codebase. We write the Python orchestrator.
5. **Outlook for Mac is a dead end** for credential import. Legacy is in sunset (EOL Oct 2025, <5% of installs remain); New Outlook is a web wrapper with zero local IMAP creds. The only supported credentials live on Microsoft's servers. Time saved by dropping: 1-2 weeks.
6. **Spark is likewise a dead end.** Spark is a SaaS client — IMAP credentials live on Readdle's servers, only session tokens live locally. Nothing extractable.

## Decisions

### v0.2.0 — "zero-config onboarding" (core)

* Add `src/mail_mcp/autoconfig.py`:
  * Order: embedded ISPDB dump → `https://autoconfig.<domain>/mail/config-v1.1.xml` → `.well-known/autoconfig/mail/config-v1.1.xml` → online ISPDB (`autoconfig.thunderbird.net/v1.1/<domain>`) → DNS SRV (`_imaps._tcp`, `_submission._tcp`) → MS Autodiscover → MX preset table → heuristic (`imap.<domain>:993`).
  * Privacy: **HTTPS-only**, 3-second timeout each, no email address ever in query string when the destination is not the user's own provider (use domain only for ISPDB).
  * Embedded ISPDB: vendor the XML dump as `src/mail_mcp/data/ispdb/` at build time (git submodule or CI fetch), licensed MPL-2.0 with attribution in NOTICE.
* Add `src/mail_mcp/wizard.py` — `mail-mcp init` using `questionary` + `rich`, gated behind `mail-mcp[cli]` extra so the MCP server itself keeps its 4 core deps.
  * Flow: email → autoconfig preview → password prompt → live IMAP/SMTP login test → confirm → save to keyring.
  * Fallback at every step if detection fails.
  * Non-TTY guard (print "use add-account for scripting" and exit 2).
* Add `src/mail_mcp/doctor.py` — `mail-mcp doctor` that prints keyring backend, accounts listed with their connection status, and which MCP clients are wired up.
* Update `SECURITY.md` with a "Keychain UX on macOS" section.

### v0.2.1 — "import from what you already have"

* `src/mail_mcp/importers/thunderbird.py`: parse `profiles.ini` + `prefs.js`, map account → server → identity → smtp, extract hostnames/ports/usernames. Skip credential decryption in v0.2.1 (GPL dependency, NSS required) — just pre-fill the form and let the user type or paste the password.
* `src/mail_mcp/importers/apple_mail.py`: read `~/Library/Accounts/Accounts4.sqlite` read-only (copy-then-open to avoid `SQLITE_BUSY`), join `ZACCOUNT`/`ZACCOUNTPROPERTY`, skip `AuthenticationScheme=ATOKEN*` accounts with a clear message, pre-fill form for the rest, then `security find-internet-password -w` for each (this triggers the Keychain prompt — documented).
* `src/mail_mcp/register.py` — `mail-mcp register --client <claude-code|claude-desktop|codex>` auto-edits the appropriate config file with a visible diff before writing.

### v0.2.2 — "password manager bridges + Microsoft OAuth"

* `src/mail_mcp/importers/bitwarden.py` — shell out to `bw get item`, parse JSON, prompt for missing host/port, confirm before save. Session token from env (`BW_SESSION`).
* `src/mail_mcp/importers/keepass.py` — `pykeepass` (pure Python, no CLI), prompts for master password.
* `src/mail_mcp/oauth.py` — `msal` with loopback PKCE for Microsoft 365. Public client registered in Azure once by the project. Refresh token in keyring under `mail-mcp:<alias>:refresh_token`. Gated behind `mail-mcp[oauth-microsoft]` extra.

### v0.3+ and non-goals

* 1Password importer (excellent UX but paid).
* Proton Pass, LastPass, Dashlane, NordPass importers (weak CLI or no CLI).
* Full Google OAuth2 in-tree (requires per-user Cloud project anyway — documented instead).
* Outlook-for-Mac importer (dead format).
* Spark importer (impossible by design).
* Reusing any other project's `client_id` (legal hazard).

## Acceptance criteria for v0.2.0

* `mail-mcp init` with an IONOS/`@mariohernandez.es` email completes end-to-end in under 45 seconds on a cold machine.
* Detection succeeds offline (no internet) when the provider is in the embedded ISPDB.
* Embedded ISPDB does not grow the install past 500 KB total.
* No new *required* dependencies; `questionary` and `rich` only via `mail-mcp[cli]`.
* Test suite stays green (72 tests at v0.2.1); new tests cover the autoconfig waterfall with mocked endpoints.
* `SECURITY.md` updated with the Keychain first-launch prompt explanation.

## References (pointers, not embedding)

* Thunderbird `accountcreation` algorithm: `mozilla/releases-comm-central/mail/components/accountcreation/modules/`
* ISPDB: `github.com/thunderbird/autoconfig`
* `myl-discovery`: `github.com/pschmitt/myl-discovery` (algorithm reference; not a dependency)
* `firefox_decrypt`: `github.com/unode/firefox_decrypt` (deferred to v0.3; GPL-3.0, NSS-dependent)
* `email-oauth2-proxy`: `github.com/simonrob/email-oauth2-proxy` (referenced in docs for Gmail escape hatch)
* NDSS 2025 "Automatic Insecurity": Mozilla's autoconfig is served over HTTP by some providers — always force HTTPS.
