# OAuth2 for Microsoft 365

Microsoft disabled basic-auth IMAP/SMTP for the vast majority of Microsoft 365
tenants in late 2022 and has been tightening the remaining exceptions ever
since. `mail-mcp` ≥ 0.3 adds a first-class OAuth2 path so tenant-managed
mailboxes work out of the box.

This document walks you through:

1. Registering an Azure AD public-client app (once per tenant — ~10 min).
2. Running `mail-mcp init` for a Microsoft 365 account.
3. What `mail-mcp` does with the resulting tokens.

If you run into trouble, jump to **Troubleshooting** at the bottom.

---

## 1. Register the Azure AD application

You need tenant-admin rights on the mailbox's tenant (being the owner of
the Microsoft 365 subscription is enough).

1. Sign in to <https://entra.microsoft.com> with an admin account.
2. **Identity → Applications → App registrations → + New registration.**
3. Fill in:
   - **Name:** `mail-mcp`
   - **Supported account types:** *Accounts in this organizational directory
     only (Single tenant)* — recommended. Prevents tokens from other tenants
     being accepted for free.
   - **Redirect URI:** choose *Public client/native (mobile & desktop)*.
     Value: `http://localhost`. This is required for the MSAL loopback
     listener.
4. Click **Register.** You land on the app's overview page.
5. Copy the **Application (client) ID** and **Directory (tenant) ID** shown
   at the top — you will need both in step 7.
6. **Authentication** tab → scroll to *Advanced settings* → set
   **Allow public client flows** = *Yes* → **Save.**
7. **API permissions** tab → **+ Add a permission** → **Microsoft Graph**
   (or Office 365 Exchange Online — both work) → *Delegated permissions* →
   add all three:
   - `IMAP.AccessAsUser.All`
   - `SMTP.Send`
   - `offline_access`
   Then click **Grant admin consent for <Tenant>** and confirm. The status
   column should flip to a green check for every row.

> ### Why these specific scopes?
>
> - `IMAP.AccessAsUser.All` — authorizes `imapclient.oauth2_login`.
> - `SMTP.Send` — authorizes the SMTP XOAUTH2 flow for outbound mail.
> - `offline_access` — required to receive a refresh token. Without it the
>   wizard fails loudly (no silent refresh means re-auth every hour, which
>   is not a state you want to be in).

> ### Why a single-tenant app?
>
> The `common` authority accepts tokens from any tenant and forces you to
> defend against that at the app level. Pinning to a specific tenant means
> Microsoft rejects foreign tokens before they reach you. Both work; single-
> tenant is just safer by default.

---

## 2. Install the OAuth extra

```bash
pipx install 'mail-mcp[cli,oauth-microsoft]'
# or, inside a venv:
pip install 'mail-mcp[oauth-microsoft]'
```

The `oauth-microsoft` extra pulls in `msal`, which the password path never
loads. If you skip this step the wizard will notice and fall back to the
password prompt with a hint.

---

## 3. Run the wizard

```bash
mail-mcp init
```

Answer:

1. **Email** — the Microsoft 365 mailbox you want to connect.
2. **Use these settings?** — *Yes* (the wizard auto-detects M365 hosts).
3. **How do you want to sign in?** — *Sign in with Microsoft (browser — recommended)*.
4. **Azure application (client) ID** — paste the GUID from step 1.5 above.
   Or set `MAIL_MCP_M365_CLIENT_ID` beforehand to skip the prompt.
5. **Directory (tenant) ID** — paste the tenant GUID. Or set
   `MAIL_MCP_M365_TENANT`. You can also use a verified domain
   (`yourcompany.com`) or `common` — but see the single-tenant note above.
6. **Browser pops up** — sign in with the target account. If your tenant
   enforces MFA you will be challenged; complete it as usual.
7. The wizard closes the loopback listener, runs a live IMAP + SMTP check
   using the fresh access token, and (if both succeed) saves:
   - the account metadata to `~/.config/mail-mcp/config.json`,
   - the refresh token to the OS keyring under
     `mail-mcp:<alias>:refresh_token`.

From then on, every `mail-mcp` invocation silently refreshes access tokens
as needed. The refresh token lasts up to 90 days of inactivity.

---

## 4. What is stored where

| Secret | Storage | Service name |
|---|---|---|
| Refresh token (OAuth accounts) | OS keyring | `mail-mcp:<alias>:refresh_token` |
| Password / app password (legacy accounts) | OS keyring | `mail-mcp:<alias>` |
| Access token (1 h TTL) | Process memory only | — |
| `client_id`, `tenant_id`, IMAP/SMTP hosts | `~/.config/mail-mcp/config.json` (0600) | — |

`config.json` never contains secrets.

---

## 5. Troubleshooting

### `AADSTS65001: The user or administrator has not consented…`
You skipped *Grant admin consent* in step 1.7. Go back, grant it, and retry.

### `AADSTS7000218: The request body must contain the following parameter: 'client_assertion'…`
Your app is registered as a *confidential client* (it expects a secret).
Fix: Authentication tab → *Allow public client flows* = **Yes**.

### `AADSTS50020: User account does not exist in tenant`
You signed in to the browser with an account that does not belong to the
tenant you registered the app under. Use the target M365 account, or switch
the app to multi-tenant if that is intentional.

### `The token bundle is missing a refresh token`
`offline_access` was not granted. Add it in API permissions → Grant admin
consent → re-run `mail-mcp init`.

### `AUTHENTICATE failed` on a live OAuth call
The access token expired and the refresh token was revoked (happens after
a password reset, conditional access policy change, or 90 days idle). Run
`mail-mcp init` once to reauthenticate; the stored refresh token is
overwritten in the keyring.

### Verifying a saved account without sending anything
```
mail-mcp doctor --connect
```
Runs IMAP + SMTP login against each account. Redact the output before
posting publicly.
