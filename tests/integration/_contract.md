# Integration-test fixture contract (shared between agents)

All five agents building `tests/integration/` use the same fixture and helper
names, defined in `conftest.py`. This keeps the five test files coherent.

## Fixtures (session scope)

- `greenmail` — starts a GreenMail container via `testcontainers` or raw
  docker-compose; yields a dict with the reachable ports:
  `{"imap_host": "localhost", "imap_port": 3993, "smtp_host": "localhost",
  "smtp_port": 3465, "admin_url": "http://localhost:8080"}`.
  Uses the SSL ports (3993 IMAPS, 3465 SMTPS).

- `patched_tls` — autouse session-level fixture that monkeypatches
  `mail_mcp.safety.tls.create_tls_context` so it returns an
  `ssl._create_unverified_context()` for tests only. The production code
  stays strict.

## Fixtures (function scope)

- `test_account(greenmail, tmp_path)` — produces a unique
  `(AccountModel, password)` tuple for each test. Email is
  `test-<uuid4-short>@localhost`, password is `"greenmail"`, config lives
  in `tmp_path/config.json`. `imap_use_ssl=True`, `smtp_starttls=False`
  (we're on SMTPS 3465, not STARTTLS).

- `patched_keyring(test_account, monkeypatch)` — stubs
  `mail_mcp.keyring_store.get_password` to return the password above.
  Autouse.

- `cfg(test_account, tmp_path)` — returns a `Config` object with
  `test_account` as the sole account and as default. Saved to
  `tmp_path/config.json`.

- `deliver(test_account)` — callable helper. Drops a message into the
  account's INBOX via GreenMail SMTP. Signature:
  `deliver(*, from_="other@localhost", to=None, subject="Hello",
  body="text", html=None, in_reply_to=None, references=None,
  message_id=None, attachment=None)`. Returns the `Message-ID` it used.
  `to` defaults to the test account's own address.

- `populated_inbox(deliver)` — seeds the INBOX with ~10 varied messages:
  three-message thread (Stripe invoice → reply → follow-up), one
  newsletter, one with a 1 KB PDF attachment, one unread, one flagged,
  one from another thread. Returns a list of `(uid, message_id, subject)`
  tuples once re-fetched after delivery.

## Imports every agent should have ready

```python
from mail_mcp import imap_client, smtp_client
from mail_mcp.config import AccountModel, Config, ConfigModel
from mail_mcp.tools import drafts, organize, read, send
from mail_mcp.tools.schemas import (
    CopyEmailInput, CreateFolderInput, DeleteEmailInput, DeleteFolderInput,
    DownloadAttachmentInput, ForwardDraftInput, GetEmailInput, GetQuotaInput,
    GetThreadInput, ListAccountsInput, ListAttachmentsInput, ListDraftsInput,
    ListFoldersInput, MarkFlagsInput, MoveEmailInput, RenameFolderInput,
    ReplyDraftInput, SaveDraftInput, SearchInput, SendDraftInput,
    SendEmailInput, SpecialFoldersInput, UpdateDraftInput,
)
```

## Marker

All files under `tests/integration/` use `pytestmark =
pytest.mark.integration`. The `pytest.ini_options` in `pyproject.toml`
registers the `integration` marker and excludes it from the default run;
integration suite is opt-in via `pytest -m integration` or the env flag
`MAIL_MCP_INTEGRATION=1`.

## File ownership (NO OVERLAPS)

- Agent A (infra) — `tests/integration/docker-compose.yml`,
  `tests/integration/README.md`, updates to `pyproject.toml` (new
  `[project.optional-dependencies].integration`), no other files.
- Agent B (conftest + seeds) — `tests/integration/conftest.py`,
  `tests/integration/fixtures/sample_emails.py`. Nothing else.
- Agent C (read path) — `tests/integration/test_integration_read.py`.
- Agent D (write path + folder ops) —
  `tests/integration/test_integration_write.py`.
- Agent E (drafts + send) —
  `tests/integration/test_integration_drafts_send.py`.
