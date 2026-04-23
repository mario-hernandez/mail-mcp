"""Shared fixtures for the GreenMail-backed integration suite.

See ``tests/integration/_contract.md`` for the cross-agent fixture contract.
Everything here is owned exclusively by Agent B; the five test modules under
this folder are expected to rely on these fixtures by name without touching
the internals.

Two session-scoped fixtures run first:

1. ``greenmail`` — starts the container defined in
   ``tests/integration/docker-compose.yml`` via ``testcontainers>=4`` and
   waits for GreenMail's admin REST readiness endpoint before yielding port
   info. Skips the whole module if Docker is unreachable.

2. ``patched_tls`` — autouse. Replaces
   :func:`mail_mcp.safety.tls.create_tls_context` with an unverified-context
   factory **only for the duration of the integration session**. GreenMail
   ships a self-signed cert under ``CN=localhost``, which the production TLS
   context refuses by design — so we shim the helper here rather than weaken
   production code.

All the function-scoped helpers (`test_account`, `patched_keyring`, `cfg`,
`deliver`, `populated_inbox`) compose on top of these two.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mail_mcp import imap_client
from mail_mcp.config import AccountModel, Config, ConfigModel

# Every test in this subtree is tagged `integration`. `pyproject.toml`
# registers the marker and keeps it out of the default `pytest` run; the
# suite is opt-in via `pytest -m integration` or the `MAIL_MCP_INTEGRATION=1`
# env var.
pytestmark = pytest.mark.integration

# --- Docker-compose container -----------------------------------------------

_COMPOSE_DIR = Path(__file__).parent
_COMPOSE_FILE = "docker-compose.yml"

# Host port mappings. The container still exposes GreenMail's native 3025 /
# 3143 / 3465 / 3993 / 8080, but we publish them on offset host ports to
# avoid colliding with whatever the developer has running locally (nginx
# tends to camp 8080, another test might already be on 3993, ...).
_HOST_PORT_OFFSET = 10_000
_HOST_IMAP_PORT = 3993 + _HOST_PORT_OFFSET      # 13993
_HOST_SMTP_PORT = 3465 + _HOST_PORT_OFFSET      # 13465
_HOST_IMAP_PLAIN = 3143 + _HOST_PORT_OFFSET     # 13143
_HOST_SMTP_PLAIN = 3025 + _HOST_PORT_OFFSET     # 13025
_HOST_ADMIN_PORT = 8080 + _HOST_PORT_OFFSET     # 18080
_READINESS_URL = f"http://localhost:{_HOST_ADMIN_PORT}/api/service/readiness"
_READINESS_TIMEOUT_S = 60.0
_READINESS_POLL_S = 1.0


def _docker_available() -> bool:
    """Return True iff a Docker daemon is reachable on this host.

    The integration suite is opt-in and may run on CI boxes or dev laptops
    without Docker; we skip cleanly rather than spew opaque failures.

    Side effect: on macOS hosts that use colima or OrbStack the CLI knows
    the socket path (via ``docker context``), but the Python docker SDK that
    ``testcontainers`` depends on still looks for the default
    ``/var/run/docker.sock``. When ``DOCKER_HOST`` is not set we inspect the
    active Docker context and export it so ``testcontainers`` can find the
    daemon.
    """
    import json
    import os
    import shutil
    import subprocess

    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False

    # Help the Python SDK find the daemon on non-default sockets (colima,
    # OrbStack, Rancher Desktop, ...).
    if not os.environ.get("DOCKER_HOST"):
        try:
            ctx = subprocess.run(
                ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
                capture_output=True,
                timeout=5,
                check=False,
                text=True,
            )
            if ctx.returncode == 0 and ctx.stdout.strip():
                host = json.loads(ctx.stdout.strip())
                if host:
                    os.environ["DOCKER_HOST"] = host
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    return True


def _wait_for_readiness(url: str, *, timeout: float) -> None:
    """Poll GreenMail's admin readiness endpoint until it returns 2xx or we time out."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 — localhost only
                if 200 <= resp.status < 300:
                    return
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
            last_err = exc
        time.sleep(_READINESS_POLL_S)
    raise TimeoutError(
        f"GreenMail readiness endpoint {url} did not respond within {timeout:.0f}s"
        + (f" (last error: {last_err!r})" if last_err else "")
    )


@pytest.fixture(scope="session")
def greenmail() -> Iterator[dict[str, Any]]:
    """Start a GreenMail container for the whole test session.

    Uses :class:`testcontainers.core.container.DockerContainer` directly
    rather than :class:`DockerCompose`, because not every host has the
    ``docker compose`` v2 CLI plugin installed (the standalone
    ``docker-compose`` v1 binary is incompatible with testcontainers'
    invocation style). The ``docker-compose.yml`` stays in the repo as a
    convenience for manual debugging.
    """
    if not _docker_available():
        pytest.skip("docker not available")

    # Disable testcontainers' "ryuk" sidecar — it tries to mount the host's
    # docker socket *into* a container, which breaks on colima/OrbStack/
    # Rancher Desktop because their sockets live at non-standard paths. We
    # provide a deterministic teardown via the ``finally`` block below, so
    # the garbage-collection-on-exit safety net ryuk provides is redundant.
    import os

    os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

    try:
        from testcontainers.core.container import DockerContainer
    except ImportError:
        pytest.skip("testcontainers not installed (install mail-mcp[integration])")

    container = (
        DockerContainer("greenmail/standalone:2.1.3")
        .with_env(
            "GREENMAIL_OPTS",
            # ``hostname=0.0.0.0`` is crucial — GreenMail defaults to binding
            # on 127.0.0.1 *inside the container*, which means ``docker -p``
            # cannot forward traffic to it from the host.
            "-Dgreenmail.setup.test.all "
            "-Dgreenmail.users.admin=admin:admin "
            "-Dgreenmail.hostname=0.0.0.0",
        )
        # ``with_bind_ports(container_port, host_port)``. Container ports stay
        # at GreenMail's defaults; host ports are shifted to 1x0xx so they
        # cannot collide with nginx, other test suites, or docker-desktop.
        .with_bind_ports(3025, _HOST_SMTP_PLAIN)
        .with_bind_ports(3143, _HOST_IMAP_PLAIN)
        .with_bind_ports(3465, _HOST_SMTP_PORT)
        .with_bind_ports(3993, _HOST_IMAP_PORT)
        .with_bind_ports(8080, _HOST_ADMIN_PORT)
    )
    container.start()
    try:
        _wait_for_readiness(_READINESS_URL, timeout=_READINESS_TIMEOUT_S)
        yield {
            "imap_host": "localhost",
            "imap_port": _HOST_IMAP_PORT,
            "smtp_host": "localhost",
            "smtp_port": _HOST_SMTP_PORT,
            "admin_url": f"http://localhost:{_HOST_ADMIN_PORT}",
        }
    finally:
        container.stop()


# --- TLS shim (autouse, session) --------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def patched_tls() -> Iterator[None]:
    """Relax TLS verification for the integration session only.

    GreenMail's self-signed cert (``CN=localhost``) is legitimately rejected
    by :func:`mail_mcp.safety.tls.create_tls_context` in production — there is
    no runtime opt-out, which is the point. For tests we monkey-patch the
    helper at the package boundary so both :mod:`imap_client` and
    :mod:`smtp_client` pick up the unverified context transparently.

    The patch lives for the whole session (session-scope, autouse) and is
    torn down automatically when the context-manager exits.
    """

    def _unverified_ctx() -> ssl.SSLContext:
        # ssl._create_unverified_context() disables both hostname checking
        # and certificate verification — acceptable only against the local
        # GreenMail container used by this suite.
        return ssl._create_unverified_context()  # noqa: S323

    # ``from .safety.tls import create_tls_context`` in the consumer modules
    # rebinds the name locally, so patching the origin is not enough.  We also
    # patch every module that imports the helper directly.
    binding_sites = [
        "mail_mcp.safety.tls.create_tls_context",
        "mail_mcp.imap_client.create_tls_context",
        "mail_mcp.smtp_client.create_tls_context",
        "mail_mcp.autoconfig.create_tls_context",
    ]
    from contextlib import ExitStack

    with ExitStack() as stack:
        for target in binding_sites:
            stack.enter_context(patch(target, _unverified_ctx))
        yield


# --- Per-test account -------------------------------------------------------


def create_greenmail_user(admin_url: str, email: str, password: str) -> None:
    """Provision a GreenMail user via the admin REST API.

    GreenMail does not auto-create mailboxes on an unknown LOGIN — it
    rejects the authentication. The test suite uses ephemeral
    ``test-<uuid>@localhost.local`` addresses, so every ``test_account``
    creates the account up front.
    """
    import json

    import requests  # type: ignore[import-not-found]

    body = json.dumps({"login": email, "email": email, "password": password}).encode()
    resp = requests.post(
        f"{admin_url}/api/user",
        data=body,
        headers={"Content-Type": "application/json"},
        auth=("admin", "admin"),
        timeout=10,
    )
    # 200/201 on create, 409 if a previous run left the user behind.
    if resp.status_code not in (200, 201, 409):
        raise RuntimeError(f"GreenMail user create failed: {resp.status_code} {resp.text}")


@pytest.fixture
def test_account(greenmail: dict[str, Any]) -> AccountModel:
    """A fresh ``AccountModel`` for each test, bound to the GreenMail instance.

    GreenMail auto-creates the mailbox on first authenticated access and
    accepts any username/password pair, so the email just needs to be unique
    enough that tests running in parallel (xdist) don't collide. ``uuid4``'s
    short hex is plenty.

    Notes on transport choice:
    * ``imap_use_ssl=True`` + port 3993 → IMAPS (implicit TLS).
    * ``smtp_starttls=False`` + port 3465 → SMTPS (implicit TLS). With this
      flag, :func:`mail_mcp.smtp_client.send` uses :class:`smtplib.SMTP_SSL`,
      which is what GreenMail expects on 3465.
    """
    short = uuid.uuid4().hex[:8]
    alias = f"greenmail-{short}"
    email = f"test-{short}@localhost.local"
    create_greenmail_user(greenmail["admin_url"], email, _GREENMAIL_PASSWORD)
    return AccountModel(
        alias=alias,
        email=email,
        imap_host=greenmail["imap_host"],
        imap_port=greenmail["imap_port"],
        smtp_host=greenmail["smtp_host"],
        smtp_port=greenmail["smtp_port"],
        imap_use_ssl=True,
        smtp_starttls=False,  # SMTPS on 3465, not STARTTLS
        drafts_mailbox="Drafts",
        trash_mailbox="Trash",
    )


# --- Keyring shim (autouse) -------------------------------------------------

_GREENMAIL_PASSWORD = "greenmail"


@pytest.fixture(autouse=True)
def patched_keyring(
    test_account: AccountModel,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stub out the OS keyring so production code sees a live password.

    Since v0.3 the tool layer no longer imports ``get_password`` directly —
    it goes through :mod:`mail_mcp.credentials.resolve_auth`, which itself
    uses ``keyring_store.get_password`` via module-qualified access. Patching
    the single origin is therefore enough; no per-consumer binding to chase.

    The stub only returns our test password for the current ``test_account``
    alias. Any other alias raises, matching production behaviour (the real
    ``get_password`` raises ``RuntimeError`` on missing entries).
    """

    def _fake_get_password(alias: str, username: str) -> str:
        if alias == test_account.alias:
            return _GREENMAIL_PASSWORD
        raise RuntimeError("credential not found in keyring")

    monkeypatch.setattr("mail_mcp.keyring_store.get_password", _fake_get_password)


# --- Mailbox seeding (autouse) ----------------------------------------------


@pytest.fixture(autouse=True)
def _ensure_standard_mailboxes(test_account: AccountModel) -> None:
    """Create Drafts and Trash on the server before each test.

    GreenMail only creates INBOX when a user is provisioned; our tools
    assume Drafts and Trash exist (``save_draft`` does IMAP APPEND to
    ``Drafts``, ``delete_emails`` moves to ``Trash`` by default). Creating
    both at the top of every test keeps the test bodies focused on the
    behaviour under test instead of boilerplate setup.
    """
    from mail_mcp import imap_client as _imap

    with _imap.connect(test_account, _GREENMAIL_PASSWORD) as client:
        for mailbox in (test_account.drafts_mailbox, test_account.trash_mailbox):
            if not client.folder_exists(mailbox):
                client.create_folder(mailbox)


# --- Config (function scope) ------------------------------------------------


@pytest.fixture
def cfg(test_account: AccountModel, tmp_path: Path) -> Config:
    """Build an in-memory ``Config`` with the test account as sole + default.

    The ``path`` points under ``tmp_path`` so any code that *does* call
    :func:`mail_mcp.config.save` writes inside the pytest temp tree rather
    than polluting ``~/.config``. Most tests don't need to persist — the
    fixture deliberately doesn't call ``save`` for you.
    """
    model = ConfigModel(
        default_alias=test_account.alias,
        accounts=[test_account],
    )
    return Config(path=tmp_path / "config.json", model=model)


# --- SMTP delivery helper ---------------------------------------------------

DeliverFn = Callable[..., str]


@pytest.fixture
def deliver(test_account: AccountModel) -> DeliverFn:
    """Return a callable that drops a pre-built ``EmailMessage`` into the account's INBOX.

    Signature::

        deliver(
            *,
            from_: str = "other@localhost.local",
            to: str | list[str] | None = None,   # defaults to test_account.email
            subject: str = "Hello",
            body: str = "hello",
            html: str | None = None,
            in_reply_to: str | None = None,
            references: list[str] | None = None,
            message_id: str | None = None,
            attachment: tuple[str, bytes] | None = None,
            date: str | None = None,
        ) -> str

    Returns the ``Message-ID`` the message was sent with (auto-minted when not
    supplied). We bypass :mod:`mail_mcp.smtp_client` on purpose — the helper
    is a *test utility* that should work independently of the code under
    test, so a regression in our own SMTP wrapper can't hide delivery bugs.

    GreenMail doesn't require auth to accept mail (it relays unconditionally
    to local mailboxes); we still pass ``admin:admin`` because GreenMail
    advertises ``AUTH`` and some Python versions' ``SMTP_SSL.sendmail`` flow
    is cleaner once logged in.
    """
    # Local import — smtplib is stdlib and lazily importing keeps fixture
    # collection fast when the suite is skipped.
    import smtplib

    def _deliver(
        *,
        from_: str = "other@localhost.local",
        to: str | list[str] | None = None,
        subject: str = "Hello",
        body: str = "hello",
        html: str | None = None,
        in_reply_to: str | None = None,
        references: list[str] | None = None,
        message_id: str | None = None,
        attachment: tuple[str, bytes] | None = None,
        date: str | None = None,
    ) -> str:
        recipients: list[str]
        if to is None:
            recipients = [test_account.email]
        elif isinstance(to, str):
            recipients = [to]
        else:
            recipients = list(to)

        msg = EmailMessage()
        msg["From"] = from_
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg["Date"] = date or formatdate(localtime=False, usegmt=True)
        mid = message_id or make_msgid(domain=from_.rsplit("@", 1)[1])
        msg["Message-ID"] = mid
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
        if references:
            msg["References"] = " ".join(references)

        msg.set_content(body)
        if html is not None:
            # add_alternative gives us a real multipart/alternative so the
            # HTML-extraction path in imap_client._extract_parts fires.
            msg.add_alternative(html, subtype="html")
        if attachment is not None:
            filename, data = attachment
            msg.add_attachment(
                data,
                maintype="application",
                subtype="pdf",
                filename=filename,
            )

        # ssl._create_unverified_context() — GreenMail cert is self-signed.
        ctx = ssl._create_unverified_context()  # noqa: S323
        with smtplib.SMTP_SSL(
            test_account.smtp_host,
            test_account.smtp_port,
            context=ctx,
            timeout=15,
        ) as server:
            try:
                server.login("admin", "admin")
            except smtplib.SMTPException:
                # GreenMail accepts unauthenticated MAIL FROM too; don't fail
                # the whole test just because AUTH wasn't advertised.
                pass
            server.send_message(msg, from_addr=from_, to_addrs=recipients)
        return mid

    return _deliver


# --- Populated inbox --------------------------------------------------------


@pytest.fixture
def populated_inbox(
    deliver: DeliverFn,
    test_account: AccountModel,
) -> list[tuple[int, str, str]]:
    """Seed the INBOX with the scenarios defined in ``fixtures.sample_emails``.

    Returns a list of ``(uid, message_id, subject)`` tuples, one per delivered
    message, obtained by a real IMAP ``SEARCH ALL`` + ``FETCH ENVELOPE`` after
    a short settle delay. GreenMail delivers synchronously but the IMAP index
    sometimes lags the SMTP ack, so we wait and retry briefly before fetching.
    """
    # Deferred import: the module lives under ``tests.integration.fixtures``
    # and pulling it at conftest-import time would make any typo there fail
    # the entire integration session rather than a single test.
    from tests.integration.fixtures.sample_emails import SAMPLE_EMAILS

    delivered: list[tuple[str, str]] = []  # (subject, message_id)
    for spec in SAMPLE_EMAILS:
        mid = deliver(**spec)
        delivered.append((spec["subject"], mid))

    # Brief settle — GreenMail normally indexes immediately, but on slower
    # CI runners the first FETCH after a burst can come up short.
    time.sleep(1.0)

    # Fetch real UIDs via IMAP. We re-use mail_mcp's own connect() so the
    # TLS shim (`patched_tls`) is exercised here too — a free smoke test of
    # the plumbing before the suite's real assertions run.
    deadline = time.monotonic() + 10.0
    results: list[tuple[int, str, str]] = []
    expected_mids = {mid for _, mid in delivered}
    while time.monotonic() < deadline:
        results = []
        with imap_client.connect(test_account, _GREENMAIL_PASSWORD) as client:
            client.select_folder("INBOX", readonly=True)
            all_uids = sorted(client.search(["ALL"]))
            if not all_uids:
                time.sleep(0.5)
                continue
            fetched = client.fetch(all_uids, ["ENVELOPE"])
            for uid in all_uids:
                env = fetched.get(uid, {}).get(b"ENVELOPE")
                if env is None:
                    continue
                mid_raw = env.message_id
                mid = mid_raw.decode() if isinstance(mid_raw, bytes) else (mid_raw or "")
                subject_raw = env.subject
                subj = (
                    subject_raw.decode(errors="replace")
                    if isinstance(subject_raw, bytes)
                    else (subject_raw or "")
                )
                results.append((int(uid), mid, subj))
        found_mids = {mid for _, mid, _ in results}
        if expected_mids.issubset(found_mids):
            break
        time.sleep(0.5)

    return results
