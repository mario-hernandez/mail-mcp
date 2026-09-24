"""Suite-wide fixtures.

Signatures are loaded from ``<config dir>/signatures/``. Many older tests build
``Config(path=Path("/tmp/x"))``, which would make ``/tmp/signatures/`` — a
world-writable place — part of every test run: a stray or planted file there
would change what those tests build, or make them fail. This fixture keeps the
real lookup for configs that live inside the test's own ``tmp_path`` (that is
how ``test_signatures.py`` exercises it) and points every other config at an
empty, test-private directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mail_mcp.signatures as _signatures


@pytest.fixture(autouse=True)
def _isolate_signature_lookup(monkeypatch, tmp_path):
    original = _signatures.signatures_root

    def isolated(cfg):
        root = original(cfg)
        if root is None:
            return None
        try:
            Path(root).resolve().relative_to(Path(tmp_path).resolve())
        except ValueError:
            return Path(tmp_path) / "isolated-signatures"
        return root

    monkeypatch.setattr(_signatures, "signatures_root", isolated)
