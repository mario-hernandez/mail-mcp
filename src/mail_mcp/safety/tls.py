"""TLS context helpers.

Python installations from python.org on macOS ship without a populated CA
bundle — the ``Install Certificates.command`` post-install script has to run
manually and is often forgotten. The consequence is
``ssl.SSLCertVerificationError: unable to get local issuer certificate`` on
every HTTPS/IMAPS/SMTPS connection, which looks like a mail-mcp bug to an
end user.

The fix is one line: when ``certifi`` is importable, feed its CA bundle into
:func:`ssl.create_default_context`. ``certifi`` is a dev/cli extra and comes
in automatically with ``pip install 'mail-mcp[cli]'`` via ``requests``-like
transitive pulls; it is also safe to install on its own (``pip install
certifi``). When ``certifi`` is not available we fall back to the system
defaults, which is the right behaviour on Linux and modern macOS tooling.
"""

from __future__ import annotations

import ssl


def create_tls_context() -> ssl.SSLContext:
    """Return a secure :class:`ssl.SSLContext`, preferring the certifi bundle.

    The returned context has hostname verification and peer verification
    enabled (``CERT_REQUIRED``) — no bypass knob exists by design.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ModuleNotFoundError:
        return ssl.create_default_context()
