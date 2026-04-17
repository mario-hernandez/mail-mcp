import pytest

from mail_mcp import autoconfig
from mail_mcp.autoconfig import Discovery, DiscoveryError, ServerSpec


def test_embedded_gmail():
    d = autoconfig.discover("alice@gmail.com")
    assert d.source == "embedded"
    assert d.imap.host == "imap.gmail.com"
    assert d.imap.port == 993
    assert d.imap.security == "ssl"
    assert d.smtp.host == "smtp.gmail.com"
    assert d.smtp.security == "starttls"


def test_embedded_icloud_alias():
    d = autoconfig.discover("bob@me.com")
    assert d.source == "embedded"
    assert d.imap.host == "imap.mail.me.com"


def test_embedded_ionos():
    d = autoconfig.discover("someone@ionos.es")
    assert d.source == "embedded"
    assert d.imap.host == "imap.ionos.es"
    assert d.smtp.host == "smtp.ionos.es"


def test_embedded_mariohernandez_removed():
    """Ensure no personal-domain shortcut leaked back into the embedded table."""
    assert "mariohernandez.es" not in autoconfig.PROVIDERS


def test_proton_needs_bridge_flag():
    d = autoconfig.discover("somebody@proton.me")
    assert d.source == "proton-bridge"
    assert d.needs_bridge is True
    assert d.imap.host == "127.0.0.1"
    assert d.smtp.host == "127.0.0.1"
    assert any("Bridge" in note for note in d.notes)


def test_offline_unknown_domain_raises():
    with pytest.raises(DiscoveryError):
        autoconfig.discover("x@totally-unknown.invalid", offline=True)


def test_heuristic_fallback_when_tiers_miss(monkeypatch):
    monkeypatch.setattr(autoconfig, "_fetch_autoconfig", lambda *a, **k: None)
    monkeypatch.setattr(autoconfig, "_try_mx_preset", lambda *a, **k: None)
    monkeypatch.setattr(autoconfig, "_try_srv", lambda *a, **k: None)

    d = autoconfig.discover("user@unknownhost.invalid")

    assert d.source == "heuristic"
    assert d.imap.host == "imap.unknownhost.invalid"
    assert d.smtp.host == "smtp.unknownhost.invalid"
    assert any("autoconfig source matched" in n for n in d.notes)


def test_provider_hosted_autoconfig_wins(monkeypatch):
    calls = []

    def fake_fetch(url, *, timeout):
        calls.append(url)
        if "autoconfig.testprovider.invalid" in url:
            return Discovery(
                imap=ServerSpec("imap.testprovider.invalid", 993, "ssl"),
                smtp=ServerSpec("smtp.testprovider.invalid", 587, "starttls"),
                source="xml",
            )
        return None

    monkeypatch.setattr(autoconfig, "_fetch_autoconfig", fake_fetch)
    monkeypatch.setattr(autoconfig, "_try_mx_preset", lambda *a, **k: None)
    monkeypatch.setattr(autoconfig, "_try_srv", lambda *a, **k: None)

    d = autoconfig.discover("x@testprovider.invalid")

    assert d.source == "provider-autoconfig"
    assert d.imap.host == "imap.testprovider.invalid"
    assert any("autoconfig.testprovider.invalid" in u for u in calls)


def test_ispdb_used_after_provider_hosted_misses(monkeypatch):
    def fake_fetch(url, *, timeout):
        if "autoconfig.thunderbird.net" in url:
            return Discovery(
                imap=ServerSpec("imap.ispdb-host.invalid", 993, "ssl"),
                smtp=ServerSpec("smtp.ispdb-host.invalid", 465, "ssl"),
                source="xml",
            )
        return None

    monkeypatch.setattr(autoconfig, "_fetch_autoconfig", fake_fetch)
    monkeypatch.setattr(autoconfig, "_try_mx_preset", lambda *a, **k: None)
    monkeypatch.setattr(autoconfig, "_try_srv", lambda *a, **k: None)

    d = autoconfig.discover("x@somerare.invalid")

    assert d.source == "ispdb"
    assert d.imap.host == "imap.ispdb-host.invalid"


def test_mx_preset_fallback(monkeypatch):
    monkeypatch.setattr(autoconfig, "_fetch_autoconfig", lambda *a, **k: None)
    monkeypatch.setattr(autoconfig, "_try_srv", lambda *a, **k: None)

    def fake_mx(domain, *, timeout):
        return Discovery(
            imap=autoconfig.PROVIDERS["gmail.com"].imap,
            smtp=autoconfig.PROVIDERS["gmail.com"].smtp,
            source="mx-preset:gmail.com",
            notes=["MX record 'aspmx.l.google.com' matched provider 'gmail.com'."],
        )

    monkeypatch.setattr(autoconfig, "_try_mx_preset", fake_mx)
    d = autoconfig.discover("ceo@customdomain.invalid")
    assert d.source == "mx-preset:gmail.com"
    assert d.imap.host == "imap.gmail.com"


def test_parse_clientconfig_xml_ok():
    xml = b"""<?xml version="1.0"?>
    <clientConfig version="1.1">
      <emailProvider id="x">
        <incomingServer type="imap">
          <hostname>imap.t.invalid</hostname>
          <port>993</port>
          <socketType>SSL</socketType>
        </incomingServer>
        <outgoingServer type="smtp">
          <hostname>smtp.t.invalid</hostname>
          <port>587</port>
          <socketType>STARTTLS</socketType>
        </outgoingServer>
      </emailProvider>
    </clientConfig>"""

    d = autoconfig._parse_clientconfig_xml(xml)

    assert d is not None
    assert d.imap.host == "imap.t.invalid"
    assert d.imap.security == "ssl"
    assert d.smtp.port == 587
    assert d.smtp.security == "starttls"


def test_parse_clientconfig_xml_garbage_returns_none():
    assert autoconfig._parse_clientconfig_xml(b"not xml") is None
    assert autoconfig._parse_clientconfig_xml(b"<root/>") is None


def test_fetch_autoconfig_rejects_http():
    assert autoconfig._fetch_autoconfig("http://example.com/c.xml", timeout=1) is None
