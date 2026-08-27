import io

import pytest

import session_assist.services.terminal_services as terminal
from session_assist.services.network import KdcCandidate, KdcDiscovery, ResolvedTarget
from session_assist.diagnostics import Diagnostics
from session_assist.models import AuthenticationMode, Credentials


def service():
    return terminal.TerminalServicesService(
        "dc01.example.org", Credentials("admin", "EXAMPLE.ORG", None, AuthenticationMode.KERBEROS), Diagnostics(io.StringIO())
    )


def test_resolved_address_is_remote_host_and_hostname_is_remote_name(monkeypatch):
    instance = service()
    monkeypatch.setattr(
        terminal, "resolve_target_hostname",
        lambda *_args, **_kwargs: ResolvedTarget("dc01.example.org", "dc01.example.org", "192.0.2.60", "example.org"),
    )
    monkeypatch.setattr(terminal, "kerberos_cache_path", lambda: "/tmp/krb5cc_1000")
    constructed = []

    class FakeSmb:
        def getDialect(self):
            return 0x311

        def kerberosLogin(self, *args, **kwargs):
            constructed.append((args, kwargs))

    def smb_connection(remote_name, remote_host, **kwargs):
        constructed.append((remote_name, remote_host, kwargs))
        return FakeSmb()

    instance._SMBConnection = smb_connection
    instance._resolve_target()
    instance.kdc_host = "dc01.example.org"
    instance._configure_impacket_cache()
    instance._connect_smb()

    assert constructed[0][0:2] == ("dc01.example.org", "192.0.2.60")
    assert constructed[1][1]["useCache"] is True
    assert "192.0.2.60" not in instance.target
    instance.__exit__()


def test_short_hostname_uses_realm_derived_dns_domain_after_direct_lookup_fails(monkeypatch):
    instance = terminal.TerminalServicesService(
        "dc01", Credentials("admin", "EXAMPLE.ORG", None, AuthenticationMode.KERBEROS), Diagnostics(io.StringIO())
    )
    monkeypatch.setattr(
        terminal, "resolve_target_hostname",
        lambda *_args, **_kwargs: ResolvedTarget("dc01", "dc01.example.org", "192.0.2.60", "example.org"),
    )

    instance._resolve_target()

    assert instance.target == "dc01.example.org"
    assert instance.remote_host == "192.0.2.60"


def test_discovered_kdc_hostname_is_passed_to_impacket_not_realm(monkeypatch):
    instance = service()
    selected = KdcCandidate("EXAMPLE.ORG", "dc01.example.org", "192.0.2.60", 88, 0, 100, "_kerberos._tcp")
    monkeypatch.setattr(terminal, "discover_kdcs", lambda realm: KdcDiscovery(realm, (selected,), selected))
    instance._resolve_kdc()
    calls = []

    class FakeSmb:
        def kerberosLogin(self, *args, **kwargs):
            calls.append((args, kwargs))

    instance._SMBConnection = lambda *_args, **_kwargs: FakeSmb()
    instance._connect_smb()

    assert instance.kdc_host == "dc01.example.org"
    assert calls[0][0][6] == "dc01.example.org"
    assert calls[0][0][6] != "EXAMPLE.ORG"


def test_unknown_impacket_version_is_quiet(monkeypatch):
    instance = service()
    monkeypatch.setattr(terminal.metadata, "version", lambda _name: (_ for _ in ()).throw(terminal.metadata.PackageNotFoundError))

    instance._load_impacket()

    output = instance.diagnostics.stream.getvalue()
    assert "Impacket version" in output
    assert "unknown" in output
    assert "Cannot determine Impacket version" not in output
