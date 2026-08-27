import socket

import pytest

import session_assist.services.network as network


def test_short_name_retries_realm_derived_fqdn_after_direct_dns_failure(monkeypatch):
    seen = []

    def resolver(hostname):
        seen.append(hostname)
        if hostname == "teacher-pc":
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return [(None, None, None, "", ("192.0.2.44", 0))]

    monkeypatch.setattr(network, "_get_addresses", resolver)
    resolved = network.resolve_target_hostname("teacher-pc", realm="EXAMPLE.ORG")

    assert seen == ["teacher-pc", "teacher-pc.example.org"]
    assert resolved.hostname == "teacher-pc.example.org"
    assert resolved.address == "192.0.2.44"
    assert resolved.dns_domain == "example.org"


def test_temporary_dns_failure_is_retried_before_suffix_lookup(monkeypatch):
    calls = []

    def resolver(hostname):
        calls.append(hostname)
        if len(calls) < 3:
            raise socket.gaierror(socket.EAI_AGAIN, "temporary")
        return [(None, None, None, "lab-pc.example.org", ("192.0.2.55", 0))]

    monkeypatch.setattr(network, "_get_addresses", resolver)
    monkeypatch.setattr(network.time, "sleep", lambda _seconds: None)
    resolved = network.resolve_target_hostname("lab-pc", realm="EXAMPLE.ORG")

    assert calls == ["lab-pc", "lab-pc", "lab-pc"]
    assert resolved.hostname == "lab-pc.example.org"


def test_kdc_discovery_tries_later_candidate_when_first_tcp_check_fails(monkeypatch):
    def srv(_realm, query):
        if "dc._msdcs" in query:
            return [(0, 100, 88, "dc02.example.org"), (0, 50, 88, "dc01.example.org")]
        return []

    monkeypatch.setattr(network, "_srv_records", srv)
    monkeypatch.setattr(
        network, "_resolve_with_retries",
        lambda hostname: [(None, None, None, hostname, ({"dc02.example.org": "192.0.2.60", "dc01.example.org": "192.0.2.61"}[hostname], 0))],
    )
    checks = []

    def tcp(host, port, timeout):
        checks.append((host, port, timeout))
        return network.TcpCheck(host, port, host == "192.0.2.61", "refused")

    monkeypatch.setattr(network, "check_tcp", tcp)
    discovered = network.discover_kdcs("example.org")

    assert checks[0][0] == "192.0.2.60"
    assert discovered.selected is not None
    assert discovered.selected.hostname == "dc01.example.org"
    assert discovered.selected.source == "_kerberos._tcp.dc._msdcs"


def test_kdc_discovery_never_uses_realm_as_a_host(monkeypatch):
    monkeypatch.setattr(network, "_srv_records", lambda *_args: [])
    discovered = network.discover_kdcs("EXAMPLE.ORG")

    assert discovered.selected is None
    assert all(candidate.hostname.casefold() != "example.org" for candidate in discovered.candidates)
