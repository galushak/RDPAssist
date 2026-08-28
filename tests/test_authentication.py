import subprocess

import pytest

from session_assist.models import AuthenticationMode
from session_assist.services import authentication


def test_kerberos_uses_cache_principal_when_identity_is_omitted(monkeypatch):
    monkeypatch.setattr(authentication, "kerberos_cache_principal", lambda: ("admin", "SCHOOL.EXAMPLE"))
    credentials = authentication.resolved_credentials(
        username=None, domain=None, password=None, mode=AuthenticationMode.KERBEROS, kdc_host=None
    )
    assert credentials.username == "admin"
    assert credentials.domain == "SCHOOL.EXAMPLE"


def test_ntlm_requires_identity():
    try:
        authentication.resolved_credentials(
            username="", domain="", password="test-password", mode=AuthenticationMode.NTLM, kdc_host=None
        )
    except ValueError as error:
        assert "NTLM" in str(error)
    else:
        raise AssertionError("missing identity should fail")


def test_kerberos_cache_status_does_not_expose_ticket_data(monkeypatch):
    class Result:
        returncode = 0
        stdout = "Ticket cache: FILE:/private/cache\nDefault principal: testuser@EXAMPLE.ORG\n"

    monkeypatch.setattr(authentication.subprocess, "run", lambda *args, **kwargs: Result())
    monkeypatch.setattr(authentication.shutil, "which", lambda _name: "/usr/bin/klist")
    status = authentication.kerberos_cache_status()
    assert status.available is True
    assert status.principal == ("testuser", "EXAMPLE.ORG")


def completed(code=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def kerberos_listing(principal="testuser@EXAMPLE.ORG"):
    return f"Ticket cache: FILE:/private/cache\nDefault principal: {principal}\n".encode()


def test_service_reports_a_valid_cache(monkeypatch):
    monkeypatch.setattr(authentication.shutil, "which", lambda _name: "/usr/bin/klist")
    calls = []
    service = authentication.KerberosService(runner=lambda args, **_kwargs: calls.append(args) or completed(stdout=kerberos_listing()))

    status = service.get_status()

    assert status.kind is authentication.KerberosStatusKind.AVAILABLE
    assert status.principal == ("testuser", "EXAMPLE.ORG")
    assert calls == [["klist"], ["klist", "-s"]]


def test_service_reports_missing_and_expired_caches(monkeypatch):
    monkeypatch.setattr(authentication.shutil, "which", lambda _name: "/usr/bin/klist")
    missing = authentication.KerberosService(runner=lambda *_args, **_kwargs: completed(1, stderr=b"No credentials cache found"))
    expired = authentication.KerberosService(runner=lambda args, **_kwargs: completed(0, kerberos_listing()) if args == ["klist"] else completed(1))

    assert missing.get_status().kind is authentication.KerberosStatusKind.MISSING
    assert expired.get_status().kind is authentication.KerberosStatusKind.EXPIRED


def test_principal_parser_is_isolated_and_normalizes_realm():
    assert authentication.parse_default_principal("Default principal: admin@example.org\n") == ("admin", "EXAMPLE.ORG")
    assert authentication.parse_default_principal("no principal") is None


def test_file_cache_parser_supports_the_system_klist_format():
    assert authentication.cache_path_from_klist("Ticket cache: FILE:/tmp/krb5cc_1000\n") == "/tmp/krb5cc_1000"
    assert authentication.cache_path_from_klist("Ticket cache: KEYRING:persistent:1000\n") is None


def test_kinit_success_uses_stdin_not_arguments(monkeypatch):
    monkeypatch.setattr(authentication.shutil, "which", lambda _name: "/usr/bin/kinit")
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "kinit":
            return completed()
        return completed(stdout=kerberos_listing())

    result = authentication.KerberosService(runner=runner).acquire_credentials("testuser", "example.org", "not-in-arguments")

    assert result.success
    kinit_args, kinit_kwargs = calls[0]
    assert kinit_args == ["kinit", "testuser@EXAMPLE.ORG"]
    assert "not-in-arguments" not in " ".join(kinit_args)
    assert kinit_kwargs["input"] == b"not-in-arguments\n"


@pytest.mark.parametrize(
    ("stderr", "message"),
    [
        (b"Password incorrect while getting initial credentials", "Sign-in failed"),
        (b"Cannot contact any KDC for realm", "Domain controller unavailable"),
        (b"Clock skew too great", "System clock differs from the domain"),
    ],
)
def test_kinit_errors_are_sanitized(monkeypatch, stderr, message):
    monkeypatch.setattr(authentication.shutil, "which", lambda _name: "/usr/bin/kinit")
    service = authentication.KerberosService(runner=lambda *_args, **_kwargs: completed(1, stderr=stderr))

    result = service.acquire_credentials("admin", "EXAMPLE.ORG", "test-password")

    assert not result.success
    assert result.friendly_message == message
    assert "test-password" not in (result.detail or "")


def test_kinit_timeout_is_bounded(monkeypatch):
    monkeypatch.setattr(authentication.shutil, "which", lambda _name: "/usr/bin/kinit")
    service = authentication.KerberosService(runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("kinit", 20)))

    result = service.acquire_credentials("admin", "EXAMPLE.ORG", "test-password")

    assert not result.success
    assert result.friendly_message == "Domain sign-in timed out"
