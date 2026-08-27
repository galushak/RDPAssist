from concurrent.futures import TimeoutError as FutureTimeout
from types import SimpleNamespace

import pytest

import session_assist.gui.controller as controller_module
from session_assist.diagnostics import Stage
from session_assist.gui.controller import BackendController, policy_capabilities
from session_assist.models import AuthenticationMode, AssistanceError, Credentials, Session, ShadowPolicy, ShadowPolicyStatus
from session_assist.services.network import TcpCheck


CONSOLE = Session(2, "jsmith", "SCHOOL", "Active", "console")


def test_no_console_disables_assistance_but_not_for_policy_reasons():
    capabilities = policy_capabilities(ShadowPolicy(ShadowPolicyStatus.UNKNOWN), None)
    assert capabilities.assist_enabled is False
    assert "console" in capabilities.reason.lower()


def test_unknown_policy_leaves_assist_available_but_never_no_consent():
    capabilities = policy_capabilities(ShadowPolicy(ShadowPolicyStatus.UNKNOWN), CONSOLE)
    assert capabilities.assist_enabled is True
    assert capabilities.full_control_enabled is True
    assert capabilities.no_consent_enabled is False


def test_view_only_policy_disables_full_control_control():
    policy = ShadowPolicy(ShadowPolicyStatus.DETECTED, view_only=True, is_conclusive=True)
    capabilities = policy_capabilities(policy, CONSOLE)
    assert capabilities.assist_enabled is True
    assert capabilities.full_control_enabled is False
    assert capabilities.view_only_enabled is True


def test_disabled_policy_disables_assistance():
    policy = ShadowPolicy(ShadowPolicyStatus.DETECTED, is_conclusive=True)
    capabilities = policy_capabilities(policy, CONSOLE)
    assert capabilities.assist_enabled is False
    assert capabilities.no_consent_enabled is False


class FakeTerminalServices:
    sessions: tuple[Session, ...] = (CONSOLE,)
    error: Exception | None = None

    def __init__(self, target, credentials, diagnostics):
        self.target = target
        self.credentials = credentials
        self.diagnostics = diagnostics
        self.smb = object()
        self.last_stage = "SMB"

    def __enter__(self):
        if self.error:
            raise self.error
        return self

    def __exit__(self, *_):
        return None

    def enumerate_sessions(self):
        self.last_stage = "SessionEnumeration"
        return list(self.sessions)


def configured_controller(monkeypatch, *, sessions=(CONSOLE,), error=None):
    FakeTerminalServices.sessions = sessions
    FakeTerminalServices.error = error
    controller = BackendController()
    credentials = Credentials("administrator", "EXAMPLE.ORG", None, AuthenticationMode.KERBEROS)
    monkeypatch.setattr(controller, "credentials", lambda progress: (credentials, ("administrator", "EXAMPLE.ORG")))
    monkeypatch.setattr(controller_module, "TerminalServicesService", FakeTerminalServices)
    monkeypatch.setattr(controller_module, "resolve_host", lambda target, **_kwargs: ("teacher-pc.example.org", "192.0.2.12"))
    monkeypatch.setattr(controller_module, "check_tcp", lambda host, port: TcpCheck(host, port, True))
    monkeypatch.setattr(
        controller_module, "ShadowPolicyService",
        lambda *_args: SimpleNamespace(query=lambda: ShadowPolicy(ShadowPolicyStatus.NOT_CONFIGURED)),
    )
    monkeypatch.setattr(controller_module, "detect_freerdp", lambda: SimpleNamespace(executable="xfreerdp3", version="3.0"))
    return controller


def test_successful_machine_check_returns_structured_stages(monkeypatch):
    controller = configured_controller(monkeypatch)
    progress = []

    result = controller.check("teacher-pc", lambda stage, message, detail=None: progress.append((stage, message, detail)))

    assert result.succeeded
    assert result.target == "teacher-pc.example.org"
    assert result.address == "192.0.2.12"
    assert result.console == CONSOLE
    assert {stage.name for stage in result.stages} >= {
        "ResolveHost", "Kerberos", "SMB", "TerminalServices", "SessionEnumeration", "ShadowPolicy", "RdpAvailability",
    }
    assert progress


def test_no_console_machine_check_is_a_successful_result(monkeypatch):
    controller = configured_controller(monkeypatch, sessions=())

    result = controller.check("teacher-pc.example.org", lambda *_args: None)

    assert result.succeeded
    assert result.console is None
    assert result.sessions == ()


def test_backend_exception_becomes_a_failure_result(monkeypatch):
    controller = configured_controller(monkeypatch, error=AssistanceError("SMB authentication failed: STATUS_LOGON_FAILURE"))

    result = controller.check("teacher-pc", lambda *_args: None)

    assert not result.succeeded
    assert result.failure_stage == "SMB"
    assert result.failure_message == "Domain authentication failed"
    assert result.debug_trace and "STATUS_LOGON_FAILURE" in result.debug_trace


@pytest.mark.parametrize("entered", ["teacher-pc", "teacher-pc.example.org"])
def test_short_and_fqdn_targets_preserve_canonical_hostname(monkeypatch, entered):
    controller = configured_controller(monkeypatch)
    seen = []

    def resolve(target, **_kwargs):
        seen.append(target)
        return "teacher-pc.example.org", "192.0.2.12"

    monkeypatch.setattr(controller_module, "resolve_host", resolve)
    result = controller.check(entered, lambda *_args: None)

    assert seen == [entered]
    assert result.target == "teacher-pc.example.org"
    assert result.requested_target == entered


def test_dns_timeout_becomes_a_presentable_failure(monkeypatch):
    controller = configured_controller(monkeypatch)
    monkeypatch.setattr(controller_module, "resolve_host", lambda _target, **_kwargs: (_ for _ in ()).throw(FutureTimeout()))

    result = controller.check("teacher-pc", lambda *_args: None)

    assert not result.succeeded
    assert result.failure_stage == "ResolveHost"
    assert result.address is None
