import pytest
import stat

from session_assist.models import AssistanceError, Session
from session_assist.models import AssistPermissionMode, ShadowControl, ShadowPolicy, ShadowPolicyStatus
from session_assist.services.assistance import normalise_invitation, resolve_assist_mode, write_private_invitation
from session_assist.cli import selected_session_id


def test_invitation_trims_nul_padding():
    assert normalise_invitation("<E><C /></E>\x00\r\n") == "<E><C /></E>"


def test_invalid_invitation_does_not_pass_to_freerdp():
    with pytest.raises(AssistanceError, match="invalid"):
        normalise_invitation("this is not XML")


def test_unexpected_xml_does_not_pass_to_freerdp():
    with pytest.raises(AssistanceError, match="unexpected"):
        normalise_invitation("<UPLOADINFO />")


def test_invitation_is_owner_only_and_not_overwritten(tmp_path):
    path = tmp_path / "request.msrcIncident"
    write_private_invitation("<E><A /><C /></E>", path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_private_invitation("<E><A /><C /></E>", path)


def test_active_selection_requires_exactly_one_session():
    class Arguments:
        session = None
        active = True

    sessions = [Session(2, "jsmith", "WCSD", "Active", "Console")]
    assert selected_session_id(Arguments(), sessions) == 2


def test_explicit_inactive_session_is_rejected():
    class Arguments:
        session = 4
        active = False

    sessions = [Session(4, "admin", "WCSD", "Disconnected", "RDP-Tcp")]
    with pytest.raises(AssistanceError, match="not an active"):
        selected_session_id(Arguments(), sessions)


def test_automatic_unknown_policy_safely_requests_consent():
    decision = resolve_assist_mode(AssistPermissionMode.AUTOMATIC, ShadowControl.FULL_CONTROL, ShadowPolicy(ShadowPolicyStatus.UNKNOWN))
    assert decision.allowed is True
    assert decision.require_consent is True
    assert decision.native_no_consent is False


def test_explicit_no_consent_requires_conclusive_no_consent_policy():
    decision = resolve_assist_mode(AssistPermissionMode.NO_CONSENT, ShadowControl.FULL_CONTROL, ShadowPolicy(ShadowPolicyStatus.ACCESS_DENIED))
    assert decision.allowed is False
    assert "conclusively" in decision.reason


def test_automatic_uses_native_no_consent_only_when_detected_policy_permits_it():
    policy = ShadowPolicy(ShadowPolicyStatus.DETECTED, control_allowed=True, consent_required=False, is_conclusive=True)
    decision = resolve_assist_mode(AssistPermissionMode.AUTOMATIC, ShadowControl.FULL_CONTROL, policy)
    assert decision.allowed is True
    assert decision.require_consent is False
    assert decision.native_no_consent is True


def test_view_only_policy_rejects_requested_full_control():
    policy = ShadowPolicy(ShadowPolicyStatus.DETECTED, view_only=True, consent_required=True, is_conclusive=True)
    decision = resolve_assist_mode(AssistPermissionMode.AUTOMATIC, ShadowControl.FULL_CONTROL, policy)
    assert decision.allowed is False
