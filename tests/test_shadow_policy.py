from session_assist.models import ShadowPolicyStatus
from session_assist.services.shadow_policy import policy_from_value


def test_all_authoritative_shadow_values_are_mapped():
    expected = {
        0: (False, False, True, "disabled"),
        1: (True, False, True, "Full Control with user approval"),
        2: (True, False, False, "Full Control without user approval"),
        3: (False, True, True, "View Only with user approval"),
        4: (False, True, False, "View Only without user approval"),
    }
    for raw, (control, view, consent, fragment) in expected.items():
        policy = policy_from_value(raw)
        assert policy.status is ShadowPolicyStatus.DETECTED
        assert (policy.control_allowed, policy.view_only, policy.consent_required) == (control, view, consent)
        assert fragment in policy.friendly_name


def test_unknown_policy_value_is_not_conclusive():
    policy = policy_from_value(99)
    assert policy.status is ShadowPolicyStatus.UNKNOWN
    assert policy.is_conclusive is False
    assert policy.consent_required is True
