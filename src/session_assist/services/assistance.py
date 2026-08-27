"""Consent-only MS-TSTS RpcShadow2 request and invitation handling."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from session_assist.diagnostics import Diagnostics
from session_assist.models import (
    AssistDecision,
    AssistPermissionMode,
    AssistanceError,
    ShadowControl,
    ShadowPolicy,
    ShadowPolicyStatus,
    UserDeclinedError,
)
from session_assist.services.terminal_services import TerminalServicesService


_RESPONSE_MESSAGES = {
    1: ("The Windows user declined the assistance request.", UserDeclinedError),
    2: ("Group Policy requires user approval. This tool already requested consent; verify the target policy and retry.", AssistanceError),
    3: ("Session shadowing is disabled by Group Policy on this computer.", AssistanceError),
    4: ("Group Policy allows view-only shadowing only; full control cannot be granted.", AssistanceError),
    5: ("Group Policy permits view-only shadowing with user approval only.", AssistanceError),
    6: ("This session is already being controlled by another shadow connection.", AssistanceError),
}


class AssistanceService:
    def __init__(self, terminal_services: TerminalServicesService, diagnostics: Diagnostics) -> None:
        self.terminal_services = terminal_services
        self.diagnostics = diagnostics

    def request_invitation(self, session_id: int, decision: AssistDecision) -> str:
        """Ask Windows to shadow a session using the already policy-resolved mode."""
        tsts: Any = self.terminal_services._tsts
        smb: Any = self.terminal_services._smb
        if tsts is None or smb is None:
            raise AssistanceError("Terminal Services connection is not open.")
        request_control = (
            tsts.SHADOW_CONTROL_REQUEST.enumItems.SHADOW_CONTROL_REQUEST_TAKECONTROL
            if decision.control
            else tsts.SHADOW_CONTROL_REQUEST.enumItems.SHADOW_CONTROL_REQUEST_VIEW
        )
        request_permission = (
            tsts.SHADOW_PERMISSION_REQUEST.enumItems.SHADOW_PERMISSION_REQUEST_REQUESTPERMISSION
            if decision.require_consent
            else tsts.SHADOW_PERMISSION_REQUEST.enumItems.SHADOW_PERMISSION_REQUEST_SILENT
        )
        self.diagnostics.step("Binding SessEnvPublicRpc...")
        self.diagnostics.step("Sending policy-compliant RpcShadow2 request...")
        if decision.require_consent:
            self.diagnostics.wait(
                "Waiting for the Windows user to approve the assistance request",
                f"Session {session_id}; {'control' if decision.control else 'view'}; consent required",
            )
        else:
            self.diagnostics.info(
                "Windows policy permits native no-prompt assistance",
                f"Session {session_id}; {'control' if decision.control else 'view'}",
            )
        try:
            with tsts.SessEnvPublicRpc(
                smb, self.terminal_services.target,
                self.terminal_services.credentials.mode.value == "kerberos",
            ) as rpc:
                response = rpc.hRpcShadow2(session_id, request_control, request_permission, 8192)
        except Exception as error:
            raise AssistanceError(f"RpcShadow2 failed: {error}") from error
        permission = response["pePermission"]
        if permission is None:
            raise AssistanceError("RpcShadow2 returned no consent decision; FreeRDP was not launched.")
        decision = int(permission.getData() if hasattr(permission, "getData") else permission)
        if decision != 0:
            message, error_type = _RESPONSE_MESSAGES.get(decision, (f"Windows returned unknown shadow decision {decision}.", AssistanceError))
            raise error_type(message)
        invitation = normalise_invitation(str(response["pszInvitation"]))
        self.diagnostics.ok(
            "User approved the request; Remote Assistance invitation received"
            if decision.require_consent
            else "Windows returned a policy-permitted no-prompt Remote Assistance invitation"
        )
        return invitation


def resolve_assist_mode(
    permission_mode: AssistPermissionMode | str,
    interaction: ShadowControl | str,
    policy: ShadowPolicy | None,
) -> AssistDecision:
    """Pure policy decision. Unknown registry state can never select silent shadowing."""
    mode = AssistPermissionMode(permission_mode)
    requested = ShadowControl(interaction)
    policy = policy or ShadowPolicy(ShadowPolicyStatus.UNKNOWN)
    control = requested is ShadowControl.FULL_CONTROL
    view_only = not control

    if policy.status is ShadowPolicyStatus.DETECTED and not policy.control_allowed and not policy.view_only:
        return AssistDecision(False, control, view_only, True, False, "Windows policy on this computer disables session shadowing.")
    if control and policy.status is ShadowPolicyStatus.DETECTED and policy.view_only:
        return AssistDecision(False, True, False, True, False, "Windows policy permits view-only assistance, not keyboard and mouse control.")

    if mode is AssistPermissionMode.CONSENT:
        return AssistDecision(True, control, view_only, True, False)
    if mode is AssistPermissionMode.NO_CONSENT:
        if policy.status is not ShadowPolicyStatus.DETECTED or policy.consent_required:
            return AssistDecision(False, control, view_only, True, False, "No-prompt assistance is unavailable until target policy conclusively permits it.")
        return AssistDecision(True, control, view_only, False, True)

    # Automatic deliberately chooses the safe prompt path unless the target itself says otherwise.
    if policy.status is ShadowPolicyStatus.DETECTED and not policy.consent_required:
        return AssistDecision(True, control, view_only, False, True)
    reason = "" if policy.status is ShadowPolicyStatus.DETECTED else "Policy could not be determined; user approval will be requested."
    return AssistDecision(True, control, view_only, True, False, reason)


def normalise_invitation(value: str) -> str:
    """Validate and trim a bounded NDR XML string without logging its sensitive contents."""
    candidate = value.rstrip("\x00\r\n ").strip()
    if not candidate.endswith(">") and "</E>" in candidate:
        candidate = candidate[: candidate.rfind("</E>") + len("</E>")]
    try:
        root = ElementTree.fromstring(candidate)
    except ElementTree.ParseError as error:
        raise AssistanceError("RpcShadow2 returned an invalid Remote Assistance invitation; FreeRDP was not launched.") from error
    if root.tag != "E":
        raise AssistanceError("RpcShadow2 returned an unexpected invitation document; FreeRDP was not launched.")
    return ElementTree.tostring(root, encoding="unicode")


def write_private_invitation(invitation: str, path: Path) -> Path:
    """Persist an invitation with owner-only permissions for the child process."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # O_EXCL prevents replacement; permissions are set before data is written.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(invitation)
    return path
