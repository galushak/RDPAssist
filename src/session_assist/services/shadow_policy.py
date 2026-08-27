"""Read the target's RDS shadow policy through the native MS-RRP protocol."""

from __future__ import annotations

from typing import Any

from session_assist.models import ShadowPolicy, ShadowPolicyStatus


_KEY = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
_SOURCE = rf"ComputerPolicy (HKLM\{_KEY}\Shadow)"


def policy_from_value(value: int | None, *, source: str = _SOURCE) -> ShadowPolicy:
    """Translate the current TerminalServer.admx Shadow DWORD into a typed result."""
    values = {
        0: (False, False, True, "Remote control disabled"),
        1: (True, False, True, "Full Control with user approval"),
        2: (True, False, False, "Full Control without user approval"),
        3: (False, True, True, "View Only with user approval"),
        4: (False, True, False, "View Only without user approval"),
    }
    result = values.get(value)
    if result is None:
        return ShadowPolicy(
            ShadowPolicyStatus.UNKNOWN, friendly_name="Unrecognized policy value - user approval will be requested",
            source=source, raw_value=value, error_message="The Shadow DWORD is not one of the supported policy values.",
        )
    control_allowed, view_only, consent_required, friendly_name = result
    return ShadowPolicy(
        ShadowPolicyStatus.DETECTED, control_allowed, view_only, consent_required, friendly_name,
        True, source, value,
    )


def unavailable_policy(status: ShadowPolicyStatus, message: str, *, source: str = _SOURCE) -> ShadowPolicy:
    friendly = (
        "Policy not configured - user approval will be requested"
        if status is ShadowPolicyStatus.NOT_CONFIGURED
        else "Policy unavailable - user approval will be requested"
    )
    return ShadowPolicy(status, friendly_name=friendly, source=source, error_message=message)


class ShadowPolicyService:
    """A read-only MS-RRP client reusing the authenticated SMB session."""

    def __init__(self, target: str, smb: Any, kerberos: bool, kdc_host: str | None = None) -> None:
        self.target = target
        self.smb = smb
        self.kerberos = kerberos
        self.kdc_host = kdc_host

    def query(self) -> ShadowPolicy:
        try:
            from impacket.dcerpc.v5 import rrp, transport
        except ImportError as error:  # covered by the parent service's dependency check in normal use
            return unavailable_policy(ShadowPolicyStatus.UNKNOWN, f"Impacket is unavailable: {error}")
        dce = None
        key = None
        try:
            rpc_transport = transport.SMBTransport(
                self.target, filename=r"\winreg", smb_connection=self.smb,
                doKerberos=self.kerberos, kdcHost=self.kdc_host,
            )
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            root = rrp.hOpenLocalMachine(dce)["phKey"]
            key = rrp.hBaseRegOpenKey(dce, root, _KEY)["phkResult"]
            _, raw_value = rrp.hBaseRegQueryValue(dce, key, "Shadow")
            try:
                value = int(raw_value)
            except (TypeError, ValueError):
                return unavailable_policy(ShadowPolicyStatus.UNKNOWN, "The remote Shadow value was not a DWORD.")
            return policy_from_value(value)
        except Exception as error:
            message = str(error)
            upper = message.upper()
            if any(token in upper for token in ("OBJECT_NAME_NOT_FOUND", "FILE_NOT_FOUND", "STATUS_NO_SUCH")):
                return unavailable_policy(ShadowPolicyStatus.NOT_CONFIGURED, message)
            if any(token in upper for token in ("ACCESS_DENIED", "E_ACCESSDENIED")):
                return unavailable_policy(ShadowPolicyStatus.ACCESS_DENIED, message)
            if any(token in upper for token in ("RPC_S_SERVER_UNAVAILABLE", "STATUS_PIPE_NOT_AVAILABLE", "CONNECTION", "TIMED OUT")):
                return unavailable_policy(ShadowPolicyStatus.UNAVAILABLE, message)
            return unavailable_policy(ShadowPolicyStatus.UNKNOWN, message)
        finally:
            if key is not None:
                try:
                    rrp.hBaseRegCloseKey(dce, key)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass
