"""Human-safe diagnostics; credentials and invitation contents are never emitted."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TextIO


class Stage(str, Enum):
    OK = "ok"
    WAIT = "wait"
    ERROR = "error"
    INFO = "info"


@dataclass(frozen=True)
class Event:
    stage: Stage
    message: str
    detail: str | None = None


class Diagnostics:
    def __init__(self, stream: TextIO, *, verbose: bool = False) -> None:
        self.stream = stream
        self.verbose = verbose
        self.events: list[Event] = []
        self._step = 0

    def emit(self, stage: Stage, message: str, detail: str | None = None) -> None:
        event = Event(stage, message, detail)
        self.events.append(event)
        marker = {Stage.OK: "[ok]", Stage.WAIT: "[wait]", Stage.ERROR: "[error]", Stage.INFO: "[info]"}[stage]
        print(f"{marker} {message}", file=self.stream)
        if detail:
            print(f"       {detail}", file=self.stream)

    def ok(self, message: str, detail: str | None = None) -> None:
        self.emit(Stage.OK, message, detail)

    def wait(self, message: str, detail: str | None = None) -> None:
        self.emit(Stage.WAIT, message, detail)

    def error(self, message: str, detail: str | None = None) -> None:
        self.emit(Stage.ERROR, message, detail)

    def info(self, message: str, detail: str | None = None) -> None:
        self.emit(Stage.INFO, message, detail)

    def step(self, message: str) -> None:
        """Emit a numbered acceptance-test stage only when verbose logging is enabled."""
        self._step += 1
        if self.verbose:
            self.info(f"[{self._step}] {message}")


def explain_error(error: BaseException) -> tuple[str, str]:
    """Translate common MSRPC/SMB failures without exposing authentication data."""
    raw = str(error)
    upper = raw.upper()
    mappings = (
        ("KERBEROS KDC DISCOVERY FAILED", "Kerberos domain controller discovery failed", "No reachable Kerberos KDC was found through the configured AD DNS records."),
        ("CONFIGURED KERBEROS KDC", "Configured Kerberos domain controller is unavailable", "Check the configured KDC hostname and TCP port 88 connectivity."),
        ("SMB KERBEROS AUTHENTICATION FAILED", "SMB is reachable, but domain authentication failed", "Kerberos could not authenticate the SMB session; verify the CIFS service ticket and domain controller reachability."),
        ("SMB PROTOCOL NEGOTIATION FAILED", "SMB TCP is reachable, but SMB negotiation failed", "Check the target's SMB service and protocol policy."),
        ("TERMINAL SERVICES RPC FAILED", "Windows is reachable, but the Terminal Services management interface could not be accessed", "See the named-pipe and interface detail in Diagnostics."),
        ("SIGN-IN REQUIRED", "Kerberos credentials are unavailable", "Sign in through Remote Control or run `kinit`, then retry."),
        ("KERBEROS SESSION EXPIRED", "Kerberos credentials have expired", "Reauthenticate through Remote Control, then retry."),
        ("NO READABLE KERBEROS CREDENTIAL CACHE", "Kerberos credentials are unavailable", "Run `kinit` or use the KDE domain login, then retry."),
        ("`KLIST` IS NOT INSTALLED", "Kerberos client tools are unavailable", "Install the `krb5-user` package and obtain a ticket before retrying."),
        ("FREERDP WAS NOT FOUND", "FreeRDP is unavailable", "Install `freerdp3-x11` on this Debian 13 workstation before retrying."),
        ("USER DECLINED", "The Windows user declined the assistance request", "No Remote Assistance client was launched."),
        ("SESSION SHADOWING IS DISABLED", "Windows Group Policy disabled session shadowing", "Configure the target policy for full control with the user's permission."),
        ("VIEW-ONLY", "Windows Group Policy does not allow the requested control mode", "Configure full control with the user's permission, or retry later with view-only."),
        ("RPC_S_SERVER_UNAVAILABLE", "Terminal Services RPC is unavailable", "Confirm RPC/firewall access and that Remote Desktop Services is running."),
        ("0X6BA", "Terminal Services RPC is unavailable", "RPC_S_SERVER_UNAVAILABLE: check host reachability and firewall rules."),
        ("STATUS_LOGON_FAILURE", "Domain authentication failed", "Check the selected account, Kerberos ticket, or password."),
        ("STATUS_ACCESS_DENIED", "Access was denied", "The administrator account may lack WINSTATION_SHADOW permission."),
        ("E_ACCESSDENIED", "Access was denied", "The administrator account may lack WINSTATION_SHADOW permission."),
        ("KRB_AP_ERR", "Kerberos authentication failed", "Verify DNS/SPN names, ticket validity, and the selected domain."),
        ("CONNECTION REFUSED", "The target refused the connection", "Confirm SMB/RPC services and firewall policy on the Windows host."),
    )
    for needle, message, detail in mappings:
        if needle in upper:
            return message, detail
    return "The Terminal Services operation failed", raw or type(error).__name__
