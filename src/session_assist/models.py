"""Small, dependency-free data models shared by the Phase 1 services."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AuthenticationMode(str, Enum):
    KERBEROS = "kerberos"
    NTLM = "ntlm"


class ShadowControl(str, Enum):
    VIEW = "view"
    FULL_CONTROL = "control"


class AssistPermissionMode(str, Enum):
    AUTOMATIC = "auto"
    CONSENT = "consent"
    NO_CONSENT = "no-consent"


class ShadowPolicyStatus(str, Enum):
    DETECTED = "Detected"
    NOT_CONFIGURED = "NotConfigured"
    ACCESS_DENIED = "AccessDenied"
    UNAVAILABLE = "Unavailable"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class Credentials:
    username: str
    domain: str
    password: str | None
    mode: AuthenticationMode
    kdc_host: str | None = None
    # Kept distinct from the Kerberos realm: this is the DNS suffix used only
    # when a user entered an otherwise-unresolvable short computer name.
    dns_domain: str | None = None


@dataclass(frozen=True)
class Session:
    """An interactive Terminal Services session suitable for display/selection."""

    session_id: int
    username: str
    domain: str
    state: str
    session_name: str
    desktop_state: str = ""

    @property
    def account_name(self) -> str:
        if not self.username:
            return "(no logged-on user)"
        return f"{self.domain}\\{self.username}" if self.domain else self.username

    @property
    def connection_type(self) -> str:
        name = self.session_name.strip()
        if name.lower() == "console":
            return "Console"
        if name.lower().startswith("rdp"):
            return "RDP"
        return name or "Unknown"

    @property
    def is_console(self) -> bool:
        return self.session_name.strip().lower() == "console"

    @property
    def is_interactive(self) -> bool:
        return bool(self.username) and self.state.lower() in {"active", "connected", "disconnected"}

    @property
    def is_active_interactive(self) -> bool:
        return self.is_interactive and self.state.lower() == "active"

    @property
    def is_active_console(self) -> bool:
        return self.is_console and self.is_active_interactive


@dataclass(frozen=True)
class ShadowPolicy:
    status: ShadowPolicyStatus
    control_allowed: bool = False
    view_only: bool = False
    consent_required: bool = True
    friendly_name: str = "Policy unknown - user approval will be requested"
    is_conclusive: bool = False
    source: str = "ComputerPolicy"
    raw_value: int | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class AssistDecision:
    allowed: bool
    control: bool
    view_only: bool
    require_consent: bool
    native_no_consent: bool
    reason: str = ""


@dataclass(frozen=True)
class DirectoryComputer:
    hostname: str
    dns_hostname: str = ""
    description: str = ""

    @property
    def display_name(self) -> str:
        return self.hostname


@dataclass(frozen=True)
class DirectoryStatus:
    realm: str | None
    server: str | None
    search_base: str | None
    authenticated: bool = False
    error_message: str | None = None


class AssistanceError(RuntimeError):
    """An actionable error that must never trigger a normal-RDP fallback."""


class UserDeclinedError(AssistanceError):
    """The user declined an otherwise valid consent request."""
