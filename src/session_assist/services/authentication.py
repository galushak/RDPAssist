"""Safe integration with the workstation's shared Kerberos credential cache."""

from __future__ import annotations

import getpass
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from session_assist.models import AuthenticationMode, Credentials


# A deployment may opt in to a default realm. Otherwise the normal Kerberos
# cache provides the realm; no organization-specific realm belongs in source.
DEFAULT_REALM = os.environ.get("REMOTE_CONTROL_KERBEROS_REALM", "").upper()
KLIST_TIMEOUT_SECONDS = 5.0
KINIT_TIMEOUT_SECONDS = 20.0
_DEFAULT_PRINCIPAL = re.compile(r"^Default principal:\s*(?P<user>[^@\s]+)@(?P<realm>[^\s]+)", re.MULTILINE)
_TICKET_CACHE = re.compile(r"^Ticket cache:\s*(?P<cache>.+)$", re.MULTILINE)


class KerberosStatusKind(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    EXPIRED = "expired"
    INVALID = "invalid"
    ERROR = "error"


@dataclass(frozen=True)
class KerberosStatus:
    kind: KerberosStatusKind
    principal: tuple[str, str] | None = None
    expires_at: str | None = None
    friendly_message: str = ""
    detail: str | None = None

    @property
    def available(self) -> bool:
        return self.kind is KerberosStatusKind.AVAILABLE

    @property
    def realm(self) -> str | None:
        return self.principal[1] if self.principal else None


@dataclass(frozen=True)
class KerberosAcquireResult:
    success: bool
    status: KerberosStatus
    friendly_message: str
    detail: str | None = None


@dataclass(frozen=True)
class KerberosCacheStatus:
    """Compatibility projection used by the existing CLI/controller callers."""

    principal: tuple[str, str] | None
    available: bool
    reason: str | None = None


def parse_default_principal(output: str) -> tuple[str, str] | None:
    """Isolated parser for MIT Kerberos' non-secret default-principal field."""
    match = _DEFAULT_PRINCIPAL.search(output)
    if not match:
        return None
    return match.group("user"), match.group("realm").upper()


def cache_path_from_klist(output: str) -> str | None:
    """Return a FILE cache path suitable for Impacket, without exposing its contents."""
    match = _TICKET_CACHE.search(output)
    if not match:
        return None
    cache = match.group("cache").strip()
    if cache.upper().startswith("FILE:"):
        return cache[5:]
    return cache if cache.startswith("/") else None


def kerberos_cache_path() -> str | None:
    """Locate the active file-backed cache when KRB5CCNAME is not exported."""
    configured = os.environ.get("KRB5CCNAME", "")
    if configured:
        return configured[5:] if configured.upper().startswith("FILE:") else configured
    try:
        result = subprocess.run(["klist"], check=False, capture_output=True, text=True, timeout=KLIST_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cache_path_from_klist(result.stdout) if result.returncode == 0 else None


def _missing_or_expired(output: str) -> KerberosStatusKind:
    text = output.lower()
    if "expired" in text or "not yet valid" in text:
        return KerberosStatusKind.EXPIRED
    return KerberosStatusKind.MISSING


def _kinit_error(stderr: bytes) -> tuple[str, str]:
    """Map common errors without returning raw process text or secrets to the UI."""
    text = stderr.decode("utf-8", "replace").lower()
    if "client not found" in text or "principal unknown" in text:
        return "Unknown domain account", "Check the username and realm, then try again."
    if "cannot contact any kdc" in text or "cannot resolve" in text or "cannot find kdc" in text:
        return "Domain controller unavailable", "Connect to the domain network or VPN, then try again."
    if "clock skew" in text:
        return "System clock differs from the domain", "Synchronize this computer's clock, then try again."
    if "password has expired" in text:
        return "Domain password has expired", "Change the password through the approved domain process, then sign in again."
    if "password incorrect" in text or "preauthentication failed" in text or "password" in text and "incorrect" in text:
        return "Sign-in failed", "The username or password was not accepted by the domain."
    if "client revoked" in text or "locked" in text or "disabled" in text:
        return "Domain account is unavailable", "The account may be locked, disabled, or otherwise unavailable."
    return "Domain sign-in failed", "Kerberos could not obtain a ticket. Check domain connectivity and try again."


class KerberosService:
    """Read and refresh the normal per-user Kerberos cache without owning it."""

    def __init__(
        self,
        *,
        default_realm: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        klist_timeout: float = KLIST_TIMEOUT_SECONDS,
        kinit_timeout: float = KINIT_TIMEOUT_SECONDS,
    ) -> None:
        self.default_realm = (default_realm or DEFAULT_REALM).upper()
        self._runner = runner or subprocess.run
        self.klist_timeout = klist_timeout
        self.kinit_timeout = kinit_timeout

    def default_username(self, status: KerberosStatus | None = None) -> str:
        if status and status.principal:
            return status.principal[0]
        return getpass.getuser()

    def get_status(self) -> KerberosStatus:
        if shutil.which("klist") is None:
            return KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Kerberos tools are unavailable", detail="Install the krb5-user package.")
        try:
            listing = self._runner(["klist"], check=False, capture_output=True, timeout=self.klist_timeout)
        except subprocess.TimeoutExpired:
            return KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Kerberos status check timed out", detail="The credential cache could not be read within five seconds.")
        except OSError:
            return KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Kerberos status check failed", detail="The system Kerberos tools could not be started.")
        stdout = listing.stdout.encode("utf-8") if isinstance(listing.stdout, str) else (listing.stdout or b"")
        stderr = listing.stderr.encode("utf-8") if isinstance(getattr(listing, "stderr", b""), str) else (getattr(listing, "stderr", b"") or b"")
        output = stdout + b"\n" + stderr
        if listing.returncode != 0:
            kind = _missing_or_expired(output.decode("utf-8", "replace"))
            message = "Kerberos session expired" if kind is KerberosStatusKind.EXPIRED else "Sign-in required"
            return KerberosStatus(kind, friendly_message=message)
        principal = parse_default_principal(stdout.decode("utf-8", "replace"))
        if principal is None:
            return KerberosStatus(KerberosStatusKind.INVALID, friendly_message="Kerberos cache could not be read", detail="The cache did not report a default principal.")
        try:
            validity = self._runner(["klist", "-s"], check=False, capture_output=True, timeout=self.klist_timeout)
        except subprocess.TimeoutExpired:
            return KerberosStatus(KerberosStatusKind.ERROR, principal, friendly_message="Kerberos status check timed out", detail="Ticket validity could not be verified within five seconds.")
        except OSError:
            return KerberosStatus(KerberosStatusKind.ERROR, principal, friendly_message="Kerberos status check failed", detail="Ticket validity could not be verified.")
        if validity.returncode != 0:
            return KerberosStatus(KerberosStatusKind.EXPIRED, principal, friendly_message="Kerberos session expired")
        return KerberosStatus(KerberosStatusKind.AVAILABLE, principal, friendly_message="Authenticated")

    def acquire_credentials(self, username: str, realm: str, password: str) -> KerberosAcquireResult:
        """Run ``kinit principal`` with the password only on its standard input."""
        principal = f"{username.strip()}@{realm.strip().upper()}"
        if not username.strip() or not realm.strip():
            status = KerberosStatus(KerberosStatusKind.INVALID, friendly_message="Username and realm are required")
            return KerberosAcquireResult(False, status, status.friendly_message)
        if not password:
            status = KerberosStatus(KerberosStatusKind.INVALID, friendly_message="Password is required")
            return KerberosAcquireResult(False, status, status.friendly_message)
        if shutil.which("kinit") is None:
            status = KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Kerberos tools are unavailable", detail="Install the krb5-user package.")
            return KerberosAcquireResult(False, status, status.friendly_message, status.detail)
        payload = bytearray(password.encode("utf-8"))
        payload.append(10)
        password = ""  # Drop this reference before waiting for the child process.
        try:
            result = self._runner(
                ["kinit", principal], check=False, input=bytes(payload), capture_output=True, timeout=self.kinit_timeout
            )
        except subprocess.TimeoutExpired:
            status = KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Domain sign-in timed out", detail="The domain did not respond within twenty seconds.")
            return KerberosAcquireResult(False, status, status.friendly_message, status.detail)
        except OSError:
            status = KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Domain sign-in could not start")
            return KerberosAcquireResult(False, status, status.friendly_message)
        finally:
            for index in range(len(payload)):
                payload[index] = 0
        if result.returncode != 0:
            message, detail = _kinit_error(result.stderr or b"")
            status = KerberosStatus(KerberosStatusKind.ERROR, friendly_message=message, detail=detail)
            return KerberosAcquireResult(False, status, message, detail)
        status = self.get_status()
        if not status.available:
            message = status.friendly_message or "Domain sign-in did not create a usable ticket"
            return KerberosAcquireResult(False, status, message, status.detail)
        return KerberosAcquireResult(True, status, "Authenticated")


def kerberos_cache_status() -> KerberosCacheStatus:
    status = KerberosService().get_status()
    return KerberosCacheStatus(status.principal, status.available, None if status.available else status.friendly_message)


def kerberos_cache_principal() -> tuple[str, str] | None:
    return kerberos_cache_status().principal


def resolved_credentials(
    *, username: str | None, domain: str | None, password: str | None,
    mode: AuthenticationMode, kdc_host: str | None, dns_domain: str | None = None,
    cached_principal: tuple[str, str] | None = None,
) -> Credentials:
    """Fill omitted Kerberos identity fields from a valid credential cache only."""
    cached = cached_principal if mode is AuthenticationMode.KERBEROS else None
    if cached is None and mode is AuthenticationMode.KERBEROS:
        cached = kerberos_cache_principal()
    user = username or (cached[0] if cached else "")
    realm = domain or (cached[1] if cached else "")
    if not user or not realm:
        raise ValueError(
            "Kerberos needs --username and --domain, or a readable credential cache with a Default principal."
            if mode is AuthenticationMode.KERBEROS
            else "NTLM needs both --username and --domain."
        )
    return Credentials(user, realm.upper(), password, mode, kdc_host, dns_domain)
