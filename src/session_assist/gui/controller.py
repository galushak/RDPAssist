"""GUI-independent orchestration and UI capability mapping.

All methods here are synchronous by design; Qt executes them in workers.
They call the existing Phase 1 services and contain no terminal-services or
shadow-policy protocol implementation.
"""

from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
import logging
from types import SimpleNamespace
from typing import Callable

from session_assist.cli import selected_session_id
from session_assist.diagnostics import Diagnostics, Stage, explain_error
from session_assist.models import AssistDecision, AssistPermissionMode, AssistanceError, AuthenticationMode, Credentials, DirectoryComputer, DirectoryStatus, Session, ShadowControl, ShadowPolicy, ShadowPolicyStatus
from session_assist.services.assistance import AssistanceService, resolve_assist_mode
from session_assist.services.authentication import KerberosService, kerberos_cache_status, resolved_credentials
from session_assist.services.network import check_tcp, resolve_target_hostname
from session_assist.services.directory import DirectoryService
from session_assist.services.rdp import FreeRDPClient, detect_freerdp
from session_assist.services.shadow_policy import ShadowPolicyService
from session_assist.services.terminal_services import TerminalServicesService, validate_target


Progress = Callable[[Stage, str, str | None], None]
LOGGER = logging.getLogger(__name__)
DNS_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class CheckStage:
    """One bounded, user-safe step of a computer check."""

    name: str
    status: Stage
    message: str
    detail: str | None = None


def resolve_host(
    target: str, timeout: float = DNS_TIMEOUT_SECONDS, *, realm: str | None = None, dns_domain: str | None = None,
) -> tuple[str, str]:
    """Resolve a target without allowing a stalled resolver to block a check forever."""
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="remote-control-dns")
    future = executor.submit(resolve_target_hostname, target, realm=realm, dns_domain=dns_domain)
    try:
        addresses = future.result(timeout=timeout)
    finally:
        # Resolver calls cannot be cancelled once the libc call begins.  Do not
        # wait for a delayed resolver after the user-visible timeout expires.
        executor.shutdown(wait=False, cancel_futures=True)
    return addresses.hostname, addresses.address


class CallbackDiagnostics(Diagnostics):
    def __init__(self, progress: Progress, *, verbose: bool = False) -> None:
        import io
        super().__init__(io.StringIO(), verbose=verbose)
        self._progress = progress

    def emit(self, stage: Stage, message: str, detail: str | None = None) -> None:
        super().emit(stage, message, detail)
        self._progress(stage, message, detail)


@dataclass(frozen=True)
class CheckResult:
    target: str
    address: str | None
    smb_reachable: bool
    rdp_reachable: bool
    kerberos_principal: tuple[str, str] | None
    sessions: tuple[Session, ...]
    policy: ShadowPolicy
    freerdp: FreeRDPClient | None
    stages: tuple[CheckStage, ...] = ()
    requested_target: str | None = None
    failure_stage: str | None = None
    failure_message: str | None = None
    failure_detail: str | None = None
    debug_trace: str | None = None

    @property
    def console(self) -> Session | None:
        matches = [session for session in self.sessions if session.is_active_console]
        return matches[0] if len(matches) == 1 else None

    @property
    def succeeded(self) -> bool:
        return self.failure_message is None


@dataclass(frozen=True)
class UiCapabilities:
    assist_enabled: bool
    full_control_enabled: bool
    view_only_enabled: bool
    no_consent_enabled: bool
    reason: str = ""


def policy_capabilities(policy: ShadowPolicy | None, console: Session | None) -> UiCapabilities:
    """Translate backend policy state to controls; resolve_assist_mode remains authoritative."""
    if console is None:
        return UiCapabilities(False, False, False, False, "No active physical console user.")
    if policy is None:
        return UiCapabilities(True, True, True, False, "Policy unknown; approval will be requested.")
    if policy.status is ShadowPolicyStatus.DETECTED and not policy.control_allowed and not policy.view_only:
        return UiCapabilities(False, False, False, False, "Remote assistance is disabled by Windows policy.")
    return UiCapabilities(
        True,
        not (policy.status is ShadowPolicyStatus.DETECTED and policy.view_only),
        True,
        policy.status is ShadowPolicyStatus.DETECTED and not policy.consent_required,
        "" if policy.is_conclusive else "Policy unknown; approval will be requested.",
    )


class BackendController:
    """Thin GUI adapter over Phase 1 authentication, TS, policy, and assist services."""

    def __init__(self, *, auth_mode: AuthenticationMode = AuthenticationMode.KERBEROS, username: str | None = None, domain: str | None = None, kdc_host: str | None = None, ldap_server: str | None = None, ldap_search_base: str | None = None, kerberos_service: KerberosService | None = None) -> None:
        self.auth_mode = auth_mode
        self.username = username
        self.domain = domain
        self.kdc_host = kdc_host
        self.ldap_server = ldap_server
        self.ldap_search_base = ldap_search_base
        self.kerberos_service = kerberos_service or KerberosService(default_realm=domain)

    def credentials(self, progress: Progress) -> tuple[Credentials, tuple[str, str] | None]:
        principal: tuple[str, str] | None = None
        if self.auth_mode is AuthenticationMode.KERBEROS:
            status = self.kerberos_service.get_status()
            if not status.available or status.principal is None:
                raise AssistanceError(status.friendly_message or "Kerberos credentials are unavailable.")
            principal = status.principal
            progress(Stage.OK, "Kerberos credentials available", f"{principal[0]}@{principal[1]}")
        credentials = resolved_credentials(
            username=self.username, domain=self.domain, password=None, mode=self.auth_mode,
            kdc_host=self.kdc_host, cached_principal=principal,
        )
        return credentials, principal

    def check(self, target_input: str, progress: Progress) -> CheckResult:
        """Return a presentable result for expected check failures.

        This method deliberately turns expected network/authentication failures into
        data.  That lets the Qt completion slot reset the UI and explain which
        machine-check phase failed, while unexpected worker failures still retain a
        traceback through ``TaskWorker.failed``.
        """
        stages: list[CheckStage] = []
        requested_target = target_input.strip()
        target = requested_target
        address: str | None = None
        principal: tuple[str, str] | None = None
        smb_reachable = False
        rdp_reachable = False
        sessions: tuple[Session, ...] = ()
        policy = ShadowPolicy(ShadowPolicyStatus.UNKNOWN)
        freerdp: FreeRDPClient | None = None
        current_stage = "ValidateTarget"

        def record(name: str, status: Stage, message: str, detail: str | None = None) -> None:
            stages.append(CheckStage(name, status, message, detail))
            progress(status, message, detail)

        def failed(error: BaseException, *, stage: str = current_stage) -> CheckResult:
            if stage == "ValidateTarget":
                message, detail = "Invalid computer name", str(error)
            elif stage == "ResolveHost":
                if isinstance(error, FutureTimeout):
                    message, detail = "Host resolution timed out", "DNS did not respond within five seconds."
                else:
                    message, detail = "Host not found", "DNS could not resolve the computer name."
            else:
                message, detail = explain_error(error)
            debug_trace = traceback.format_exc()
            LOGGER.exception("Computer check failed at %s for %s", stage, requested_target)
            record(stage, Stage.ERROR, message, detail)
            return CheckResult(
                target, address, smb_reachable, rdp_reachable, principal, sessions, policy, freerdp,
                tuple(stages), requested_target, stage, message, detail, debug_trace,
            )

        try:
            target = validate_target(target_input)
        except (ValueError, AssistanceError) as error:
            return failed(error, stage=current_stage)

        current_stage = "Kerberos"
        record(current_stage, Stage.WAIT, "Checking Kerberos credentials")
        try:
            credentials, principal = self.credentials(lambda status, message, detail=None: record("Kerberos", status, message, detail))
        except (AssistanceError, ValueError) as error:
            return failed(error, stage=current_stage)

        current_stage = "ResolveHost"
        record(current_stage, Stage.WAIT, "Resolving host", target)
        try:
            target, address = resolve_host(target, realm=credentials.domain, dns_domain=credentials.dns_domain)
        except FutureTimeout as error:
            return failed(error, stage=current_stage)
        except OSError as error:
            return failed(AssistanceError(f"Computer not found: {error}"), stage=current_stage)
        record(current_stage, Stage.OK, "Hostname resolved", f"{target} → {address}")

        current_stage = "SMB"
        smb = check_tcp(target, 445)
        smb_reachable = smb.reachable
        record(current_stage, Stage.OK if smb.reachable else Stage.ERROR,
               "SMB reachable" if smb.reachable else "SMB not reachable", None if smb.reachable else smb.detail)

        current_stage = "RdpAvailability"
        rdp = check_tcp(target, 3389)
        rdp_reachable = rdp.reachable
        record(current_stage, Stage.OK if rdp.reachable else Stage.ERROR,
               "RDP reachable" if rdp.reachable else "RDP not reachable", None if rdp.reachable else rdp.detail)

        diagnostics = CallbackDiagnostics(progress)
        terminal_services = TerminalServicesService(target, credentials, diagnostics)
        current_stage = "TerminalServices"
        record(current_stage, Stage.WAIT, "Connecting to Windows management services")
        try:
            with terminal_services:
                record("SMB", Stage.OK, "SMB authentication succeeded")
                current_stage = "SessionEnumeration"
                sessions = tuple(terminal_services.enumerate_sessions())
                record("TerminalServices", Stage.OK, "Terminal Services RPC endpoint accessible")
                record(current_stage, Stage.OK, f"Interactive sessions enumerated: {len(sessions)}")
                current_stage = "ShadowPolicy"
                record(current_stage, Stage.WAIT, "Reading Remote Assistance policy")
                policy = ShadowPolicyService(
                    target, terminal_services.smb, credentials.mode is AuthenticationMode.KERBEROS,
                    getattr(terminal_services, "kdc_host", credentials.kdc_host),
                ).query()
        except AssistanceError as error:
            service_stage = getattr(terminal_services, "last_stage", current_stage)
            return failed(error, stage=service_stage)
        record("ShadowPolicy", Stage.OK if policy.is_conclusive else Stage.ERROR, "Remote Assistance policy", policy.friendly_name)

        current_stage = "RdpClient"
        try:
            freerdp = detect_freerdp()
            record(current_stage, Stage.OK, "FreeRDP detected", f"{freerdp.executable} ({freerdp.version})")
        except AssistanceError as error:
            record(current_stage, Stage.ERROR, "FreeRDP unavailable", str(error))
        return CheckResult(
            target, address, smb_reachable, rdp_reachable, principal, sessions, policy, freerdp,
            tuple(stages), requested_target,
        )

    def request_assistance(
        self, target_input: str, session_id: int | None, permission: AssistPermissionMode,
        interaction: ShadowControl, progress: Progress,
    ) -> tuple[str, CheckResult, AssistDecision]:
        result = self.check(target_input, progress)
        if not result.succeeded:
            raise AssistanceError(result.failure_message or "Computer check did not complete.")
        args = SimpleNamespace(session=session_id)
        selected = selected_session_id(args, list(result.sessions))
        decision = resolve_assist_mode(permission, interaction, result.policy)
        if not decision.allowed:
            raise AssistanceError(decision.reason)
        if result.freerdp is None:
            raise AssistanceError("FreeRDP is not installed; assistance was not requested.")
        progress(Stage.OK, "Windows policy evaluated", result.policy.friendly_name)
        with TerminalServicesService(result.target, self.credentials(progress)[0], CallbackDiagnostics(progress)) as terminal_services:
            invitation = AssistanceService(terminal_services, CallbackDiagnostics(progress)).request_invitation(selected, decision)
        return invitation, result, decision

    def directory_status(self, progress: Progress) -> DirectoryStatus:
        credentials, _principal = self.credentials(progress)
        status = DirectoryService(credentials, ldap_server=self.ldap_server, search_base=self.ldap_search_base).status()
        if status.authenticated:
            progress(Stage.OK, "Active Directory available", f"{status.server} • {status.search_base}")
        else:
            progress(Stage.ERROR, "Active Directory unavailable", status.error_message)
        return status

    def search_directory(self, query: str, progress: Progress) -> tuple[DirectoryStatus, list[DirectoryComputer]]:
        credentials, _principal = self.credentials(progress)
        status, results = DirectoryService(credentials, ldap_server=self.ldap_server, search_base=self.ldap_search_base).search_computers(query)
        if status.authenticated:
            progress(Stage.OK, "Directory search complete", f"{len(results)} computer result(s)")
        else:
            progress(Stage.ERROR, "Directory search unavailable", status.error_message)
        return status, results

    def test_directory(self, progress: Progress) -> DirectoryStatus:
        credentials, _principal = self.credentials(progress)
        status = DirectoryService(credentials, ldap_server=self.ldap_server, search_base=self.ldap_search_base).test_search()
        if status.authenticated and not status.error_message:
            progress(Stage.OK, "Active Directory test search", f"{status.server} • {status.search_base}")
        else:
            progress(Stage.ERROR, "Active Directory test search", status.error_message)
        return status
