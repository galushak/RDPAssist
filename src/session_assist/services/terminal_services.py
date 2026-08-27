"""Impacket-backed SMB/MSRPC Terminal Services session enumeration.

This uses the same public classes as current upstream `examples/tstool.py`:
TermSrvEnumeration for the list and TermSrvSession for account/session details.
"""

from __future__ import annotations

import ipaddress
import os
import re
from importlib import metadata
from typing import Any

from session_assist.diagnostics import Diagnostics
from session_assist.models import AssistanceError, AuthenticationMode, Credentials, Session
from session_assist.services.authentication import kerberos_cache_path
from session_assist.services.network import check_tcp, discover_kdcs, resolve_target_hostname

WINDOWS_SERVICE_TIMEOUT_SECONDS = 10.0
TERMSRV_PIPE = r"\pipe\LSM_API_service"
TERMSRV_ENUMERATION_UUID = "88143fd0-c28d-4b2b-8fef-8d882f6a9390 v1.0"
TERMSRV_SESSION_UUID = "484809d6-4239-471b-b5bc-61df8c23ac48 v1.0"


class TerminalServicesService:
    def __init__(
        self, target: str, credentials: Credentials, diagnostics: Diagnostics,
        timeout: float = WINDOWS_SERVICE_TIMEOUT_SECONDS,
    ) -> None:
        self.target = target
        self.credentials = credentials
        self.diagnostics = diagnostics
        self.timeout = timeout
        self.last_stage = "ResolveHost"
        self.remote_host = target
        self.kdc_host: str | None = None
        self._previous_krb5ccname: str | None = None
        self._configured_krb5ccname = False
        self._smb: Any | None = None
        self._tsts: Any | None = None

    @property
    def smb(self) -> Any:
        if self._smb is None:
            raise AssistanceError("SMB connection is not open.")
        return self._smb

    def __enter__(self) -> "TerminalServicesService":
        self._load_impacket()
        self.diagnostics.step("Resolving host...")
        self._resolve_target()
        self._configure_impacket_cache()
        self.last_stage = "KerberosKdc"
        self._resolve_kdc()
        self.diagnostics.step("Connecting SMB...")
        self._connect_smb()
        return self

    def __exit__(self, *_: object) -> None:
        if self._smb is not None:
            try:
                self._smb.logoff()
            except Exception:
                pass
        if self._configured_krb5ccname:
            if self._previous_krb5ccname is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = self._previous_krb5ccname

    def _load_impacket(self) -> None:
        try:
            from impacket.dcerpc.v5 import tsts
            from impacket.smbconnection import SMBConnection
        except ImportError as error:
            raise AssistanceError(
                "Impacket is not installed. Create the virtual environment and run `pip install -e '.[dev]'`."
            ) from error
        self._SMBConnection = SMBConnection
        self._tsts = tsts
        try:
            version = metadata.version("impacket")
        except metadata.PackageNotFoundError:
            version = "unknown"
        self.diagnostics.info("Impacket version", version)

    def _resolve_target(self) -> None:
        self.last_stage = "ResolveHost"
        try:
            resolved = resolve_target_hostname(
                self.target, realm=self.credentials.domain, dns_domain=self.credentials.dns_domain,
            )
        except OSError as error:
            raise AssistanceError(f"Could not resolve {self.target}: {error}") from error
        self.target = resolved.hostname
        self.remote_host = resolved.address
        self.diagnostics.ok(f"Host resolved: {self.target}", self.remote_host)

    def _resolve_kdc(self) -> None:
        """Select a reachable KDC hostname before Impacket requests a service ticket."""
        if self.credentials.mode is not AuthenticationMode.KERBEROS:
            return
        configured = (self.credentials.kdc_host or "").strip().rstrip(".")
        # A realm is not a host.  In particular, allowing None through to
        # Impacket makes it try the realm name as a KDC when no cached TGS exists.
        if configured and configured.casefold() != self.credentials.domain.casefold():
            try:
                resolved = resolve_target_hostname(configured)
            except OSError as error:
                raise AssistanceError(f"Configured Kerberos KDC {configured} could not be resolved: {error}") from error
            status = check_tcp(resolved.address, 88, timeout=self.timeout)
            if not status.reachable:
                raise AssistanceError(f"Configured Kerberos KDC {resolved.hostname}:88 is unreachable: {status.detail}")
            self.kdc_host = resolved.hostname
            self.diagnostics.ok("Kerberos KDC selected", f"realm: {self.credentials.domain}; host: {resolved.hostname}; address: {resolved.address}; port: 88; source: configured")
            return
        discovery = discover_kdcs(self.credentials.domain)
        for candidate in discovery.candidates:
            self.diagnostics.info(
                "Kerberos KDC candidate",
                f"realm: {candidate.realm}; host: {candidate.hostname}; address: {candidate.address}; "
                f"port: {candidate.port}; priority: {candidate.priority}; weight: {candidate.weight}; source: {candidate.source}; "
                f"TCP 88: {'reachable' if candidate.reachable else candidate.detail or 'unreachable'}",
            )
        if discovery.selected is None:
            detail = discovery.error or "No usable _kerberos SRV result was returned."
            raise AssistanceError(f"Kerberos KDC discovery failed for {self.credentials.domain}: {detail}")
        self.kdc_host = discovery.selected.hostname
        selected = discovery.selected
        self.diagnostics.ok(
            "Kerberos KDC selected",
            f"realm: {selected.realm}; host: {selected.hostname}; address: {selected.address}; port: {selected.port}; "
            f"priority: {selected.priority}; weight: {selected.weight}; source: {selected.source}",
        )

    def _configure_impacket_cache(self) -> None:
        if self.credentials.mode is not AuthenticationMode.KERBEROS:
            return
        cache_path = kerberos_cache_path()
        if not cache_path:
            return
        self._previous_krb5ccname = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = cache_path
        self._configured_krb5ccname = True
        self.diagnostics.info("Kerberos credential cache provided to Impacket", "file cache available")

    def _connect_smb(self) -> None:
        self.last_stage = "SMBNegotiation"
        try:
            self._smb = self._SMBConnection(self.target, self.remote_host, sess_port=445, timeout=self.timeout)
        except Exception as error:
            raise AssistanceError(f"SMB protocol negotiation failed: {error}") from error
        self.diagnostics.ok("SMB protocol negotiation succeeded", f"remoteName: {self.target}; remoteHost: {self.remote_host}")
        self.last_stage = "SMBAuthentication"
        try:
            if self.credentials.mode is AuthenticationMode.KERBEROS:
                self.diagnostics.step(f"Using CIFS service principal cifs/{self.target}@{self.credentials.domain}...")
                self._smb.kerberosLogin(
                    self.credentials.username, self.credentials.password or "", self.credentials.domain,
                    "", "", "", self.kdc_host, useCache=True,
                )
            else:
                self._smb.login(
                    self.credentials.username, self.credentials.password or "", self.credentials.domain, "", ""
                )
        except Exception as error:
            mode = "SMB Kerberos authentication failed" if self.credentials.mode is AuthenticationMode.KERBEROS else "SMB authentication failed"
            raise AssistanceError(f"{mode}: {error}") from error
        self.diagnostics.ok("SMB Kerberos authentication succeeded" if self.credentials.mode is AuthenticationMode.KERBEROS else "SMB authentication succeeded", "Kerberos" if self.credentials.mode is AuthenticationMode.KERBEROS else "NTLM")

    def enumerate_sessions(self) -> list[Session]:
        """Return only logged-on session records; service/listener sessions are omitted."""
        assert self._tsts is not None and self._smb is not None
        raw: dict[int, dict[str, Any]] = {}
        try:
            self.last_stage = "TerminalServicesRpc"
            self.diagnostics.info("Opening Terminal Services named pipe", TERMSRV_PIPE)
            self.diagnostics.info("Binding Terminal Services enumeration interface", TERMSRV_ENUMERATION_UUID)
            with self._tsts.TermSrvEnumeration(self._smb, self.target, self.credentials.mode is AuthenticationMode.KERBEROS) as lsm:
                handle = lsm.hRpcOpenEnum()
                self.diagnostics.ok("Terminal Services RPC endpoint accessible")
                try:
                    rows = lsm.hRpcGetEnumResult(handle, Level=1)["ppSessionEnumResult"]
                finally:
                    lsm.hRpcCloseEnum(handle)
            for item in rows:
                session = item["SessionInfo"]["SessionEnum_Level1"]
                state = self._tsts.enum2value(self._tsts.WINSTATIONSTATECLASS, session["State"]).split("_")[-1]
                raw[int(session["SessionId"])] = {
                    "session_name": clean_wchar(session["Name"]), "state": state, "username": "", "domain": "", "desktop_state": "",
                }
            self.diagnostics.info("Binding Terminal Services session interface", TERMSRV_SESSION_UUID)
            with self._tsts.TermSrvSession(self._smb, self.target, self.credentials.mode is AuthenticationMode.KERBEROS) as termsrv:
                self.last_stage = "SessionEnumeration"
                for session_id, record in raw.items():
                    info = termsrv.hRpcGetSessionInformationEx(session_id)["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]
                    record["username"] = clean_wchar(info["UserName"])
                    record["domain"] = clean_wchar(info["DomainName"])
                    record["desktop_state"] = self._tsts.enum2value(self._tsts.SESSIONFLAGS, info["SessionFlags"]).replace("WTS_SESSIONSTATE_", "")
        except Exception as error:
            endpoint = TERMSRV_ENUMERATION_UUID if self.last_stage == "TerminalServicesRpc" else TERMSRV_SESSION_UUID
            raise AssistanceError(f"Terminal Services RPC failed at {self.last_stage} (named pipe {TERMSRV_PIPE}; interface {endpoint}): {error}") from error
        sessions = [
            Session(session_id, r["username"], r["domain"], r["state"], r["session_name"], r["desktop_state"])
            for session_id, r in sorted(raw.items())
        ]
        useful = [session for session in sessions if session.is_interactive]
        self.diagnostics.ok(f"Interactive sessions enumerated: {len(useful)}")
        return useful


def clean_wchar(value: Any) -> str:
    """Convert Impacket WCHAR arrays to presentation-safe Python strings."""
    if hasattr(value, "getValue"):
        value = value.getValue()
    return str(value).split("\x00", 1)[0].strip()


_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)


def validate_target(value: str) -> str:
    """Accept a hostname/FQDN/IP literal; reject whitespace and non-network input."""
    candidate = value.strip()
    if not candidate or candidate != value:
        raise ValueError("target must be a hostname, FQDN, or IP address without surrounding whitespace")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if not _HOSTNAME.fullmatch(candidate):
        raise ValueError("target must be a hostname, FQDN, or IP address")
    return candidate.rstrip(".")
