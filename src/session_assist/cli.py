"""Development CLI for Remote Control's Linux backend."""

from __future__ import annotations

import argparse
import getpass
import sys
import tempfile
from pathlib import Path

from session_assist.diagnostics import Diagnostics, explain_error
from session_assist.models import AssistPermissionMode, AssistanceError, AuthenticationMode, ShadowControl
from session_assist.services.assistance import AssistanceService, resolve_assist_mode, write_private_invitation
from session_assist.services.authentication import kerberos_cache_status, resolved_credentials
from session_assist.services.network import check_tcp, resolve_target_hostname
from session_assist.services.rdp import detect_freerdp, launch_invitation, launch_normal_rdp
from session_assist.services.shadow_policy import ShadowPolicyService
from session_assist.services.terminal_services import TerminalServicesService, validate_target
from session_assist.storage import Storage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Remote Control for Linux: Windows RDP and existing-session assistance")
    parser.add_argument("target", help="Managed Windows hostname, FQDN, or IP address")
    parser.add_argument("--auth", choices=[mode.value for mode in AuthenticationMode], default="kerberos")
    parser.add_argument("--username", help="Domain username; defaults to Kerberos cache principal when possible")
    parser.add_argument("--domain", help="AD DNS realm/domain; defaults to Kerberos cache realm when possible")
    parser.add_argument("--kdc-host", help="Optional domain controller for Kerberos")
    parser.add_argument("--password-prompt", action="store_true", help="Prompt once for an NTLM password; never save it")
    parser.add_argument("--verbose", action="store_true", help="Show numbered, credential-safe live-test stages")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("diagnose", help="Run read-only reachability, session, policy, and client checks")
    sub.add_parser("sessions", help="Enumerate Windows interactive sessions")
    sub.add_parser("policy", help="Read the target computer's effective configured Shadow policy")
    sub.add_parser("rdp", help="Launch a separate normal RDP connection")
    favorite = sub.add_parser("favorite", help="Add, remove, or inspect this target in per-user favorites")
    favorite.add_argument("action", choices=("add", "remove", "show"))
    assist = sub.add_parser("assist", help="Attach to the active physical console; never falls back to normal RDP")
    assist.add_argument("--session", type=positive_session_id, help="Explicit active console Windows session ID")
    assist.add_argument("--permission", choices=[mode.value for mode in AssistPermissionMode], help="Override the saved permission mode")
    assist.add_argument("--interaction", choices=[control.value for control in ShadowControl], default="control")
    assist.add_argument("--view-only", action="store_true", help=argparse.SUPPRESS)
    assist.add_argument("--no-launch", action="store_true", help="Save validated invitation but do not launch FreeRDP")
    assist.add_argument("--invitation-file", type=Path, help="Optional new .msrcIncident output path (must not already exist)")
    return parser


def positive_session_id(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("session ID must be positive")
    return parsed


def print_sessions(sessions: list) -> None:
    if not sessions:
        print("No logged-on interactive sessions were found.")
        return
    print(f"{'ID':<5} {'ACCOUNT':<30} {'STATE':<14} {'TYPE':<16} {'CONSOLE':<8} DESKTOP")
    for session in sessions:
        console = "yes" if session.is_console else "no"
        print(f"{session.session_id:<5} {session.account_name:<30} {session.state:<14} {session.connection_type:<16} {console:<8} {session.desktop_state}")


def selected_session_id(args: argparse.Namespace, sessions: list) -> int:
    """Choose only the active physical console; an explicit ID does not widen that scope."""
    if getattr(args, "session", None) is not None:
        match = next((session for session in sessions if session.session_id == args.session), None)
        if match is None:
            raise AssistanceError(f"Session {args.session} is not a logged-on interactive session; no shadow request was made.")
        if not match.is_active_console:
            raise AssistanceError(f"Session {args.session} is not an active physical console session; no shadow request was made.")
        return args.session
    active_console = [session for session in sessions if session.is_active_console]
    if len(active_console) != 1:
        raise AssistanceError(
            f"Assist requires exactly one active physical console session; found {len(active_console)}. "
            "Refresh after the user signs in locally."
        )
    return active_console[0].session_id


def _credentials(args: argparse.Namespace, diagnostics: Diagnostics):
    mode = AuthenticationMode(args.auth)
    cached_principal: tuple[str, str] | None = None
    if mode is AuthenticationMode.KERBEROS:
        diagnostics.step("Checking the Kerberos credential cache...")
        cache_status = kerberos_cache_status()
        if not cache_status.available or cache_status.principal is None:
            raise AssistanceError(cache_status.reason or "No usable Kerberos credential cache was found.")
        cached_principal = cache_status.principal
        diagnostics.ok("Kerberos credential cache found")
        diagnostics.ok("Kerberos principal detected", f"{cached_principal[0]}@{cached_principal[1]}")
    password = getpass.getpass("Domain password: ") if args.password_prompt else None
    if mode is AuthenticationMode.NTLM and password is None:
        raise AssistanceError("NTLM requires --password-prompt; passwords are intentionally not accepted as command-line arguments.")
    return resolved_credentials(
        username=args.username, domain=args.domain, password=password, mode=mode, kdc_host=args.kdc_host,
        cached_principal=cached_principal,
    )


def _report_policy(policy, diagnostics: Diagnostics) -> None:
    if policy.is_conclusive:
        diagnostics.ok("Shadow policy detected", policy.friendly_name)
    else:
        diagnostics.error("Shadow policy query", f"{policy.friendly_name}. Safe fallback: user approval required.")
    if policy.error_message and diagnostics.verbose:
        diagnostics.info("Shadow policy detail", policy.error_message)


def run(args: argparse.Namespace, diagnostics: Diagnostics, storage: Storage | None = None) -> int:
    target = validate_target(args.target)
    storage = storage or Storage()
    if args.command == "favorite":
        settings = storage.load_settings()
        if args.action == "add" and target.lower() not in {item.lower() for item in settings.favorites}:
            settings.favorites.append(target)
            storage.save_settings(settings)
            print(f"Added {target} to favorites.")
        elif args.action == "remove":
            settings.favorites = [item for item in settings.favorites if item.lower() != target.lower()]
            storage.save_settings(settings)
            print(f"Removed {target} from favorites.")
        else:
            print("Favorites:")
            for item in settings.favorites:
                print(item)
        return 0
    credentials = _credentials(args, diagnostics)
    diagnostics.step("Resolving target hostname...")
    try:
        resolved = resolve_target_hostname(target, realm=credentials.domain, dns_domain=credentials.dns_domain)
    except OSError as error:
        raise AssistanceError(f"Could not resolve {target}: {error}") from error
    target = resolved.hostname
    diagnostics.ok("Hostname resolved", f"{target} → {resolved.address}")
    saved_settings = storage.load_settings()
    requested_permission = getattr(args, "permission", None) or saved_settings.assist_permission_mode
    try:
        permission_mode = AssistPermissionMode(requested_permission)
    except ValueError:
        permission_mode = AssistPermissionMode.AUTOMATIC
    storage.remember(target, permission_mode.value)
    storage.log(f"{args.command} requested for {target}")

    if args.command == "rdp":
        diagnostics.step("Detecting FreeRDP...")
        client = detect_freerdp()
        diagnostics.ok("FreeRDP detected", f"{client.executable} ({client.version})")
        diagnostics.ok("Launching normal RDP (separate from Assist)", target)
        launch_normal_rdp(target, credentials, client)
        return 0

    if args.command == "diagnose":
        for label, port in (("SMB TCP", 445), ("RDP TCP", 3389)):
            status = check_tcp(target, port)
            if status.reachable:
                diagnostics.ok(f"{label} reachable")
            else:
                diagnostics.error(f"{label} not reachable", status.detail)

    with TerminalServicesService(target, credentials, diagnostics) as terminal_services:
        if args.command == "policy":
            policy = ShadowPolicyService(
                terminal_services.target, terminal_services.smb, credentials.mode is AuthenticationMode.KERBEROS, terminal_services.kdc_host
            ).query()
            _report_policy(policy, diagnostics)
            print(policy.friendly_name)
            return 0
        if args.command == "sessions":
            print_sessions(terminal_services.enumerate_sessions())
            return 0

        sessions: list = []
        session_error: AssistanceError | None = None
        try:
            sessions = terminal_services.enumerate_sessions()
        except AssistanceError as error:
            session_error = error
            message, detail = explain_error(error)
            diagnostics.error("Terminal Services session enumeration unavailable", f"{message}. {detail}")
        if args.command == "diagnose":
            print_sessions(sessions)
        policy = ShadowPolicyService(
            terminal_services.target, terminal_services.smb, credentials.mode is AuthenticationMode.KERBEROS, terminal_services.kdc_host
        ).query()
        if args.command in {"diagnose", "assist"}:
            _report_policy(policy, diagnostics)
        if args.command == "sessions":
            return 0
        if args.command == "diagnose":
            if session_error is not None:
                diagnostics.info("Session query and policy query are independent", "Policy was queried despite the Terminal Services failure.")
            console = [session for session in sessions if session.is_active_console]
            if console:
                diagnostics.ok("Active physical console session", f"{console[0].account_name}, session {console[0].session_id}")
            else:
                diagnostics.error("No active physical console session", "Assist is unavailable; normal RDP remains separate and may still be available.")
            diagnostics.step("Detecting FreeRDP...")
            try:
                client = detect_freerdp()
            except AssistanceError as error:
                diagnostics.error("FreeRDP is unavailable or incompatible", str(error))
                return 3
            diagnostics.ok("FreeRDP executable detected", client.executable)
            diagnostics.ok("FreeRDP version", client.version)
            return 0 if console else 3

        if session_error is not None:
            raise session_error
        session_id = selected_session_id(args, sessions)
        selected = next(session for session in sessions if session.session_id == session_id)
        diagnostics.ok(f"Active physical console selected: {session_id}", selected.account_name)
        interaction = ShadowControl.VIEW if args.view_only else ShadowControl(args.interaction)
        decision = resolve_assist_mode(permission_mode, interaction, policy)
        if not decision.allowed:
            raise AssistanceError(decision.reason)
        if decision.reason:
            diagnostics.info("Assist policy decision", decision.reason)
        if not args.no_launch:
            diagnostics.step("Detecting FreeRDP before sending any user prompt...")
            client = detect_freerdp()
            diagnostics.ok("FreeRDP detected", f"{client.executable} ({client.version})")
        invitation = AssistanceService(terminal_services, diagnostics).request_invitation(session_id, decision)

    destination = args.invitation_file
    if destination is None:
        destination = Path(tempfile.mkdtemp(prefix="remote-control-", dir=tempfile.gettempdir())) / "shadow.msrcIncident"
    if destination.suffix.lower() != ".msrcincident":
        raise AssistanceError("--invitation-file must end in .msrcIncident.")
    write_private_invitation(invitation, destination)
    diagnostics.ok("Validated invitation written to a private file", str(destination))
    if args.no_launch:
        diagnostics.info("FreeRDP was not launched (--no-launch). This did not create a normal RDP session.")
        return 0
    diagnostics.ok("Launching FreeRDP with Remote Assistance invitation (not normal RDP)")
    launch_invitation(destination, client)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalise_global_options(sys.argv[1:] if argv is None else argv))
    diagnostics = Diagnostics(sys.stdout, verbose=args.verbose)
    try:
        return run(args, diagnostics)
    except (AssistanceError, ValueError) as error:
        message, detail = explain_error(error)
        diagnostics.error(message, detail)
        return 2
    except KeyboardInterrupt:
        diagnostics.error("Cancelled by the administrator; FreeRDP was not launched.")
        return 130


def normalise_global_options(argv: list[str]) -> list[str]:
    """Permit authentication options before or after a subcommand without invoking a shell."""
    options_with_value = {"--auth", "--username", "--domain", "--kdc-host"}
    global_options: list[str] = []
    remaining: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in options_with_value:
            if index + 1 >= len(argv):
                remaining.append(item)
            else:
                global_options.extend((item, argv[index + 1]))
                index += 1
        elif item in {"--password-prompt", "--verbose"}:
            global_options.append(item)
        else:
            remaining.append(item)
        index += 1
    return [*global_options, *remaining]


if __name__ == "__main__":
    raise SystemExit(main())
