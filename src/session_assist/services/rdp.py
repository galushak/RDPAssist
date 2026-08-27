"""FreeRDP discovery and separately constructed normal-RDP / assistance launches."""

from __future__ import annotations

import shutil
import subprocess
import re
from dataclasses import dataclass
from pathlib import Path

from session_assist.models import AssistanceError, Credentials


@dataclass(frozen=True)
class FreeRDPClient:
    executable: str
    version: str


_VERSION = re.compile(r"(?:This is )?FreeRDP(?:\s+version)?\s+(?P<version>[0-9][^\s,]*)", re.IGNORECASE)


def detect_freerdp() -> FreeRDPClient:
    """Locate a current FreeRDP client and read its version without a shell."""
    for name in ("xfreerdp3", "xfreerdp"):
        executable = shutil.which(name)
        if not executable:
            continue
        try:
            result = subprocess.run(
                [executable, "/version"], check=False, capture_output=True, text=True, timeout=5
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AssistanceError(f"FreeRDP executable was found at {executable}, but could not be queried: {error}") from error
        output = f"{result.stdout}\n{result.stderr}"
        match = _VERSION.search(output)
        if not match:
            raise AssistanceError(
                f"FreeRDP executable was found at {executable}, but its version could not be determined with `/version`."
            )
        return FreeRDPClient(executable, match.group("version"))
    raise AssistanceError(
        "FreeRDP was not found. On this Debian 13 workstation install it with: `sudo apt install freerdp3-x11`."
    )


def find_freerdp() -> str:
    return detect_freerdp().executable


def invitation_command(invitation_file: Path, client: FreeRDPClient | None = None) -> list[str]:
    """Build an argument array for Remote Assistance, never `/v:` normal RDP."""
    if invitation_file.suffix.lower() != ".msrcincident":
        raise ValueError("Remote Assistance invitation files must use the .msrcIncident extension.")
    return [(client.executable if client else find_freerdp()), str(invitation_file), "+clipboard"]


def launch_invitation(invitation_file: Path, client: FreeRDPClient | None = None) -> subprocess.Popen[bytes]:
    return subprocess.Popen(invitation_command(invitation_file, client), start_new_session=True)


def normal_rdp_command(
    target: str, credentials: Credentials, client: FreeRDPClient | None = None,
    *, dynamic_resolution: bool = True, clipboard: bool = True, audio: bool = True,
) -> list[str]:
    """Build a normal RDP command. It is never used by the assistance workflow."""
    executable = client.executable if client else find_freerdp()
    command = [
        executable,
        f"/v:{target}",
        f"/u:{credentials.username}",
        f"/d:{credentials.domain}",
    ]
    if dynamic_resolution:
        command.append("/dynamic-resolution")
    if clipboard:
        command.append("+clipboard")
    if audio:
        command.append("/sound")
    if credentials.mode.value == "kerberos":
        # Prefer the existing MIT/Heimdal cache; no password is placed in argv.
        command.append("/auth-pkg-list:!ntlm,kerberos")
    return command


def launch_normal_rdp(target: str, credentials: Credentials, client: FreeRDPClient | None = None) -> subprocess.Popen[bytes]:
    return subprocess.Popen(normal_rdp_command(target, credentials, client), start_new_session=True)
