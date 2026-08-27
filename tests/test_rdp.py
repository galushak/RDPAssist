from pathlib import Path

import pytest

from session_assist.services import rdp
from session_assist.models import AuthenticationMode, Credentials


def test_invitation_command_uses_no_normal_rdp_server_argument(monkeypatch):
    monkeypatch.setattr(rdp, "find_freerdp", lambda: "/usr/bin/xfreerdp3")
    command = rdp.invitation_command(Path("/tmp/request.msrcIncident"))
    assert command == ["/usr/bin/xfreerdp3", "/tmp/request.msrcIncident", "+clipboard"]
    assert not any(argument.startswith("/v:") for argument in command)


def test_invitation_command_rejects_other_files(monkeypatch):
    monkeypatch.setattr(rdp, "find_freerdp", lambda: "/usr/bin/xfreerdp3")
    with pytest.raises(ValueError):
        rdp.invitation_command(Path("/tmp/normal.rdp"))


def test_detects_xfreerdp3_and_its_version(monkeypatch):
    class Result:
        stdout = "This is FreeRDP version 3.15.0\n"
        stderr = ""

    monkeypatch.setattr(rdp.shutil, "which", lambda name: "/usr/bin/xfreerdp3" if name == "xfreerdp3" else None)
    monkeypatch.setattr(rdp.subprocess, "run", lambda *args, **kwargs: Result())
    client = rdp.detect_freerdp()
    assert client.executable == "/usr/bin/xfreerdp3"
    assert client.version == "3.15.0"


def test_normal_rdp_command_is_separate_from_invitation(monkeypatch):
    monkeypatch.setattr(rdp, "find_freerdp", lambda: "/usr/bin/xfreerdp3")
    credentials = Credentials("admin", "SCHOOL.EXAMPLE", None, AuthenticationMode.KERBEROS)
    command = rdp.normal_rdp_command("room.school.example", credentials)
    assert "/v:room.school.example" in command
    assert "/dynamic-resolution" in command
    assert "+clipboard" in command
    assert "/auth-pkg-list:!ntlm,kerberos" in command


def test_normal_rdp_options_can_be_disabled_for_saved_gui_preferences(monkeypatch):
    monkeypatch.setattr(rdp, "find_freerdp", lambda: "/usr/bin/xfreerdp3")
    credentials = Credentials("admin", "SCHOOL.EXAMPLE", None, AuthenticationMode.KERBEROS)
    command = rdp.normal_rdp_command("room.school.example", credentials, dynamic_resolution=False, clipboard=False, audio=False)
    assert "/dynamic-resolution" not in command
    assert "+clipboard" not in command
    assert "/sound" not in command
