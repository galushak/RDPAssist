import pytest

from session_assist.cli import normalise_global_options
from session_assist.services.terminal_services import validate_target


@pytest.mark.parametrize("target", ["HS-ROOM-214-TEACHER", "room214.school.example", "10.0.0.12", "2001:db8::12"])
def test_valid_targets(target):
    assert validate_target(target) == target


@pytest.mark.parametrize("target", ["host name", "host;command", " host", ""])
def test_invalid_targets(target):
    with pytest.raises(ValueError):
        validate_target(target)


def test_authentication_options_are_accepted_after_subcommand():
    assert normalise_global_options(
        ["HOST", "sessions", "--auth", "kerberos", "--domain", "SCHOOL.EXAMPLE"]
    ) == ["--auth", "kerberos", "--domain", "SCHOOL.EXAMPLE", "HOST", "sessions"]


def test_verbose_is_accepted_after_subcommand():
    assert normalise_global_options(["HOST", "diagnose", "--verbose"]) == ["--verbose", "HOST", "diagnose"]
