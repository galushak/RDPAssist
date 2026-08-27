import configparser
import tomllib
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_desktop_entry_has_one_gui_identity_and_no_terminal():
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(ROOT / "data" / "remote-control.desktop", encoding="utf-8")
    entry = parser["Desktop Entry"]
    assert entry["Name"] == "Remote Control"
    assert entry["Exec"] == "remote-control"
    assert entry["Icon"] == "remote-control"
    assert entry["Terminal"] == "false"
    assert entry["StartupWMClass"] == "remote-control"


def test_gui_and_cli_entry_points_are_separate():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project["project"]["scripts"]
    assert scripts["remote-control"] == "session_assist.gui.app:main"
    assert scripts["remote-control-cli"] == "session_assist.cli:main"


def test_debian_builder_is_shipped_for_release_installation():
    assert (ROOT / "packaging" / "debian" / "build-deb.py").is_file()


def test_debian_builder_does_not_depend_on_debian_12_impacket_api():
    builder = (ROOT / "packaging" / "debian" / "build-deb.py").read_text(encoding="utf-8")
    control = builder.split('WRAPPER =', 1)[0]
    assert "python3-impacket" not in control
    assert "vendored_runtime" in builder
    assert "Cryptodome" in builder


def test_icon_asset_exists():
    assert (ROOT / "data" / "icons" / "hicolor" / "scalable" / "apps" / "remote-control.svg").is_file()
