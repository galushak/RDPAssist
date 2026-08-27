#!/usr/bin/env python3
"""Build a self-contained Debian application package without a source checkout at runtime."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "dist"
PACKAGE = "remote-control"
VERSION = "0.4.4~dev1"


CONTROL = """Package: {package}
Version: {version}
Section: net
Priority: optional
Architecture: {architecture}
Maintainer: Remote Control Contributors <noreply@localhost>
Depends: python3 (>= 3.10), python3-pyside6.qtwidgets, python3-dnspython, python3-ldap3, python3-openssl, python3-pyasn1, python3-pyasn1-modules, python3-six, krb5-user, freerdp3-x11
Description: Linux GUI for Windows RDP and policy-compliant session assistance
 Remote Control provides normal RDP and Windows physical-console assistance
 for authorized Active Directory environments. It does not deploy an endpoint
 agent or store passwords.
"""


WRAPPER = """#!/usr/bin/python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'lib' / 'remote-control'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'lib' / 'remote-control' / 'vendor'))
from session_assist.{module} import main
raise SystemExit(main())
"""


def copytree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def vendored_runtime(destination: Path) -> tuple[Path, Path]:
    """Ship the tested Impacket 0.13 runtime instead of Debian 13's incompatible 0.12 API."""
    try:
        import impacket
        import Cryptodome
        from impacket import version as impacket_version
    except ImportError as error:
        raise RuntimeError(
            "Build with the project's virtual environment: `.venv/bin/python packaging/debian/build-deb.py`. "
            "It must contain Impacket 0.13 and pycryptodomex."
        ) from error
    banner = getattr(impacket_version, "BANNER", "")
    if "v0.13" not in banner and "0.13" not in banner:
        raise RuntimeError("The Debian package must be built with tested Impacket 0.13.x.")
    copytree(Path(impacket.__file__).resolve().parent, destination / "impacket")
    copytree(Path(Cryptodome.__file__).resolve().parent, destination / "Cryptodome")
    return Path(impacket.__file__).resolve().parent, Path(Cryptodome.__file__).resolve().parent


def copy_vendored_notices(impacket_package: Path, cryptodome_package: Path, destination: Path) -> None:
    """Keep the licenses for privately bundled runtime code in the .deb."""
    impacket_license = next(impacket_package.parent.glob("impacket-*.dist-info/licenses/LICENSE"), None)
    cryptodome_license = next(cryptodome_package.parent.glob("pycryptodomex-*.dist-info/LICENSE.rst"), None)
    if impacket_license is None or cryptodome_license is None:
        raise RuntimeError("The installed Impacket/PyCryptodome license notices are required to build the package.")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(impacket_license, destination / "impacket-LICENSE")
    shutil.copy2(cryptodome_license, destination / "pycryptodomex-LICENSE.rst")
    (destination / "THIRD_PARTY_NOTICES").write_text(
        "Remote Control privately bundles Impacket and PyCryptodome for runtime compatibility.\n"
        "Their complete license notices are included alongside this file.\n",
        encoding="utf-8",
    )


def main() -> int:
    if shutil.which("dpkg-deb") is None:
        print("dpkg-deb is required to build a Debian package.", file=sys.stderr)
        return 2
    DIST.mkdir(exist_ok=True)
    architecture = subprocess.run(["dpkg", "--print-architecture"], check=True, capture_output=True, text=True).stdout.strip()
    output = DIST / f"{PACKAGE}_{VERSION}_{architecture}.deb"
    with tempfile.TemporaryDirectory(prefix="remote-control-deb-") as temporary:
        stage = Path(temporary) / f"{PACKAGE}_{VERSION}_{architecture}"
        control = stage / "DEBIAN"
        application = stage / "usr" / "lib" / "remote-control"
        vendor = application / "vendor"
        applications = stage / "usr" / "share" / "applications"
        icons = stage / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps"
        documentation = stage / "usr" / "share" / "doc" / PACKAGE
        binaries = stage / "usr" / "bin"
        control.mkdir(parents=True)
        application.mkdir(parents=True)
        applications.mkdir(parents=True)
        icons.mkdir(parents=True)
        binaries.mkdir(parents=True)
        (control / "control").write_text(CONTROL.format(package=PACKAGE, version=VERSION, architecture=architecture), encoding="utf-8")
        copytree(ROOT / "src" / "session_assist", application / "session_assist")
        vendor.mkdir()
        impacket_package, cryptodome_package = vendored_runtime(vendor)
        copy_vendored_notices(impacket_package, cryptodome_package, documentation)
        shutil.copy2(ROOT / "data" / "remote-control.desktop", applications / "remote-control.desktop")
        shutil.copy2(ROOT / "data" / "icons" / "hicolor" / "scalable" / "apps" / "remote-control.svg", icons / "remote-control.svg")
        for executable, module in (("remote-control", "gui.app"), ("remote-control-cli", "cli")):
            path = binaries / executable
            path.write_text(WRAPPER.format(module=module), encoding="utf-8")
            path.chmod(0o755)
        for path in stage.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
            elif path.parent != binaries:
                path.chmod(0o644)
        stage.chmod(0o755)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(stage), str(output)], check=True)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
