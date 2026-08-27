# RDPAssist / Remote Control

`remote-control` is a development-stage PySide6/Qt application for KDE-oriented
Linux desktops that administer authorized domain-joined Windows hosts. It keeps
two distinct operations distinct:

* **Normal RDP** starts a conventional new FreeRDP desktop connection.
* **Assist User** targets the already logged-on **active physical console** through
  Windows Terminal Services shadowing. It never substitutes normal RDP.

The Phase 1 implementation uses current Impacket Terminal Services support for
structured session enumeration and `RpcShadow2`, and MS-RRP/Remote Registry to
read the target computer's configured RDS shadow policy. It does not install an
endpoint agent or parse text output such as `qwinsta`.

## Current status

This is a **development build** (currently `0.4.4-dev`), not a production-ready
release. The GUI, Kerberos sign-in/cache flow, Active Directory search, DNS/KDC
discovery, SMB Kerberos authentication, session enumeration infrastructure,
policy detection, FreeRDP launching, diagnostics, KDE integration, and Debian
packaging are implemented. Live Windows session-shadow acceptance testing and
Terminal Services RPC interoperability validation are ongoing. KDE launcher and
dock-pinning acceptance testing is also still required on target desktops.

## Install

On Debian/Ubuntu, install the distribution's current FreeRDP X11 client and
Kerberos tools. Debian 13 provides `freerdp3-x11` / `xfreerdp3`; older releases
may provide `freerdp2-x11` / `xfreerdp`.

```bash
sudo apt install python3-venv krb5-user freerdp3-x11
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

`remote-control` discovers `xfreerdp3` and `xfreerdp` rather than hard-coding
one executable. It uses the active Kerberos cache by default. When an
authenticated GUI operation needs a ticket, **Domain Sign In** securely runs
the system `kinit` client with the password on standard input only; it never
stores a password. Tickets use the normal shared Linux credential cache, so
existing domain-aware tools can reuse them and externally-created tickets are
detected on refresh. NTLM is available only with an interactive password prompt.

## Launching

```bash
.venv/bin/remote-control
```

The Qt app uses system light/dark styling, runs DNS/Kerberos/SMB/RPC work in Qt
workers, and manages FreeRDP through `QProcess`. It installs a KDE-compatible
`remote-control.desktop` launcher with a matching application icon and desktop
identity, so it appears as one pinnable application without a terminal.

To run directly from source without installing an editable console script:

```bash
PYTHONPATH=src .venv/bin/python -m session_assist.gui.app
```

The Settings dialog stores assist/RDP preferences, recents, favorites, logging
preferences, and reports Kerberos/FreeRDP status. The Diagnostics dialog runs
the same non-secret backend checks and can copy a safe summary.

## Active Directory discovery

Typing at least two characters in the editable computer field starts a
debounced, bounded background search for computer `name`, `dNSHostName`, and
`description`. Results remain optional: manual host entry, recents, and
favorites work when DNS, LDAP, or Kerberos is unavailable.

Directory search derives its realm from the active Kerberos principal where
possible, discovers a domain controller through `_ldap._tcp.dc._msdcs` DNS SRV
records, then reads `defaultNamingContext` from RootDSE. The Settings dialog
can override the LDAP server or set a specific search base/OU. LDAP binds use
the existing Kerberos credential cache; neither LDAP nor application passwords
are stored.

Favorites may have an optional display name. Right-click the computer field for
the scoped Assist, RDP, Refresh, Favorite, and Copy Hostname/IP actions.

## Debian/Ubuntu installation

Build the Debian package on Debian 13 or a compatible build host:

```bash
.venv/bin/python packaging/debian/build-deb.py
sudo apt install ./dist/remote-control_0.4.4~dev1_amd64.deb
```

It installs the GUI, CLI, desktop entry, and icon under normal system paths;
normal usage is simply **Remote Control** from the KDE application launcher.
No checkout or virtual environment is needed at runtime. To upgrade, pass a
newer `.deb` to `apt install`; to uninstall while retaining user settings and
logs, run `sudo apt remove remote-control`.

The package depends on Python 3, Qt/PySide, dnspython, Kerberos tools, and
FreeRDP. It privately bundles the tested Impacket 0.13 runtime because Debian
13's system Impacket lacks the required `RpcShadow2` API. See [the package notes](packaging/debian/README.md) for
the exact dependency declaration and commands.

The project has not selected a license for its own source yet. The Debian
builder includes third-party notices for the bundled Impacket and PyCryptodome
runtimes; see [the package notes](packaging/debian/README.md).

## Development CLI

```bash
remote-control-cli HOST diagnose
remote-control-cli HOST sessions
remote-control-cli HOST policy
remote-control-cli HOST rdp
remote-control-cli HOST assist
remote-control-cli HOST favorite add
```

`diagnose` uses DNS plus TCP/RPC/SMB checks, not ICMP alone. It reports the
Kerberos principal (never ticket material), FreeRDP path/version, structured
session data, active console availability, and policy-query result.

`assist` selects the sole active console automatically. It stops if none or
more than one is found, so it never picks an RDP session or silently targets a
different user. An explicit `--session ID` is accepted only for an active
console session.

```bash
# Default: saved policy mode (Automatic + Full Control on first use).
remote-control-cli HOST assist

# Force a native Windows approval prompt.
remote-control-cli HOST assist --permission consent

# Request view-only assistance.
remote-control-cli HOST assist --interaction view

# Only valid after the target policy is conclusively read as no-consent.
remote-control-cli HOST assist --permission no-consent
```

Policy behavior is conservative:

| Target policy result | Automatic assist behavior |
| --- | --- |
| Full/View with approval | Native Windows approval prompt |
| Full/View without approval | Native no-prompt `RpcShadow2` request |
| Disabled | Stops before assist |
| Not configured, unreadable, unavailable, or unknown | Native Windows approval prompt |

`--permission no-consent` is rejected unless a conclusive target policy permits
it. A consent decline, policy failure, or invalid invitation ends the operation;
it can never launch `/v:HOST` as a fallback.

Normal RDP is intentionally separate. It uses dynamic resolution, clipboard,
audio, and Kerberos authentication preference when supported by the discovered
FreeRDP client. It does not depend on an active console session.

## Storage and safety

Per-user state follows XDG locations:

* configuration: `$XDG_CONFIG_HOME/remote-control/settings.json`
* data: `$XDG_DATA_HOME/remote-control/`
* logs: `$XDG_STATE_HOME/remote-control/logs/`
* cache: `$XDG_CACHE_HOME/remote-control/`

Recent targets, the last target, and the selected permission mode are stored in
the settings file. Use `remote-control-cli HOST favorite add` or `remove` to manage
favorites; `show` lists them. Logs contain operational stages only; passwords, tickets,
hashes, keys, and Remote Assistance invitation XML are never logged. Invitation
files are newly created with `0600` permissions.

## Windows prerequisites

The target needs an active logged-on physical console user, administrator
`WINSTATION_SHADOW` permission, SMB/RPC/Remote Registry access, and appropriate
Windows RDS shadow policy. Validate on an authorized managed workstation before
production use. See [research notes](docs/research.md) and the [endpoint
acceptance checklist](docs/testing.md).

## Test

```bash
.venv/bin/python -m pytest
```

The automated tests cover policy mapping/decisions, console selection,
FreeRDP command construction, Kerberos-cache discovery, target validation, and
private invitation handling. The final desktop-sharing path requires a live,
authorized Windows endpoint test.
