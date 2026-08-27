# Debian package

Build from the repository root:

```bash
.venv/bin/python packaging/debian/build-deb.py
```

The output is `dist/remote-control_0.4.4~dev1_amd64.deb` on the current build
host. The builder uses the project virtual environment to bundle the tested
Impacket 0.13 runtime privately; Debian 13's system `python3-impacket` is 0.12
and does not expose the `RpcShadow2` API required by Remote Control.

```bash
sudo apt install ./dist/remote-control_0.4.4~dev1_amd64.deb
# Upgrade with a newer package:
sudo apt install ./dist/remote-control_<new-version>_amd64.deb
# Remove the application but retain per-user XDG settings/logs:
sudo apt remove remote-control
```

The package installs the application implementation under
`/usr/lib/remote-control`, launchers in `/usr/bin`, and the desktop entry/icon
under `/usr/share`. It depends on Debian's Qt, DNS, Kerberos, and FreeRDP
packages; no source checkout or Python virtual environment is required to
launch the installed GUI.

The builder privately bundles the tested Impacket and PyCryptodome runtimes
because Debian's available Impacket API is insufficient for session shadowing.
Neither dependency's source is committed to this repository. The generated
package includes their complete installed license notices under
`/usr/share/doc/remote-control/`; replacing the private runtime with a suitable
upstream system dependency can be evaluated in a future packaging change.
