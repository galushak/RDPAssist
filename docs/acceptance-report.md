# Development acceptance status

Generated for the public `0.4.4-dev` development baseline. This report records
only sanitized outcomes; it contains no production hostnames, user identities,
addresses, ticket contents, or credential-cache paths.

| Area | Status | Notes |
| --- | --- | --- |
| Automated tests | Pass | Offline unit and Qt tests cover backend and UI behavior. |
| Debian build | Pass | The package builder creates a private Impacket runtime and Debian launchers. |
| Kerberos cache flow | Implemented | The application uses the normal Linux credential cache and can invoke `kinit` without retaining the password. |
| DNS/KDC discovery | Implemented | KDC SRV candidates are resolved and TCP/88-tested before use. |
| SMB Kerberos | Live validation in progress | Read-only checks have reached SMB authentication against authorized test hosts. |
| Terminal Services RPC | Live validation in progress | Target-dependent endpoint interoperability still needs validation/fixes. |
| Session shadowing | Pending live acceptance | Requires an authorized Windows console session and policy-controlled consent testing. |
| KDE launcher/pinning | Pending live acceptance | Package metadata is present; desktop-shell behavior requires manual verification. |

## Safety boundaries

Normal RDP and existing-session assistance remain separate. Assistance uses
Windows' native session-shadow/Remote Assistance path and stops on policy,
consent, or invitation failures; it never falls back to normal RDP.

Kerberos service-ticket acquisition uses AD DNS SRV discovery and a bounded TCP
test. Diagnostics report only operational metadata and do not include passwords,
ticket material, hashes, or Remote Assistance invitation XML.

## Reproducing the development checks

```bash
.venv/bin/python -m pytest
.venv/bin/python packaging/debian/build-deb.py
```

For live validation, use only an organization-authorized Windows endpoint and
follow [the endpoint checklist](testing.md). Do not add live output containing
identities, addresses, caches, or credentials to this public repository.
