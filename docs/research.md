# Phase 1 research notes (checked 2026-08-27)

## Current supported upstream path

The maintained upstream [Impacket `tstool.py`](https://github.com/fortra/impacket/blob/master/examples/tstool.py)
uses `SMBConnection`, `TermSrvEnumeration`, `TermSrvSession`,
`SessEnvPublicRpc`, and `hRpcShadow2`. This project adapts that maintained
path—not a shell parser—for structured Terminal Services sessions and the
invitation used to display the existing desktop.

Microsoft's current [MS-TSTS `RpcShadow2` specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/70cb89cf-10d0-429e-8f8b-c2c4eea5eb8c)
states that it creates a Desktop Sharing shadow session and returns an MS-RAI
invitation. Current Impacket exposes the protocol's `VIEW`/`TAKECONTROL` and
`SILENT`/`REQUESTPERMISSION` enum values. `REQUESTPERMISSION` blocks while the
target user answers; the returned invitation is only passed to FreeRDP after an
allow response.

The client reads the target's configured Computer Policy value via the native
[MS-RRP Windows Remote Registry Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78),
reusing the authenticated SMB session and `\\winreg` named pipe. It reads only:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

The current Windows policy options are verified as:

| DWORD | Meaning |
| --- | --- |
| 0 | Remote control disabled |
| 1 | Full Control with user approval |
| 2 | Full Control without user approval |
| 3 | View Only with user approval |
| 4 | View Only without user approval |

Microsoft's current support article confirms the policy's **Full Control
without user's permission** mode for no-prompt shadowing; the protocol itself
returns a policy-permission-required status when a silent request conflicts
with policy. See [Microsoft support](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/shadow-terminal-server-session)
and the current [Impacket TSTS enum definitions](https://github.com/fortra/impacket/blob/master/impacket/dcerpc/v5/tsts.py).

If that remote registry key/value is missing or unreadable, it is not evidence
that no-prompt control is legal. The code reports `NotConfigured`,
`AccessDenied`, `Unavailable`, or `Unknown`, and Automatic mode asks Windows to
request approval. The `RpcShadow2` response remains the final Windows policy
authority.

## FreeRDP

Current FreeRDP accepts a `.msrcIncident` Remote Assistance invitation as a
positional input. The `assist` service gives it a newly created, owner-only
file and never constructs `/v:HOST`. The `rdp` service constructs `/v:HOST`
separately, with dynamic resolution, clipboard, audio, and Kerberos preference.
All launches use argument arrays, never `shell=True`, and do not disable
certificate validation. See the [current FreeRDP command-line source](https://github.com/FreeRDP/FreeRDP/blob/master/client/common/cmdline.h).

## Endpoint validation remains required

Protocol/API availability does not prove every Windows 11 policy, network
topology, and packaged FreeRDP build interoperates. Before calling this live
verified, test an organization-owned Windows endpoint with an interactive user:

1. Windows shows the native consent prompt when policy requires it.
2. Decline produces no FreeRDP launch and no normal-RDP fallback.
3. Acceptance shows the existing physical desktop and keeps it synchronized.
4. The no-prompt path is tested only under explicitly configured no-consent
   policy.
