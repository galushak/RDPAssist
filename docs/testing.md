# Authorized Windows endpoint acceptance checklist

Run this only against an organization-owned Windows 11 workstation with a user
present. It validates both independently implemented paths: normal RDP and
policy-compliant assistance to the same existing physical desktop.

## Preflight

Use **Domain Sign In** in the GUI (or an existing system ticket), then run:

```bash
remote-control-cli HOST diagnose --auth kerberos --verbose
```

Expect DNS/IP resolution, Kerberos principal detection, SMB/RPC status,
structured session enumeration, Remote Registry policy status, and discovered
FreeRDP path/version. The command must not send an assistance request.

Confirm the Windows host has an active signed-in console user, the administrator
has `WINSTATION_SHADOW` permission, SMB/RPC/Remote Registry is reachable, and
the RDS shadow policy is configured deliberately.

## Active Directory search

With a valid domain ticket, type a distinctive room or host fragment in the GUI
computer field. Confirm that the directory result list is bounded, returns the
expected computer name/description, and selecting a result performs the normal
computer check. Repeat with an unavailable/expired Kerberos ticket: directory
search should request a single GUI domain sign-in and resume after success;
after cancellation, manual host entry remains usable and the app must not keep
prompting while the user types.

## Session behavior

```bash
remote-control-cli HOST sessions
```

Verify the desired user is shown as `Active`, type `Console`, and `CONSOLE yes`.
An active RDP session is not a candidate for this application's Assist action.

## Consent-required policy

Set the target computer policy to **Full Control with user's permission**.

```bash
remote-control-cli HOST assist --permission auto --interaction control
```

1. Confirm the native Windows approval prompt appears for the console user.
2. Have the user decline. The command must report decline and no FreeRDP window
   or normal RDP connection may start.
3. Repeat and accept. Confirm Linux displays the same physical desktop; input
   works; the user remains logged in; and both views stay synchronized.
4. Repeat with `--interaction view` and verify input remains unavailable.

## No-consent policy

Only after explicit authorization, set the target policy to a documented
no-consent mode and verify it with `remote-control-cli HOST policy`.

```bash
remote-control-cli HOST assist --permission auto
remote-control-cli HOST assist --permission no-consent
```

Both commands may use native silent `RpcShadow2` only if the policy result is
conclusive and permits it. Change the policy query to unavailable/unreadable
and verify that Automatic instead requests approval, while explicit
`--permission no-consent` stops before a request.

## Separate normal RDP

With no active console user, run:

```bash
remote-control-cli HOST rdp
```

It may open a conventional new RDP session. It must not be triggered by an
Assist failure, user decline, invalid invitation, or policy block.
