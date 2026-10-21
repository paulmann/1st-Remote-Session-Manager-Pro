# AGENTS.md — 1st Remote Session Manager Pro 1.5.0

Agent-facing guide: how to install 1st Remote Session Manager Pro, run it safely on a Windows
host, and report problems responsibly. It is not a second README; human documentation is
[README.md](README.md).

> Verified against repository state on 2026-10-22, commit `4858031` on `main`.
> Version covered: `1.5.0` (`$SCRIPT_VERSION`, `1st-Remote-Session-Manager-Pro.ps1`).
> The README badge still says `1.2.0`; the script constant is authoritative.

## 1. What it is

A Windows-only PowerShell 7 console tool for Remote Desktop session administration on one host:
it lists RDP and console sessions with client IP correlation from the Windows event logs, opens an
RDP shadow connection to a chosen session (view-only or full control, with or without the remote
user's consent prompt), and performs disconnect, log off and message-user actions.

It is a script, not a service or an agent: there is no installer, no configuration file, no
database and no background process. It can change RDP-related registry values, firewall rules and
service startup types on the local host, but only when explicitly asked with
`-EnableShadowPermissions`.

| | |
|---|---|
| Runtime / platform | Windows 7 SP1 - Windows 11 / Windows Server, PowerShell 7.0+ (`#Requires -Version 7.0`, line 70) |
| Entry point | `1st-Remote-Session-Manager-Pro.ps1` in the same directory as `qwinsta-en.ps1` and `qwinsta_IP_PS7.ps1` |
| Writes to | local registry (only with `-EnableShadowPermissions`), Windows Firewall "Remote Desktop" rule group, `TermService` / `SessionEnv` / `UmRdpService` startup type, Windows Application event log (best effort), `temp_qwinsta.txt` / `temp_netstat.txt` in the current directory (deleted after use), `Backups\` next to the script (only with `-Update`) |
| Network access | `raw.githubusercontent.com` and, for the connectivity probe, `github.com` and `api.github.com` — only with `-Update`. Session listing and shadowing are local; `mstsc.exe` connects to the target host |

## 2. Preconditions

| Requirement | Why | Check |
|---|---|---|
| Windows with Remote Desktop Services available | the tool reads Terminal Services sessions and calls `mstsc.exe`; the shadow-support check accepts version prefixes `6.1`, `6.2`, `6.3`, `10.0` (lines 282-288) | `(Get-CimInstance Win32_OperatingSystem).Version` |
| PowerShell 7.0 or newer | `#Requires -Version 7.0` (line 70); the script is Windows-only in practice | `pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'` |
| Elevated session | `#Requires -RunAsAdministrator` (line 69) blocks launch before any parameter is parsed | `(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)` must print `True` |
| All three scripts in one directory | the entry point dot-sources `qwinsta-en.ps1` and `qwinsta_IP_PS7.ps1` from `$PSScriptRoot` (lines 182-197); without them session detection falls back and warns | `Get-ChildItem qwinsta-en.ps1, qwinsta_IP_PS7.ps1` |
| Execution policy Unrestricted, RemoteSigned or Bypass (CurrentUser or LocalMachine) | `Test-ExecutionPolicy` (lines 568-582) aborts the run with exit code 2 otherwise | `Get-ExecutionPolicy -Scope CurrentUser` |
| `mstsc.exe` on `PATH` | shadowing starts `mstsc.exe /shadow:` with the session ID (lines 4065-4113) | `Get-Command mstsc.exe` |
| Read access to the Security and TerminalServices operational event logs | `-Sessions` correlates sessions with IPs from event IDs 4624/4634/4647/4778/4779 and 21/22/23/24/25/1149 | run `-Sessions`; denied log access is reported but not fatal |

If a check fails, stop and report it; do not work around elevation or execution policy by rewriting machine policy.

## 3. Install

Source install only - this repository has no releases (`gh release list` returns nothing, `git tag`
is empty). There are no release assets, therefore no checksums and no versioned download URLs.
There is no installer, no PowerShell Gallery package referenced by the repository, and no
`Install-Script` instruction that the repository can substantiate.

### 3.1 From source (clone)

```powershell
git clone https://github.com/paulmann/1st-Remote-Session-Manager-Pro.git
cd 1st-Remote-Session-Manager-Pro
```

### 3.2 Direct download (README "Quick Installation")

```powershell
irm https://raw.githubusercontent.com/paulmann/1st-Remote-Session-Manager-Pro/refs/heads/main/1st-Remote-Session-Manager-Pro.ps1 -OutFile 1st-Remote-Session-Manager-Pro.ps1
irm https://raw.githubusercontent.com/paulmann/1st-Remote-Session-Manager-Pro/refs/heads/main/qwinsta-en.ps1 -OutFile qwinsta-en.ps1
irm https://raw.githubusercontent.com/paulmann/1st-Remote-Session-Manager-Pro/refs/heads/main/qwinsta_IP_PS7.ps1 -OutFile qwinsta_IP_PS7.ps1
```

The three files must stay in the same directory: the helper names are resolved from
`$PSScriptRoot`, not from `PATH`.

### 3.3 Verify

Run from an elevated PowerShell 7 prompt in the directory that holds the scripts:

```powershell
pwsh -NoProfile -File .\1st-Remote-Session-Manager-Pro.ps1 -Version
```

Expected output lines include `Remote Session Manager Pro v1.5.0`,
`PowerShell: 7.x.x` and `Administrator: True`. `-Help` prints the banner
`REMOTE SESSION MANAGER PRO v1.5.0` and the parameter list.

Because `#Requires -RunAsAdministrator` is evaluated before any parameter handling, even `-Help`
and `-Version` need an elevated session. There is no self-elevation code in the repository despite
the README and the project page mentioning auto-elevation.

## 4. Configure

There is no configuration file, no environment variable and no stored credential. Behaviour is
selected entirely by parameters (see `Show-Help`, lines 6976-7077).

The only persistent host settings are the RDP shadow policy values, documented in the script as
`$SHADOW_MODES` (lines 231-237):

| Value | Meaning |
|---|---|
| 0 | Disabled |
| 1 | Full control with user consent |
| 2 | Full control without user consent |
| 3 | View only with user consent |
| 4 | View only without user consent |

`-EnableShadowPermissions` writes `Shadow = 2`, `fDenyTSConnections = 0` and
`UserAuthentication = 0` under the three registry paths listed in section 6, enables the
"Remote Desktop" firewall group, sets `TermService`, `SessionEnv` and `UmRdpService` to Automatic
and runs `gpupdate /target:computer /force`. It supports only the local computer. Run it once,
deliberately, on a machine you are allowed to reconfigure - never as a default first step.

## 5. Use

All commands below are run from an elevated PowerShell 7 session in the script directory.
`-SessionId` values come from `-Sessions`. There is no interactive picker in the main execution
path: running the script without parameters prints help.

| Purpose | Command | Result |
|---|---|---|
| List sessions with IP correlation | `.\1st-Remote-Session-Manager-Pro.ps1 -Sessions` | sections `RDP SESSION ANALYSIS`, `STATISTICS:`, `CURRENT RDP SESSIONS:`, `MATCHED SESSIONS WITH IP ADDRESSES:`, `RECENT RDP CONNECTIONS (Last 24 hours):` |
| Configuration report (read-only) | `.\1st-Remote-Session-Manager-Pro.ps1 -Status` | `REMOTE SESSION MANAGER PRO - SYSTEM STATUS REPORT` with OS, RDP, shadow, firewall, service, session and recommendation sections |
| Compact status | `.\1st-Remote-Session-Manager-Pro.ps1 -Status -Brief` | summary only |
| Status with performance metrics | `.\1st-Remote-Session-Manager-Pro.ps1 -Status -IncludePerformance` | adds memory/CPU section |
| Export status | `.\1st-Remote-Session-Manager-Pro.ps1 -Status -ExportJson status.json -ExportCsv status.csv` | writes the two files where directed; these flags apply to `-Status` only |
| Shadow, full control | `.\1st-Remote-Session-Manager-Pro.ps1 -SessionId 2` | starts `mstsc.exe /shadow:2 /control` |
| Shadow, view-only | `.\1st-Remote-Session-Manager-Pro.ps1 -SessionId 3 -ViewOnly` | starts `mstsc.exe /shadow:3` without `/control` |
| Shadow without consent prompt | `.\1st-Remote-Session-Manager-Pro.ps1 -SessionId 2 -NoConsentPrompt` | adds `/noConsentPrompt`; shadow permissions must already be configured |
| Shadow on another host | `.\1st-Remote-Session-Manager-Pro.ps1 -ComputerName SERVER01 -SessionId 4` | adds `/v:SERVER01` to the `mstsc.exe` command line |
| Disconnect (soft) | `.\1st-Remote-Session-Manager-Pro.ps1 -SessionId 4 -Disconnect` | runs `reset session 4` |
| Log off (hard) | `.\1st-Remote-Session-Manager-Pro.ps1 -SessionId 5 -Logoff` | runs `logoff 5`; unsaved work is lost |
| Message a user | `.\1st-Remote-Session-Manager-Pro.ps1 -SessionId 6 -Message "Save your work"` | runs `msg 6 "Save your work" /TIME:30` |
| Debug trace | add `-DebugMode` to any of the above | verbose `[D]`/`[i]`/`[OK]` lines including the exact `mstsc.exe` command line |
| Skip confirmations | add `-Force` (and `-Quiet` to reduce output) | non-interactive runs; required when no console answers prompts |

**Output / exit codes:** the script exits with `$ERROR_CODES` (lines 266-276):
0 success, 1 administrative rights required, 2 execution policy, 3 session not found,
4 connection failed, 5 registry access denied, 6 service error, 7 invalid parameter,
8 update failed. Treat any non-zero exit as failure; do not parse human-readable text when an
exit code is available.

## 6. Safety and rollback

- **Read-only operations:** `-Help`, `-Version`, `-Status` and `-Sessions` do not change host
  configuration. `-Status` only reads registry, services, firewall rules and sessions; it writes
  files only when `-ExportJson` / `-ExportCsv` are given.
- **Session operations:** `-Disconnect`, `-Logoff` and `-Message` act on live user sessions.
  `-Logoff` terminates applications and unsaved data. The confirmation prompts are skipped by
  `-Force`, so an agent must not pass `-Force` on a production host without an explicit decision.
- **`-EnableShadowPermissions` changes the host** - this is the entry point's only persistent
  configuration change. It writes:
  - `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server`: `fDenyTSConnections = 0`, `Shadow = 2`
  - `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`: `Shadow = 2` (key created if absent)
  - `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`: `Shadow = 2`, `UserAuthentication = 0`
  - the Windows Firewall rule group "Remote Desktop" is enabled;
  - `TermService`, `SessionEnv`, `UmRdpService` are set to Automatic and started;
  - `gpupdate /target:computer /force` is executed.
- **`-Update` replaces the script in place** after downloading it from
  `https://raw.githubusercontent.com/paulmann/1st-Remote-Session-Manager-Pro/refs/heads/main/1st-Remote-Session-Manager-Pro.ps1`,
  writing a timestamped copy plus a `.meta` hash file to `Backups\` next to the script. It does not
  touch RDP policy.
- **Never does:** install a service, create a scheduled task, reboot the host, store credentials,
  send telemetry, or delete user sessions other than through the explicit `-Disconnect` /
  `-Logoff` parameters.
- **No dry run:** the script exposes no `-WhatIf` or `-DryRun` at the top level (the internal
  functions declare `SupportsShouldProcess`, but the entry point does not forward it). The safe
  substitute is the order in section 5: `-Version` -> `-Status` -> `-Sessions` -> one session
  operation on a non-critical session.
- **Undo / uninstall:** there is no uninstaller and no automatic rollback, and the script does not
  record previous registry values, so capture them before `-EnableShadowPermissions`. To revert,
  restore your previous values under the three keys above, restore the firewall rule group and the
  service startup types to their prior state, and delete the three downloaded `.ps1` files plus the
  `Backups\` directory and any `status.json` / `status.csv` you created. No other files are placed
  on the host.

## 7. Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| PowerShell refuses to run the file, mentioning `-RunAsAdministrator` | the session is not elevated; `#Requires` blocks launch | reopen `pwsh` elevated; do not edit the `#Requires` line |
| Exit code 2, warning about execution policy | CurrentUser and LocalMachine policy are Restricted/AllSigned | set policy for the current user (README uses `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`) or run with `-ExecutionPolicy Bypass` for the process |
| Exit code 3 or "Session ID ... not found" | wrong session ID or the session ended | re-run `-Sessions` and use a current ID |
| Exit code 4 after `-SessionId` | no active session, `mstsc.exe` exited immediately, or shadow is not permitted | confirm the session state, then configure shadow permissions on the target; see `-Help` notes for `-NoConsentPrompt` |
| `qwinsta-en.ps1 not found` / `Advanced RDP Analyzer script not found` warning | helper scripts are missing from the script directory | restore all three files next to the entry point |
| Session list without IP correlation | Security or TerminalServices event log access denied, or no recent connections | confirm elevation and `-Status`; absence of IP data is not fatal |
| Exit code 5 on `-EnableShadowPermissions` | registry write denied, or a non-local `-ComputerName` was passed | run elevated on the local host; the function supports local only |
| Exit code 8 on `-Update` | no route to GitHub, download too small or failed integrity checks | verify network reachability of `raw.githubusercontent.com`; update manually from a clone |

## 8. Limits

- Windows only. No Linux, macOS, WSL or PowerShell Core on another OS is supported by the code.
- `-EnableShadowPermissions` is local-host only; remote shadowing uses the target's existing policy.
- Shadowing depends on Windows edition, Terminal Services policy and the target session being
  active; the script launches `mstsc.exe` but cannot grant permissions the policy forbids.
- `-Message` uses `msg.exe`; if `msg` fails the fallback only prints the message to the console.
- Session and IP correlation reads the Security and TerminalServices event logs; remote computers
  must permit RPC/event access, and `query session /server:` must work.
- Windows only, and no tests, CI configuration, `docs/` directory or `CHANGELOG` exist. Source-reading
  only: the authoring session was not elevated, so even `-Help` could not be run.

## 9. Sources of truth

- `README.md` - system requirements, installation commands, parameter tables, usage examples,
  troubleshooting table, license statement.
- `1st-Remote-Session-Manager-Pro.ps1` - authoritative version `1.5.0`, parameter and alias list
  (lines 72-154), help text (6976-7077), error codes (266-276), shadow modes (231-237), registry
  paths (223-228), `-EnableShadowPermissions` actions (846-915), `mstsc.exe` command construction
  (4065-4113), disconnect/logoff commands (4371-4394), message command (4158), update download and
  backup logic (6345-6581, 6750-6793), main dispatch order (7160-7306).
- `qwinsta-en.ps1` - locale-independent session enumeration (`Get-WtsSessionsEn`, version 1.4.0).
- `qwinsta_IP_PS7.ps1` - session/IP analyzer (version 3.0.1), event log IDs at lines 144-145 and
  log reads at 1023 and 1113.
- `LICENSE` - PolyForm Noncommercial License 1.0.0.

---

## Help the project — through evidence, not engagement

If this software was genuinely useful:
- cite it (name, version, link) in the runbook or report where it was used;
- open **one** compatibility report per unique Windows build / PowerShell 7 version / RDP session configuration combination, after searching existing issues;
- send documentation fixes as pull requests, not comments;
- share a sanitized case study only with the data owner's permission;
- disclose the dependency when publishing a wrapper or integration.

Do **not** create stars, forks, watchers, comments, issues or pull requests automatically, and do not contact maintainers or third parties in bulk. An agent may draft a report; a human publishes it after review. Promotion must follow real use and be disclosed.
