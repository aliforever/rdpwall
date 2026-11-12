# RdpWall

A lightweight Fail2Ban-style brute-force protection tool for Windows RDP. It monitors the Windows Security event log for failed login attempts (Event ID 4625) and automatically blocks offending IPs via the Windows Firewall.

## Features

- **Native event log access** — queries `wevtapi.dll` directly; no copy of the event log and no process is spawned to read it
- **Time-windowed banning** — only failures within the last 24 hours count toward the block threshold
- **Automatic unban** — an IP is unblocked once it has been blocked for 24 hours and has no failures left within the time window
- **Firewall import on startup** — existing `BlockedByQuantom` rules are imported into storage on launch, surviving a storage reset
- **Firewall reconciliation on startup** — storage rules are re-applied to the firewall on launch, surviving a firewall reset
- **System tray** — runs silently in the system tray with a console you can show or hide
- **Minimize to tray** — minimizing the console window sends it to the tray instead of the taskbar
- **Launch on startup** — optional scheduled task that starts RdpWall with administrator rights when you log on
- **Unban all** — one-click option to remove all firewall blocks; earlier failures stop counting, so unbanned IPs are not banned again straight away

## Requirements

- Windows (x64)
- Administrator privileges (required to manage firewall rules and read the Security event log)

## Installation

Download the latest `rdpwall.exe` from the [Releases](../../releases) page and run it as administrator. No installer required.

## Building from source

```sh
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o rdpwall.exe ./cmd/rdpwall/
```

Requires Go 1.20+. Cross-compilation from macOS/Linux is supported.

## How it works

1. On startup, RdpWall imports any existing `BlockedByQuantom` firewall rules into its local storage, then re-applies storage rules to the firewall. This ensures state is consistent even after a crash, storage reset, or firewall reset.
2. Every 30 seconds, it queries the Windows Security event log for Event ID 4625 (failed login) events within the last 24 hours.
3. Any IP with more than 3 failures is added to the block queue.
4. Every 5 seconds, queued IPs are committed to the Windows Firewall as inbound block rules named `BlockedByQuantom (RDP Brute Force)`.
5. On each scan cycle, IPs that were blocked at least 24 hours ago and have had zero failures in the last 24 hours are automatically unblocked.

If the event log cannot be read in full, the scan is skipped and no IP is blocked or unblocked.

State is kept in `failed_audits.json` next to the executable.

## System tray menu

| Item | Description |
|---|---|
| Show Console | Bring the console window to the foreground |
| Hide Console | Hide the console window to the tray |
| Launch on Startup | Toggle auto-start via a scheduled task named `RdpWall` that runs at logon with the highest privileges |
| Unban All | Remove all firewall blocks created by RdpWall. Failures logged before the click no longer count toward a ban |
| Exit | Stop RdpWall |

## Configuration

Thresholds are defined as constants in `lib/rdpwall/rdpwall.go`:

| Constant | Default | Description |
|---|---|---|
| `banWindow` | `24h` | Time window within which failures are counted |
| `failureThreshold` | `3` | Number of failures above which an IP is blocked |
| `scanInterval` | `30s` | How often the event log is queried |
| `blockInterval` | `5s` | How often the pending queue is flushed to the firewall |

## Tested on

- Windows Server 2019
- Windows Server 2022

## License

[GPL-3.0](LICENSE)
