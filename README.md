<p align="center"><img src="assets/logo.svg" width="320" alt="RdpWall"></p>

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

1. Download the latest `rdpwall.exe` from the [Releases](../../releases) page.
2. Put it in a folder of its own, for example `C:\Program Files\RdpWall`. The state file is written next to it.
3. Run it as administrator. No installer required.
4. Right-click the tray icon and tick **Launch on Startup** to have it start when you log on.

### Upgrading from 0.0.x

Replace the executable and start it. The old state file is read as it is. Existing bans have no recorded block time, so their 24 hours start at the first launch of the new version. If you used Launch on Startup before, untick and tick it once to replace the old registry entry with the scheduled task.

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

## Limitations

- **There is no allowlist.** Your own address is blocked like any other after more than 3 failed logins in 24 hours. Make sure you have another way into the server, such as the provider's console, before relying on RdpWall.
- **Every failed logon counts, not only RDP.** Any Event ID 4625 that carries a source address is counted, whichever service it came from.
- **A blocked address is blocked on every port**, not only on the RDP port.
- **It runs only while you are logged on.** Launch on Startup starts RdpWall at logon, so after a reboot nothing is scanned until you sign in. Existing firewall rules stay in place meanwhile.
- **Each scan re-reads the whole 24-hour window.** On a log with 25,000 failed logins that takes about 4 to 5 seconds of CPU every 30 seconds.

## Configuration

Thresholds are defined as constants in `lib/rdpwall/rdpwall.go`:

| Constant | Default | Description |
|---|---|---|
| `banWindow` | `24h` | Time window within which failures are counted |
| `failureThreshold` | `3` | Number of failures above which an IP is blocked |
| `scanInterval` | `30s` | How often the event log is queried |
| `blockInterval` | `5s` | How often the pending queue is flushed to the firewall |

## Development

```sh
go test ./...                              # runs on any OS
GOOS=windows GOARCH=amd64 go vet ./...
```

The logo and icon drawings are in `assets/`. The tray icon is embedded from `cmd/rdpwall/tray.ico`, and the executable's icon comes from `cmd/rdpwall/rsrc_windows_amd64.syso`, which is rebuilt from `assets/app.ico` with `go generate ./cmd/rdpwall/`.

Pushing a `v*` tag builds `rdpwall.exe` and publishes it as a GitHub release.

## Tested on

- Windows Server 2019
- Windows Server 2022

## License

[GPL-3.0](LICENSE)
