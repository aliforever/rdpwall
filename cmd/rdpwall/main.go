//go:build windows

package main

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aliforever/rdpwall/lib/rdpwall"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ── Win32 helpers ────────────────────────────────────────────────────────────

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	user32               = windows.NewLazySystemDLL("user32.dll")
	getConsoleWin        = kernel32.NewProc("GetConsoleWindow")
	showWindowProc       = user32.NewProc("ShowWindow")
	isIconicProc         = user32.NewProc("IsIconic")
	setForegroundWinProc = user32.NewProc("SetForegroundWindow")
	bringWindowToTopProc = user32.NewProc("BringWindowToTop")
)

const (
	swHide     = 0
	swShow     = 5
	swMinimize = 6
	swRestore  = 9
)

func consoleHwnd() uintptr {
	hwnd, _, _ := getConsoleWin.Call()
	return hwnd
}

func showConsole() {
	hwnd := consoleHwnd()
	showWindowProc.Call(hwnd, swShow)
	showWindowProc.Call(hwnd, swRestore)
	setForegroundWinProc.Call(hwnd)
	bringWindowToTopProc.Call(hwnd)
}

func hideConsole() {
	showWindowProc.Call(consoleHwnd(), swHide)
}

func isIconic() bool {
	ret, _, _ := isIconicProc.Call(consoleHwnd())
	return ret != 0
}

// watchMinimize hides the console window whenever the user minimises it.
func watchMinimize() {
	for {
		if isIconic() {
			hideConsole()
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// ── Launch on startup (scheduled task) ───────────────────────────────────────

func logf(format string, args ...interface{}) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

const (
	startupTaskName = "RdpWall"

	// Older versions registered a HKCU Run value. It started RdpWall without
	// administrator rights, so it is only read and removed now.
	legacyRunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	legacyRunKeyName = "RdpWall"
)

// runPowerShell runs a script through powershell.exe -EncodedCommand (base64
// UTF-16 LE), which avoids all quoting issues.
func runPowerShell(script string) error {
	units := utf16.Encode([]rune("$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; " + script))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// psQuote returns s as a PowerShell single-quoted string literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func legacyRunValueExists() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, legacyRunKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(legacyRunKeyName)
	return err == nil
}

func removeLegacyRunValue() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, legacyRunKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue(legacyRunKeyName)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

// isStartupEnabled reports whether RdpWall is set to start at logon.
func isStartupEnabled() bool {
	if exec.Command("schtasks", "/Query", "/TN", startupTaskName).Run() == nil {
		return true
	}
	return legacyRunValueExists()
}

// enableStartup registers a scheduled task that starts RdpWall when the
// current user logs on. The task runs with the highest privileges, because
// RdpWall needs administrator rights, and starts in the executable's folder.
func enableStartup() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	script := "$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name; " +
		"$action = New-ScheduledTaskAction -Execute " + psQuote(exe) + " -WorkingDirectory " + psQuote(filepath.Dir(exe)) + "; " +
		"$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user; " +
		"$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest; " +
		// By default a task is stopped after 3 days and does not run on battery.
		"$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; " +
		"Register-ScheduledTask -TaskName " + psQuote(startupTaskName) + " -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null"

	if err := runPowerShell(script); err != nil {
		return err
	}

	return removeLegacyRunValue()
}

// disableStartup removes the scheduled task and the Run value of older versions.
func disableStartup() error {
	if exec.Command("schtasks", "/Query", "/TN", startupTaskName).Run() == nil {
		out, err := exec.Command("schtasks", "/Delete", "/TN", startupTaskName, "/F").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	return removeLegacyRunValue()
}

// ── Tray icon ────────────────────────────────────────────────────────────────

// trayIcon is built from the drawings in assets/. The tray library always
// loads the 32px frame and lets Windows scale it down, so that frame holds the
// 16px drawing doubled pixel for pixel: scaled back to 16px it comes out exact
// instead of blurred.
//
//go:embed tray.ico
var trayIcon []byte

// ── Entry point ──────────────────────────────────────────────────────────────

func main() {
	// Keep the state file next to the executable, so that it is the same
	// file no matter which folder RdpWall is started from.
	statePath := "failed_audits.json"
	if exe, err := os.Executable(); err == nil {
		statePath = filepath.Join(filepath.Dir(exe), statePath)
	}

	fs, err := rdpwall.NewFileStorage(statePath)
	if err != nil {
		fmt.Printf("could not open %s: %v\n", statePath, err)
		os.Exit(1)
	}

	go fs.Sync(5 * time.Second)

	q := rdpwall.New(fs)

	systray.Run(func() { onReady(q) }, func() {
		if err := fs.Flush(); err != nil {
			logf("STORAGE ERROR: could not save state on exit: %v", err)
		}
	})
}

func onReady(q *rdpwall.Quantom) {
	systray.SetIcon(trayIcon)
	systray.SetTitle("RdpWall")
	systray.SetTooltip("RdpWall – RDP brute-force protection")

	mShow := systray.AddMenuItem("Show Console", "Bring the console window to front")
	mHide := systray.AddMenuItem("Hide Console", "Hide the console window to tray")
	systray.AddSeparator()
	mStartup := systray.AddMenuItemCheckbox(
		"Launch on Startup",
		"Start RdpWall automatically when Windows starts",
		isStartupEnabled(),
	)
	systray.AddSeparator()
	mUnbanAll := systray.AddMenuItem("Unban All", "Remove all firewall blocks created by RdpWall")
	systray.AddSeparator()
	mExit := systray.AddMenuItem("Exit", "Stop RdpWall and quit")

	// Start the protection engine.
	q.Start()

	// Poll for minimize-to-tray.
	go watchMinimize()

	// Handle tray menu clicks.
	for {
		select {
		case <-mShow.ClickedCh:
			showConsole()
		case <-mHide.ClickedCh:
			hideConsole()
		case <-mStartup.ClickedCh:
			if mStartup.Checked() {
				if err := disableStartup(); err != nil {
					logf("STARTUP ERROR: could not disable: %v", err)
				} else {
					mStartup.Uncheck()
				}
			} else {
				if err := enableStartup(); err != nil {
					logf("STARTUP ERROR: could not enable: %v", err)
				} else {
					mStartup.Check()
				}
			}
		case <-mUnbanAll.ClickedCh:
			go q.UnbanAll()
		case <-mExit.ClickedCh:
			systray.Quit()
			return
		}
	}
}
