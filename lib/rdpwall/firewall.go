package rdpwall

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"unicode/utf16"
)

const firewallRuleName = "BlockedByQuantom (RDP Brute Force)"

// netshFirewall implements Firewall on top of the Windows Firewall. Every
// blocked IP gets its own inbound block rule named firewallRuleName.
type netshFirewall struct{}

// encodedPS encodes a PowerShell script as base64 UTF-16 LE for use with
// powershell.exe -EncodedCommand, which avoids all quoting issues.
func encodedPS(script string) string {
	units := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (netshFirewall) List() ([]string, error) {
	script := "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; " +
		"Get-NetFirewallRule -DisplayName '" + firewallRuleName + "' -ErrorAction SilentlyContinue | " +
		"Get-NetFirewallAddressFilter | " +
		"Select-Object -ExpandProperty RemoteAddress; " +
		// Finding no rule leaves the last command marked as failed, which
		// powershell.exe turns into exit code 1. Real errors stop the script
		// before this line.
		"exit 0"

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPS(script))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseAddressList(string(stdout)), nil
}

// parseAddressList extracts the IPs from one-address-per-line output. The
// firewall reports a single host either bare or with a full-length mask.
func parseAddressList(out string) []string {
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		ip := strings.TrimSpace(line)
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		if net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (netshFirewall) Add(ip string) error {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+firewallRuleName,
		"dir=in",
		"action=block",
		"remoteip="+ip).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f netshFirewall) Remove(ip string) error {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+firewallRuleName,
		"remoteip="+ip).CombinedOutput()
	if err == nil {
		return nil
	}

	// netsh exits with the same code when the delete failed and when there
	// was no rule to delete. Look at the firewall to tell the two apart.
	rules, listErr := f.List()
	if listErr == nil && !contains(rules, ip) {
		return nil
	}

	return fmt.Errorf("netsh delete: %w: %s", err, strings.TrimSpace(string(out)))
}
