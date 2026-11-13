package rdpwall

import (
	"fmt"
	"sync"
	"time"
)

const (
	// banWindow is the time window within which failed attempts are counted.
	// An IP is blocked if it exceeds failureThreshold failures within this window.
	// A blocked IP is unbanned once it has been blocked for at least this long
	// and has no failures left within the window.
	banWindow = 24 * time.Hour

	// failureThreshold is the number of recent failures above which an IP gets blocked.
	failureThreshold = 3

	// scanInterval controls how often the event log is queried.
	scanInterval = 30 * time.Second

	// blockInterval controls how often pending IPs are committed to the firewall.
	blockInterval = 5 * time.Second
)

func logf(format string, args ...interface{}) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// Firewall manages the block rules.
type Firewall interface {
	// List returns the IPs that currently have a block rule.
	List() ([]string, error)
	Add(ip string) error
	// Remove deletes the block rule for an IP. Removing an IP that has no
	// rule is not an error.
	Remove(ip string) error
}

// EventSource returns the failed logins of the last window, keyed by IP. It
// must return an error instead of a partial result: an IP missing from the
// result is treated as having no failures.
type EventSource func(window time.Duration) (map[string][]FailedAudit, error)

type Quantom struct {
	storage  Storage
	firewall Firewall
	events   EventSource
	now      func() time.Time

	// mu serialises scans, firewall flushes and UnbanAll so they never act
	// on each other's half-finished state.
	mu sync.Mutex
}

// New creates a new Quantom instance backed by the Windows Firewall and the
// Windows Security event log.
func New(storage Storage) *Quantom {
	return &Quantom{
		storage:  storage,
		firewall: netshFirewall{},
		events:   queryRecentFailures,
		now:      time.Now,
	}
}

// Start brings storage and firewall in sync, then runs the scan and block
// loops. It returns immediately.
func (q *Quantom) Start() {
	go func() {
		q.syncWithFirewall()
		go q.PendBlockIPs()
		q.BlockIPs()
	}()
}

// syncWithFirewall makes storage and firewall agree on startup. Rules that
// exist in the firewall but not in storage are imported (the state file was
// deleted or reset). IPs that storage has blocked but the firewall has no rule
// for get their rule back (the firewall was reset).
func (q *Quantom) syncWithFirewall() {
	q.mu.Lock()
	defer q.mu.Unlock()

	stored, err := q.storage.BlockedIPs()
	if err != nil {
		logf("SYNC ERROR: could not read blocked IPs: %v", err)
		return
	}

	rules, err := q.firewall.List()
	if err != nil {
		// Without the rule list we cannot tell which rules are missing.
		// Replace every rule so that none is missing and none is duplicated.
		logf("SYNC ERROR: could not list firewall rules: %v — reapplying all %d stored IP(s)", err, len(stored))
		for _, ip := range stored {
			if err := q.firewall.Remove(ip); err != nil {
				logf("SYNC ERROR: %s: %v", ip, err)
				continue
			}
			if err := q.firewall.Add(ip); err != nil {
				logf("SYNC ERROR: %s: %v", ip, err)
			}
		}
		return
	}

	inFirewall := make(map[string]struct{}, len(rules))
	for _, ip := range rules {
		inFirewall[ip] = struct{}{}
	}
	inStorage := make(map[string]struct{}, len(stored))
	for _, ip := range stored {
		inStorage[ip] = struct{}{}
	}

	imported := 0
	for ip := range inFirewall {
		if _, ok := inStorage[ip]; ok {
			continue
		}
		if err := q.storage.BlockIP(ip, q.now()); err != nil {
			logf("SYNC ERROR: import %s: %v", ip, err)
			continue
		}
		imported++
	}

	reapplied := 0
	for _, ip := range stored {
		if _, ok := inFirewall[ip]; ok {
			continue
		}
		if err := q.firewall.Add(ip); err != nil {
			logf("SYNC ERROR: reapply %s: %v", ip, err)
			continue
		}
		reapplied++
	}

	logf("SYNC: %d rule(s) in firewall, %d IP(s) in storage — imported %d, reapplied %d",
		len(rules), len(stored), imported, reapplied)
}

// BlockIPs commits pending IPs to the firewall every blockInterval. It never
// returns.
func (q *Quantom) BlockIPs() {
	for {
		q.flushPending()
		time.Sleep(blockInterval)
	}
}

func (q *Quantom) flushPending() {
	q.mu.Lock()
	defer q.mu.Unlock()

	ips, err := q.storage.PendingIPsToBeBlocked()
	if err != nil {
		logf("ERROR reading pending IPs: %v", err)
		return
	}

	for _, ip := range ips {
		if err := q.blockIP(ip); err != nil {
			logf("ERROR blocking IP %s: %v", ip, err)
		}
	}
}

// PendBlockIPs scans the event log every scanInterval. It never returns.
func (q *Quantom) PendBlockIPs() {
	for {
		if err := q.scanOnce(); err != nil {
			logf("ERROR querying event log: %v — scan skipped", err)
		}
		time.Sleep(scanInterval)
	}
}

// scanOnce reads the recent failures, queues offenders for blocking and lifts
// bans that have run their course. When the event log cannot be read in full
// it changes nothing.
func (q *Quantom) scanOnce() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	data, err := q.events(banWindow)
	if err != nil {
		return err
	}

	// Failures from before the last "unban all" no longer count.
	cutoff := q.storage.IgnoreBefore()
	failures := make(map[string]int, len(data))
	for ip, audits := range data {
		for _, a := range audits {
			if a.Time.After(cutoff) {
				failures[ip]++
			}
		}
	}

	offenders := 0
	newBanned := 0
	newUnbanned := 0

	// Block IPs that exceeded the threshold within the time window.
	for ip, count := range failures {
		if count <= failureThreshold {
			continue
		}
		offenders++
		exists, err := q.storage.PendBlockIP(ip)
		if err != nil {
			logf("ERROR pending block for IP %s: %v", ip, err)
			continue
		}
		if !exists {
			newBanned++
			logf("PENDING BLOCK: %s (%d recent failures in last %s)", ip, count, banWindow)
		}
	}

	// Remove from pending any IP that no longer has recent failures.
	pendingIPs, err := q.storage.PendingIPsToBeBlocked()
	if err != nil {
		logf("ERROR reading pending IPs: %v", err)
	}
	for _, ip := range pendingIPs {
		if failures[ip] == 0 {
			logf("REMOVING PENDING: %s (no recent failures)", ip)
			if err := q.storage.RemovePendingIP(ip); err != nil {
				logf("ERROR removing pending IP %s: %v", ip, err)
			}
		}
	}

	// Unblock IPs whose ban has lasted the full window and that have no
	// failures left in it. The block time is checked as well as the event
	// log, so a cleared or rolled-over log does not lift bans early.
	blockedIPs, err := q.storage.BlockedIPs()
	if err != nil {
		logf("ERROR reading blocked IPs: %v", err)
	}
	now := q.now()
	for _, ip := range blockedIPs {
		if failures[ip] != 0 {
			continue
		}
		if at, ok := q.storage.BlockedAt(ip); ok && now.Sub(at) < banWindow {
			continue
		}
		logf("UNBLOCKING: %s (no recent failures in last %s)", ip, banWindow)
		if err := q.unblockIP(ip); err != nil {
			logf("ERROR unblocking IP %s: %v", ip, err)
			continue
		}
		newUnbanned++
	}

	pendingCount := 0
	if p, err := q.storage.PendingIPsToBeBlocked(); err == nil {
		pendingCount = len(p)
	}
	blockedCount := 0
	if b, err := q.storage.BlockedIPs(); err == nil {
		blockedCount = len(b)
	}

	logf("── Scan ── %d IPs seen | %d offenders | pending: %d | banned: %d | +%d new | -%d unbanned",
		len(data), offenders, pendingCount, blockedCount, newBanned, newUnbanned)

	return nil
}

// BlockIP adds a firewall rule for the IP and records it as blocked.
func (q *Quantom) BlockIP(ip string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.blockIP(ip)
}

func (q *Quantom) blockIP(ip string) error {
	// Guard against duplicate firewall rules: an IP that storage already has
	// as blocked has its rule. Only clear it from the pending queue.
	if at, ok := q.storage.BlockedAt(ip); ok {
		return q.storage.BlockIP(ip, at)
	}

	if err := q.firewall.Add(ip); err != nil {
		return err
	}

	logf("FIREWALL ADD: blocking %s", ip)
	return q.storage.BlockIP(ip, q.now())
}

// UnblockIP removes the firewall rule for the IP and forgets it.
func (q *Quantom) UnblockIP(ip string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.unblockIP(ip)
}

func (q *Quantom) unblockIP(ip string) error {
	if err := q.firewall.Remove(ip); err != nil {
		return err
	}

	return q.storage.UnblockIP(ip)
}

// UnbanAll removes every firewall rule created by RdpWall and clears the
// pending queue. Failures logged before this call stop counting, so an
// unbanned IP is only banned again after it exceeds the threshold anew.
func (q *Quantom) UnbanAll() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if err := q.storage.SetIgnoreBefore(q.now()); err != nil {
		logf("UNBAN ALL ERROR: could not save cutoff: %v", err)
		return
	}

	pendingIPs, err := q.storage.PendingIPsToBeBlocked()
	if err != nil {
		logf("UNBAN ALL ERROR: could not read pending IPs: %v", err)
	}
	for _, ip := range pendingIPs {
		if err := q.storage.RemovePendingIP(ip); err != nil {
			logf("UNBAN ALL ERROR: pending %s: %v", ip, err)
		}
	}

	blockedIPs, err := q.storage.BlockedIPs()
	if err != nil {
		logf("UNBAN ALL ERROR: could not read blocked IPs: %v", err)
		return
	}

	if len(blockedIPs) == 0 {
		logf("UNBAN ALL: nothing to unban")
		return
	}

	logf("UNBAN ALL: removing %d blocked IP(s)...", len(blockedIPs))

	failed := 0
	for _, ip := range blockedIPs {
		if err := q.unblockIP(ip); err != nil {
			logf("UNBAN ALL ERROR: %s: %v", ip, err)
			failed++
		} else {
			logf("UNBAN ALL: unblocked %s", ip)
		}
	}

	if failed == 0 {
		logf("UNBAN ALL: done — all IPs unblocked")
	} else {
		logf("UNBAN ALL: done — %d succeeded, %d failed", len(blockedIPs)-failed, failed)
	}
}
