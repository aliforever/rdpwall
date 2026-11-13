package rdpwall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

type fakeFirewall struct {
	rules     map[string]int // ip -> number of rules
	listErr   error
	removeErr error
}

func (f *fakeFirewall) List() ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var ips []string
	for ip := range f.rules {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}

func (f *fakeFirewall) Add(ip string) error {
	f.rules[ip]++
	return nil
}

func (f *fakeFirewall) Remove(ip string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.rules, ip)
	return nil
}

type harness struct {
	t       *testing.T
	q       *Quantom
	fw      *fakeFirewall
	storage *FileStorage
	now     time.Time
	events  map[string][]FailedAudit
	evErr   error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fs, err := NewFileStorage(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t:       t,
		fw:      &fakeFirewall{rules: map[string]int{}},
		storage: fs,
		now:     time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC),
		events:  map[string][]FailedAudit{},
	}
	h.q = &Quantom{
		storage:  fs,
		firewall: h.fw,
		now:      func() time.Time { return h.now },
		events: func(window time.Duration) (map[string][]FailedAudit, error) {
			if h.evErr != nil {
				return nil, h.evErr
			}
			// Like the real query, only return what is inside the window.
			out := map[string][]FailedAudit{}
			for ip, audits := range h.events {
				for _, a := range audits {
					if h.now.Sub(a.Time) <= window {
						out[ip] = append(out[ip], a)
					}
				}
			}
			return out, nil
		},
	}
	return h
}

// fail records n failed logins from ip at the current time.
func (h *harness) fail(ip string, n int) {
	for i := 0; i < n; i++ {
		h.events[ip] = append(h.events[ip], FailedAudit{Username: "admin", Time: h.now})
	}
}

// cycle runs one scan followed by one firewall flush.
func (h *harness) cycle() {
	h.t.Helper()
	if err := h.q.scanOnce(); err != nil {
		h.t.Fatalf("scanOnce: %v", err)
	}
	h.q.flushPending()
}

func (h *harness) blocked() []string {
	ips, _ := h.storage.BlockedIPs()
	sort.Strings(ips)
	return ips
}

func (h *harness) assertBlocked(want ...string) {
	h.t.Helper()
	if got := h.blocked(); !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
		h.t.Fatalf("blocked in storage = %v, want %v", got, want)
	}
	rules, _ := h.fw.List()
	if !reflect.DeepEqual(rules, want) && !(len(rules) == 0 && len(want) == 0) {
		h.t.Fatalf("firewall rules = %v, want %v", rules, want)
	}
}

func TestBlocksOnlyAboveThreshold(t *testing.T) {
	h := newHarness(t)
	h.fail("1.1.1.1", failureThreshold)
	h.fail("2.2.2.2", failureThreshold+1)
	h.cycle()
	h.assertBlocked("2.2.2.2")

	// A second cycle must not add a second rule.
	h.cycle()
	if n := h.fw.rules["2.2.2.2"]; n != 1 {
		t.Fatalf("got %d rules for 2.2.2.2, want 1", n)
	}
}

func TestUnbansAfterWindow(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	h.cycle()
	h.assertBlocked("2.2.2.2")

	h.now = h.now.Add(banWindow - time.Minute)
	h.cycle()
	h.assertBlocked("2.2.2.2")

	h.now = h.now.Add(2 * time.Minute)
	h.cycle()
	h.assertBlocked()
}

func TestEventLogErrorChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	h.cycle()
	h.now = h.now.Add(banWindow + time.Hour)

	h.evErr = errors.New("EvtNext: stale query")
	if err := h.q.scanOnce(); err == nil {
		t.Fatal("scanOnce returned no error for a failed event query")
	}
	h.assertBlocked("2.2.2.2")
}

func TestClearedEventLogDoesNotLiftBansEarly(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	h.cycle()

	h.events = map[string][]FailedAudit{} // the Security log was cleared
	h.now = h.now.Add(time.Hour)
	h.cycle()
	h.assertBlocked("2.2.2.2")
}

func TestUnbanAllIsNotUndoneByNextScan(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	h.fail("3.3.3.3", 5)
	h.cycle()
	h.assertBlocked("2.2.2.2", "3.3.3.3")

	h.now = h.now.Add(time.Minute)
	h.q.UnbanAll()
	h.assertBlocked()

	h.now = h.now.Add(time.Minute)
	h.cycle()
	h.cycle()
	h.assertBlocked()

	// Failures after the unban count again, from zero.
	h.fail("2.2.2.2", failureThreshold)
	h.cycle()
	h.assertBlocked()
	h.fail("2.2.2.2", 1)
	h.cycle()
	h.assertBlocked("2.2.2.2")
}

func TestUnbanAllClearsPending(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	if err := h.q.scanOnce(); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Second)
	h.q.UnbanAll()
	h.q.flushPending()
	h.assertBlocked()
}

func TestFailedRuleRemovalKeepsIPBlocked(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	h.cycle()

	h.fw.removeErr = errors.New("access denied")
	h.now = h.now.Add(banWindow + time.Hour)
	h.cycle()
	h.assertBlocked("2.2.2.2")

	h.fw.removeErr = nil
	h.cycle()
	h.assertBlocked()
}

func TestAlreadyBlockedIPLeavesPendingQueue(t *testing.T) {
	h := newHarness(t)
	h.fail("2.2.2.2", 5)
	h.cycle()

	// A state file from an older version can list an IP as both.
	h.storage.data.PendingIPsToBeBlocked = []string{"2.2.2.2"}
	h.q.flushPending()

	if pending, _ := h.storage.PendingIPsToBeBlocked(); len(pending) != 0 {
		t.Fatalf("pending = %v, want empty", pending)
	}
	if n := h.fw.rules["2.2.2.2"]; n != 1 {
		t.Fatalf("got %d rules for 2.2.2.2, want 1", n)
	}
}

func TestSyncImportsAndReappliesRules(t *testing.T) {
	h := newHarness(t)
	h.storage.BlockIP("1.1.1.1", h.now) // in storage, rule lost
	h.storage.BlockIP("2.2.2.2", h.now) // in both
	h.fw.rules["2.2.2.2"] = 1
	h.fw.rules["3.3.3.3"] = 1 // rule exists, storage lost

	h.q.syncWithFirewall()
	h.assertBlocked("1.1.1.1", "2.2.2.2", "3.3.3.3")
	for ip, n := range h.fw.rules {
		if n != 1 {
			t.Fatalf("got %d rules for %s, want 1", n, ip)
		}
	}
}

func TestSyncWithoutRuleListLeavesOneRulePerIP(t *testing.T) {
	h := newHarness(t)
	h.storage.BlockIP("1.1.1.1", h.now)
	h.storage.BlockIP("2.2.2.2", h.now)
	h.fw.rules["2.2.2.2"] = 1
	h.fw.listErr = errors.New("powershell missing")

	h.q.syncWithFirewall()

	h.fw.listErr = nil
	h.assertBlocked("1.1.1.1", "2.2.2.2")
	for ip, n := range h.fw.rules {
		if n != 1 {
			t.Fatalf("got %d rules for %s, want 1", n, ip)
		}
	}
}

func TestStorageSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	fs, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	fs.BlockIP("1.1.1.1", at)
	fs.BlockIP("2.2.2.2", at)
	fs.PendBlockIP("3.3.3.3")
	fs.SetIgnoreBefore(at)
	if err := fs.Flush(); err != nil {
		t.Fatal(err)
	}

	// A shorter state must fully replace the longer one on disk.
	fs.UnblockIP("2.2.2.2")
	if err := fs.Flush(); err != nil {
		t.Fatal(err)
	}

	fs2, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fs2.BlockedIPs(); !reflect.DeepEqual(got, []string{"1.1.1.1"}) {
		t.Fatalf("blocked = %v", got)
	}
	if got, _ := fs2.PendingIPsToBeBlocked(); !reflect.DeepEqual(got, []string{"3.3.3.3"}) {
		t.Fatalf("pending = %v", got)
	}
	if got, ok := fs2.BlockedAt("1.1.1.1"); !ok || !got.Equal(at) {
		t.Fatalf("BlockedAt = %v, %v", got, ok)
	}
	if !fs2.IgnoreBefore().Equal(at) {
		t.Fatalf("IgnoreBefore = %v", fs2.IgnoreBefore())
	}
}

func TestStorageReadsStateFileOfOlderVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := `{"PendingIPsToBeBlocked":["3.3.3.3"],"FailedSecurityAudits":null,"BlockedIPs":["1.1.1.1"]}`
	if err := os.WriteFile(path, []byte(old), 0666); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fs.BlockedIPs(); !reflect.DeepEqual(got, []string{"1.1.1.1"}) {
		t.Fatalf("blocked = %v", got)
	}
	// Without a recorded block time the ban window starts at load.
	if at, ok := fs.BlockedAt("1.1.1.1"); !ok || time.Since(at) > time.Minute {
		t.Fatalf("BlockedAt = %v, %v", at, ok)
	}
}

func TestParseFailedLogin(t *testing.T) {
	const event = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-01-10T11:59:58.1234567Z'/></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='IpAddress'>%s</Data></EventData></Event>`

	ip, audit, err := parseFailedLogin(fmt.Sprintf(event, "203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.7" || audit.Username != "admin" {
		t.Fatalf("got ip=%q audit=%+v", ip, audit)
	}
	if want := time.Date(2026, 1, 10, 11, 59, 58, 123456700, time.UTC); !audit.Time.Equal(want) {
		t.Fatalf("time = %v, want %v", audit.Time, want)
	}

	// Local logons carry no source address and are skipped, not errors.
	if ip, _, err := parseFailedLogin(fmt.Sprintf(event, "-")); err != nil || ip != "" {
		t.Fatalf("got ip=%q err=%v for an event without address", ip, err)
	}

	if _, _, err := parseFailedLogin("<Event><System>"); err == nil {
		t.Fatal("no error for truncated XML")
	}
}

func TestParseAddressList(t *testing.T) {
	out := "203.0.113.7\r\n198.51.100.2/255.255.255.255\r\n2001:db8::1\r\nAny\r\n\r\n"
	want := []string{"203.0.113.7", "198.51.100.2", "2001:db8::1"}
	if got := parseAddressList(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestEncodedPS(t *testing.T) {
	// "hi" as UTF-16 LE is 68 00 69 00.
	if got := encodedPS("hi"); got != "aABpAA==" {
		t.Fatalf("got %q", got)
	}
}
