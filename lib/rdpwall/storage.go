package rdpwall

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

type Storage interface {
	// PendBlockIP queues an IP for blocking. It reports true when the IP was
	// already pending or blocked.
	PendBlockIP(ip string) (bool, error)
	PendingIPsToBeBlocked() ([]string, error)
	RemovePendingIP(ip string) error

	BlockedIPs() ([]string, error)
	// BlockedAt reports when an IP was blocked.
	BlockedAt(ip string) (time.Time, bool)
	// BlockIP marks an IP as blocked since at and removes it from the pending
	// queue. An IP that is already blocked keeps its original time.
	BlockIP(ip string, at time.Time) error
	UnblockIP(ip string) error

	// IgnoreBefore is the cutoff set by the last "unban all": failures logged
	// before it no longer count toward a ban.
	IgnoreBefore() time.Time
	SetIgnoreBefore(t time.Time) error
}

type Data struct {
	PendingIPsToBeBlocked []string
	BlockedIPs            []string
	BlockedAt             map[string]time.Time `json:",omitempty"`
	IgnoreBefore          time.Time
}

// FileStorage implements Storage
type FileStorage struct {
	mutex sync.Mutex

	filename string

	data *Data
}

func NewFileStorage(filename string) (*FileStorage, error) {
	f, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data *Data
	err = json.NewDecoder(f).Decode(&data)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if data == nil {
		data = &Data{}
	}
	if data.BlockedAt == nil {
		data.BlockedAt = map[string]time.Time{}
	}

	// State files written by older versions have no block times. Start the
	// ban window now for those IPs.
	now := time.Now()
	for _, ip := range data.BlockedIPs {
		if _, ok := data.BlockedAt[ip]; !ok {
			data.BlockedAt[ip] = now
		}
	}

	return &FileStorage{
		filename: filename,
		data:     data,
	}, nil
}

func (s *FileStorage) PendBlockIP(ip string) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if contains(s.data.PendingIPsToBeBlocked, ip) || contains(s.data.BlockedIPs, ip) {
		return true, nil
	}

	s.data.PendingIPsToBeBlocked = append(s.data.PendingIPsToBeBlocked, ip)

	return false, nil
}

func (s *FileStorage) BlockedIPs() ([]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return append([]string(nil), s.data.BlockedIPs...), nil
}

func (s *FileStorage) BlockedAt(ip string) (time.Time, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	t, ok := s.data.BlockedAt[ip]
	return t, ok
}

func (s *FileStorage) PendingIPsToBeBlocked() ([]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return append([]string(nil), s.data.PendingIPsToBeBlocked...), nil
}

func (s *FileStorage) RemovePendingIP(ip string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.data.PendingIPsToBeBlocked = without(s.data.PendingIPsToBeBlocked, ip)

	return nil
}

func (s *FileStorage) BlockIP(ip string, at time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !contains(s.data.BlockedIPs, ip) {
		s.data.BlockedIPs = append(s.data.BlockedIPs, ip)
		s.data.BlockedAt[ip] = at
	}
	s.data.PendingIPsToBeBlocked = without(s.data.PendingIPsToBeBlocked, ip)

	return nil
}

func (s *FileStorage) UnblockIP(ip string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.data.BlockedIPs = without(s.data.BlockedIPs, ip)
	delete(s.data.BlockedAt, ip)
	s.data.PendingIPsToBeBlocked = without(s.data.PendingIPsToBeBlocked, ip)

	return nil
}

func (s *FileStorage) IgnoreBefore() time.Time {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.data.IgnoreBefore
}

func (s *FileStorage) SetIgnoreBefore(t time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.data.IgnoreBefore = t

	return nil
}

// Sync writes the state to disk every interval. It never returns.
func (s *FileStorage) Sync(interval time.Duration) {
	ticker := time.NewTicker(interval)

	for range ticker.C {
		if err := s.Flush(); err != nil {
			logf("STORAGE ERROR: could not save %s: %v", s.filename, err)
		}
	}
}

// Flush writes the state to disk now. The file is replaced in one step, so a
// crash mid-write cannot leave a truncated state file behind.
func (s *FileStorage) Flush() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	j, err := json.Marshal(s.data)
	if err != nil {
		return err
	}

	tmp := s.filename + ".tmp"
	if err := os.WriteFile(tmp, j, 0666); err != nil {
		return err
	}

	return os.Rename(tmp, s.filename)
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// without returns a new slice holding list minus every occurrence of v.
func without(list []string, v string) []string {
	var out []string
	for _, item := range list {
		if item != v {
			out = append(out, item)
		}
	}
	return out
}
