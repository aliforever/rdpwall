package quantom

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Storage interface {
	ReadFailedSecurityAudits() (map[string][]FailedAudit, error) // IP Address -> FailedAudit{ Username, Count }
	WriteFailedSecurityAudits(map[string][]FailedAudit) error
	PendBlockIP(ip string) (bool, error)
	PendingIPsToBeBlocked() ([]string, error)
	BlockedIPs() ([]string, error)
	removePendingIP(ip string) error
	BlockIP(ip string) error
}

type Data struct {
	PendingIPsToBeBlocked []string
	FailedSecurityAudits  map[string][]FailedAudit
	BlockedIPs            []string
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
	if err != nil {
		if err.Error() != "EOF" {
			return nil, err
		} else {
			data = &Data{}
			err = nil
		}
	}

	return &FileStorage{
		filename: filename,
		data:     data,
	}, nil
}

func (s *FileStorage) ReadFailedSecurityAudits() (map[string][]FailedAudit, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	file, err := os.OpenFile(s.filename, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var failedAudits map[string][]FailedAudit

	err = json.NewDecoder(file).Decode(&failedAudits)
	if err != nil {
		return nil, err
	}

	return failedAudits, nil
}

func (s *FileStorage) WriteFailedSecurityAudits(failedAudits map[string][]FailedAudit) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	file, err := os.OpenFile(s.filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(failedAudits)
}

func (s *FileStorage) PendBlockIP(ip string) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	foundInPend := false
	for _, pendingIP := range s.data.PendingIPsToBeBlocked {
		if pendingIP == ip {
			foundInPend = true
			break
		}
	}

	if foundInPend {
		return true, nil
	}

	foundInBlocked := false
	for _, blockedIP := range s.data.BlockedIPs {
		if blockedIP == ip {
			foundInBlocked = true
			break
		}
	}

	if !foundInBlocked {
		s.data.PendingIPsToBeBlocked = append(s.data.PendingIPsToBeBlocked, ip)
	}

	return foundInBlocked, nil
}

func (s *FileStorage) BlockedIPs() ([]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.data.BlockedIPs, nil
}

func (s *FileStorage) PendingIPsToBeBlocked() ([]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.data.PendingIPsToBeBlocked, nil
}

func (s *FileStorage) Sync(interval time.Duration) {
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			s.sync()
		}
	}
}

func (s *FileStorage) sync() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	file, err := os.OpenFile(s.filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	j, err := json.Marshal(s.data)
	if err != nil {
		panic(err)
	}

	_, err = file.Write(j)
	if err != nil {
		panic(err)
	}

	fmt.Println("synced")
}

func (s *FileStorage) BlockIP(ip string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	found := false
	for _, blockedIP := range s.data.BlockedIPs {
		if blockedIP == ip {
			found = true
			break
		}
	}

	if !found {
		s.data.BlockedIPs = append(s.data.BlockedIPs, ip)
	}

	return s.removePendingIP(ip)
}

func (s *FileStorage) removePendingIP(ip string) error {
	var newPendingIPs []string

	for _, pendingIP := range s.data.PendingIPsToBeBlocked {
		if pendingIP != ip {
			newPendingIPs = append(newPendingIPs, pendingIP)
		}
	}

	s.data.PendingIPsToBeBlocked = newPendingIPs

	return nil
}
