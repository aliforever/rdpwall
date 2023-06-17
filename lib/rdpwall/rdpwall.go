package rdpwall

import (
	"fmt"
	"github.com/Velocidex/ordereddict"
	"os"
	"os/exec"
	"strings"
	"time"
	"www.velocidex.com/golang/evtx"
)

type Quantom struct {
	storage Storage

	securityEventsXmlPath string
}

// New creates a new Quantom instance
func New(storage Storage, securityEventsXmlPath string) *Quantom {
	return &Quantom{
		storage:               storage,
		securityEventsXmlPath: securityEventsXmlPath,
	}
}

func (q *Quantom) CopyFile(from, tempFilePath string) error {
	return exec.Command("cmd", "/C", "copy", "/y", from, tempFilePath).Run()
}

func (q *Quantom) ParseFile() (map[string][]FailedAudit, error) {
	tempFilePath := "Security.evtx"

	err := q.CopyFile(q.securityEventsXmlPath, tempFilePath)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(tempFilePath, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	chunks, err := evtx.GetChunks(file)
	if err != nil {
		return nil, err
	}

	failedAudits := map[string][]FailedAudit{}

	for _, chunk := range chunks {
		records, err := chunk.Parse(0)
		if err != nil {
			return nil, err
		}

		for i := range records {
			record := records[i]

			eventMap, ok := record.Event.(*ordereddict.Dict)
			if ok {
				event, ok := ordereddict.GetMap(eventMap, "Event")
				if !ok {
					continue
				}

				eventId, _ := ordereddict.GetInt(event, "System.EventID.Value")
				if eventId != 4625 {
					continue
				}

				targetUsername, ok := ordereddict.GetString(event, "EventData.TargetUserName")
				if !ok {
					continue
				}

				targetIp, ok := ordereddict.GetString(event, "EventData.IpAddress")
				if !ok {
					continue
				}

				timeCreatedEpoch, ok := ordereddict.GetAny(event, "System.TimeCreated.SystemTime")
				if !ok {
					continue
				}

				timeCreatedEpochFloat, ok := timeCreatedEpoch.(float64)
				if !ok {
					continue
				}

				seconds := int64(timeCreatedEpochFloat)
				nanoseconds := int64((timeCreatedEpochFloat - float64(seconds)) * 1_000_000_000)

				failedAudits[targetIp] = append(failedAudits[targetIp], FailedAudit{
					Username:    targetUsername,
					Time:        time.Unix(seconds, nanoseconds),
					EventRecord: record,
				})
			}
		}
	}

	return failedAudits, nil
}

// func (q *Quantom) ReadFailedSecurityAudits(count int64) (map[string]*FailedAudits, error) {
// 	cmd := exec.Command(
// 		"wevtutil",
// 		"qe", "Security",
// 		"/rd:true",
// 		"/f:xml",
// 		fmt.Sprintf("/c:%d", count),
// 		"/q:*[System[EventID=4625]]",
// 	)
//
// 	out, err := cmd.CombinedOutput()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	xmlData := "<Events>" + string(out) + "</Events>"
//
// 	var events Events
// 	err = xml.Unmarshal([]byte(xmlData), &events)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	failedAudits := map[string]*FailedAudits{}
//
// 	for i := 0; i < len(events.Events); i++ {
// 		event := events.Events[i]
//
// 		var username string
// 		var ip string
//
// 		for _, data := range event.EventData.Data {
// 			if data.Name == "TargetUserName" {
// 				username = data.Body
// 			}
// 			if data.Name == "IpAddress" {
// 				ip = data.Body
// 			}
// 		}
//
// 		if username != "" && ip != "" {
// 			if _, ok := failedAudits[ip]; !ok {
// 				failedAudits[ip] = &FailedAudits{
// 					IpAddress: ip,
// 				}
// 			}
//
// 			failedAudits[ip].Usernames = append(failedAudits[ip].Usernames, username)
// 		}
// 	}
//
// 	return failedAudits, nil
// }

func (q *Quantom) Start() {
	go q.PendBlockIPs()
	go q.BlockIPs()

	select {}
}

func (q *Quantom) BlockIPs() {
	for {
		ips, err := q.storage.PendingIPsToBeBlocked()
		if err != nil {
			goto Continue
		}

		for _, ip := range ips {
			err = q.BlockIP(ip)
			if err != nil {
				panic(err)
			}
		}
	Continue:
		time.Sleep(5 * time.Second)
	}
}

func (q *Quantom) PendBlockIPs() {
	for {
		data, err := q.ParseFile()
		if err != nil {
			panic(err)
		}

		for ip, audits := range data {
			if ip == "" || strings.Count(ip, ".") != 3 {
				continue
			}
			if len(audits) > 3 {
				exists, err := q.storage.PendBlockIP(ip)
				if err != nil {
					panic(err)
				}

				if !exists {
					fmt.Printf("Blocking IP %s for %d failed audits\n", ip, len(audits))
				}
			}
		}

		time.Sleep(5 * time.Second)
	}
}

func (q *Quantom) BlockIP(ip string) error {
	cmd := exec.Command("netsh",
		"advfirewall",
		"firewall",
		"add",
		"rule",
		"name=BlockedByQuantom (RDP Brute Force)",
		"dir=in",
		"action=block",
		"remoteip="+ip)

	err := cmd.Run()
	if err != nil {
		return err
	}

	return q.storage.BlockIP(ip)
}
