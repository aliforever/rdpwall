package rdpwall

import (
	"encoding/xml"
	"fmt"
	"net"
	"time"
)

// evtXMLEvent is the subset of the Windows Event XML schema we care about.
type evtXMLEvent struct {
	System struct {
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// queryRecentFailures queries the Windows Security event log for failed login
// attempts (event 4625) within the last window using the native wevtapi.dll
// API directly — no PowerShell or external process spawn.
func queryRecentFailures(window time.Duration) (map[string][]FailedAudit, error) {
	query := fmt.Sprintf(
		"*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= %d]]]",
		int64(window/time.Millisecond),
	)

	xmlEvents, err := evtQueryXML("Security", query)
	if err != nil {
		return nil, fmt.Errorf("evtQueryXML: %w", err)
	}

	failedAudits := map[string][]FailedAudit{}
	for _, xmlStr := range xmlEvents {
		ip, audit, err := parseFailedLogin(xmlStr)
		if err != nil {
			return nil, err
		}
		if ip == "" {
			continue
		}
		failedAudits[ip] = append(failedAudits[ip], audit)
	}

	return failedAudits, nil
}

// parseFailedLogin reads one rendered 4625 event. It returns an empty ip for
// events that carry no source address (local logons report "-").
func parseFailedLogin(xmlStr string) (ip string, audit FailedAudit, err error) {
	var ev evtXMLEvent
	if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
		return "", FailedAudit{}, fmt.Errorf("parse event: %w", err)
	}

	for _, d := range ev.EventData.Data {
		switch d.Name {
		case "IpAddress":
			ip = d.Value
		case "TargetUserName":
			audit.Username = d.Value
		}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", FailedAudit{}, nil
	}

	audit.Time, err = time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
	if err != nil {
		return "", FailedAudit{}, fmt.Errorf("parse event time: %w", err)
	}

	return parsed.String(), audit, nil
}
