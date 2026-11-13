package rdpwall

import "time"

type FailedAudit struct {
	Username string
	Time     time.Time
}
