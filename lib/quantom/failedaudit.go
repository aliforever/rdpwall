package quantom

import (
	"time"
	"www.velocidex.com/golang/evtx"
)

type FailedAudit struct {
	Username string
	Time     time.Time

	EventRecord *evtx.EventRecord
}
