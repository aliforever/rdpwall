package main

import (
	"github.com/aliforever/rdpwall/lib/rdpwall"
	"time"
)

func main() {
	fs, err := rdpwall.NewFileStorage("failed_audits.json")
	if err != nil {
		panic(err)
	}

	go fs.Sync(time.Second * 5)

	xmlPath := `C:\Windows\System32\winevt\Logs\Security.evtx`

	q := rdpwall.New(fs, xmlPath)

	q.Start()
}
