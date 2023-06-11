package main

import (
	"quantom/lib/quantom"
	"time"
)

func main() {
	fs, err := quantom.NewFileStorage("failed_audits.json")
	if err != nil {
		panic(err)
	}

	go fs.Sync(time.Second * 5)

	xmlPath := `C:\Windows\System32\winevt\Logs\Security.evtx`

	q := quantom.New(fs, xmlPath)

	q.Start()
}
