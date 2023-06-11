package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
)

type Event struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
			Guid string `xml:"Guid,attr"`
		} `xml:"Provider"`
		EventID string `xml:"EventID"`
		// Include all other relevant fields here...
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`
			Body string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

type Events struct {
	XMLName xml.Name `xml:"Events"`
	Events  []Event  `xml:"Event"`
}

func main() {
	cmd := exec.Command("wevtutil", "qe", "Security", "/rd:true", "/f:xml", "/c:200", "/q:*[System[EventID=4625]]")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}

	// Combine the events into a single string with a root node.
	xmlData := "<Events>" + string(out) + "</Events>"

	var events Events
	err = xml.Unmarshal([]byte(xmlData), &events)
	if err != nil {
		fmt.Printf("error: %v", err)
		return
	}

	for i := 0; i < len(events.Events); i++ {
		event := events.Events[i]

		for _, data := range event.EventData.Data {
			if data.Name == "TargetUserName" {
				fmt.Printf("Username: %s - ", data.Body)
			}
			if data.Name == "IpAddress" {
				fmt.Printf("IpAddress: %s - ", data.Body)
			}
			// fmt.Println("Data Name: " + data.Name)
			// fmt.Println("Data Body: " + data.Body)
		}
		fmt.Println()
	}
}
