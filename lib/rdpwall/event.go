package rdpwall

import "encoding/xml"

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
