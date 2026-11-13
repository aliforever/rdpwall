//go:build !windows

package rdpwall

import "errors"

// evtQueryXML is only available on Windows.
func evtQueryXML(channel, query string, handle func(xml string) error) error {
	return errors.New("the Windows event log is not available on this platform")
}
