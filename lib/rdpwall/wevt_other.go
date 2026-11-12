//go:build !windows

package rdpwall

import "errors"

// evtQueryXML is only available on Windows.
func evtQueryXML(channel, query string) ([]string, error) {
	return nil, errors.New("the Windows event log is not available on this platform")
}
