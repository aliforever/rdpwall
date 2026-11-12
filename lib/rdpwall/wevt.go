//go:build windows

package rdpwall

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath = 0x1
	evtRenderEventXml   = 1
	evtBatchSize        = 64
)

// evtQueryXML queries a Windows Event Log channel and returns each matching
// event rendered as a UTF-8 XML string, using the native wevtapi.dll API
// directly — no PowerShell or external process spawn needed.
func evtQueryXML(channel, query string) ([]string, error) {
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, fmt.Errorf("EvtQuery channel: %w", err)
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, fmt.Errorf("EvtQuery query: %w", err)
	}

	hQuery, _, e := procEvtQuery.Call(
		0, // NULL session (local machine)
		uintptr(unsafe.Pointer(ch)),
		uintptr(unsafe.Pointer(q)),
		evtQueryChannelPath,
	)
	if hQuery == 0 {
		return nil, fmt.Errorf("EvtQuery: %w", e)
	}
	defer procEvtClose.Call(hQuery)

	var results []string
	handles := make([]uintptr, evtBatchSize)

	for {
		var returned uint32
		r, _, e := procEvtNext.Call(
			hQuery,
			uintptr(evtBatchSize),
			uintptr(unsafe.Pointer(&handles[0])),
			uintptr(2000), // 2s timeout (ignored for queries, required by API)
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 {
			// ERROR_NO_MORE_ITEMS = normal end of result set. Anything else
			// means the result is incomplete, and callers must not act on it.
			if e != windows.ERROR_NO_MORE_ITEMS {
				return nil, fmt.Errorf("EvtNext: %w", e)
			}
			break
		}

		var renderErr error
		for i := uint32(0); i < returned; i++ {
			if renderErr == nil {
				var xml string
				if xml, renderErr = renderEventXML(handles[i]); renderErr == nil {
					results = append(results, xml)
				}
			}
			procEvtClose.Call(handles[i])
		}
		if renderErr != nil {
			return nil, renderErr
		}
	}

	return results, nil
}

// renderEventXML renders a single event handle to a UTF-8 XML string.
func renderEventXML(h uintptr) (string, error) {
	var bufferUsed, propertyCount uint32
	bufferSize := uint32(8192) // initial buffer — grows if needed
	buffer := make([]byte, bufferSize)

	for {
		r, _, e := procEvtRender.Call(
			0, // NULL context → render as XML
			h,
			evtRenderEventXml,
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&bufferUsed)),
			uintptr(unsafe.Pointer(&propertyCount)),
		)
		if r != 0 {
			break // success
		}
		if e == windows.ERROR_INSUFFICIENT_BUFFER && bufferUsed > bufferSize {
			bufferSize = bufferUsed
			buffer = make([]byte, bufferSize)
			continue
		}
		return "", fmt.Errorf("EvtRender: %w", e)
	}

	// Strip UTF-16 null terminator (2 bytes) before converting
	data := buffer[:bufferUsed]
	if len(data) >= 2 && data[len(data)-2] == 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-2]
	}

	return utf16leToString(data), nil
}

func utf16leToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}
