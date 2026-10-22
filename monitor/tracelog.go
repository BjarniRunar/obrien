// SPDX-License-Identifier: AGPL-3.0-or-later

package monitor

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// NoTrace stands in for the trace on TraceLog lines of untraced requests.
const NoTrace = "NOTRACE"

// TraceLog is a Hook writing one line per request to w, in the style of an
// HTTP access log with the host and trace appended:
//
//	1.2.3.4 - - [02/Jan/2006:15:04:05 -0700] "GET /a HTTP/1.1" 200 - example.com <trace>
type TraceLog struct {
	mu sync.Mutex
	w  io.Writer
}

func NewTraceLog(w io.Writer) *TraceLog {
	return &TraceLog{w: w}
}

func (l *TraceLog) Observe(rec *Record) {
	line := FormatTraceLine(rec)
	l.mu.Lock()
	// A failed write cannot be reported from a hook, and must not affect
	// the request, so it is dropped.
	_, _ = io.WriteString(l.w, line)
	l.mu.Unlock()
}

// FormatTraceLine returns rec as a TraceLog line, including the newline.
func FormatTraceLine(rec *Record) string {
	addr := rec.RemoteAddr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	t := rec.Trace
	if t == "" {
		t = NoTrace
	}
	host := rec.Host
	if host == "" {
		host = "-"
	}
	return fmt.Sprintf("%s - - [%s] %q %d - %s %s\n",
		addr, rec.Time.Format("02/Jan/2006:15:04:05 -0700"),
		rec.Method+" "+rec.URI+" "+rec.Proto, rec.Status, oneLine(host), oneLine(t))
}

// oneLine keeps a field from breaking the line apart; net/http already
// refuses control characters in hosts, and traces are a single line.
func oneLine(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}
