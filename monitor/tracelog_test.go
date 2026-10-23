// SPDX-License-Identifier: AGPL-3.0-or-later

package monitor

import (
	"strings"
	"testing"
	"time"
)

func TestTraceLogLines(t *testing.T) {
	var b strings.Builder
	l := NewTraceLog(&b)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	l.Observe(&Record{Time: at, RemoteAddr: "10.0.0.1:1234", Method: "GET", Host: "example.com",
		URI: "/a?b=1", Proto: "HTTP/1.1", Status: 200, Trace: "/a ?b=N"})
	l.Observe(&Record{Time: at, RemoteAddr: "[::1]:80", Method: "POST", URI: "/x", Proto: "HTTP/2.0", Status: 404})
	l.Observe(&Record{Time: at, RemoteAddr: "10.0.0.1:1234", Method: "GET", Host: "example.com",
		URI: "/b", Proto: "HTTP/1.1", Status: 403, Blocked: true, Trace: "/b"})
	l.Observe(&Record{Time: at, RemoteAddr: "10.0.0.1:1234", Method: "GET", Host: "example.com",
		URI: "/c", Proto: "HTTP/1.1", Status: 403, Blocked: true, Malformed: true})
	want := `10.0.0.1 - - [02/Jan/2026:03:04:05 +0000] "GET /a?b=1 HTTP/1.1" 200 - example.com /a ?b=N` + "\n" +
		`::1 - - [02/Jan/2026:03:04:05 +0000] "POST /x HTTP/2.0" 404 - - NOTRACE` + "\n" +
		`10.0.0.1 - - [02/Jan/2026:03:04:05 +0000] "GET /b HTTP/1.1" 403 - example.com BLOCKED /b` + "\n" +
		`10.0.0.1 - - [02/Jan/2026:03:04:05 +0000] "GET /c HTTP/1.1" 403 - example.com BLOCKED MALFORMED NOTRACE` + "\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}
