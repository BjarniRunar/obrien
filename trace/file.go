// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"bytes"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// maxFile caps how much of a file is parsed as JSON or XML.
const maxFile = 20 << 10

// sniffLen is how much of a file is kept to tell its type.
const sniffLen = 512

// fileTok tokenizes one file: a whole body, or one multipart part. JSON and
// XML are parsed up to maxFile bytes and emitted as their kind and tokens,
// JSON with each object's keys sorted; anything else is OTHER, its sniffed
// media type and a size bucket. TRUNC follows a file that was cut short,
// and INVALID replaces the tokens of one that does not parse. Nothing is
// appended to out until the file ends.
type fileTok struct {
	out    *[]string
	kind   string // JSON, XML or OTHER; "" until sniffed
	head   []byte
	n      int64 // bytes written
	fed    int64 // bytes passed to tok
	tokens []string
	tok    interface {
		write([]byte) bool
		end() bool
		repair()
	}
	bad bool
}

// structured returns the kind of file a media type declares, or "" if it
// must be sniffed.
func structured(mt string) string {
	switch {
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return "JSON"
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return "XML"
	}
	return ""
}

func newFile(out *[]string, kind string) *fileTok {
	f := &fileTok{out: out}
	if kind != "" {
		f.start(kind)
	}
	return f
}

func (f *fileTok) start(kind string) {
	f.kind = kind
	switch kind {
	case "JSON":
		f.tok = newJSON(&f.tokens)
	case "XML":
		f.tok = newXML(&f.tokens)
	}
}

func (f *fileTok) write(p []byte) bool {
	f.n += int64(len(p))
	if f.kind == "" {
		take := min(len(p), sniffLen-len(f.head))
		f.head = append(f.head, p[:take]...)
		if p = p[take:]; len(f.head) < sniffLen {
			return true
		}
		f.sniff()
	}
	f.feed(p)
	return true
}

// sniff takes data starting with '{' or '[' for JSON, and with '<' for XML
// unless it looks like HTML.
func (f *fileTok) sniff() {
	t := bytes.TrimLeft(f.head, " \t\r\n")
	switch {
	case len(t) > 0 && (t[0] == '{' || t[0] == '['):
		f.start("JSON")
	case len(t) > 0 && t[0] == '<' && !strings.HasPrefix(http.DetectContentType(f.head), "text/html"):
		f.start("XML")
	default:
		f.start("OTHER")
	}
	f.feed(f.head)
}

func (f *fileTok) feed(p []byte) {
	if f.tok == nil || f.bad {
		return
	}
	if room := maxFile - f.fed; int64(len(p)) > room {
		p = p[:room]
	}
	f.fed += int64(len(p))
	if !f.tok.write(p) {
		f.bad = true
	}
}

// end emits the file; complete is false if it was cut off before its end.
func (f *fileTok) end(complete bool) bool {
	if f.kind == "" {
		f.sniff()
	}
	truncated := !complete
	*f.out = append(*f.out, f.kind)
	if f.tok == nil {
		mt, _, _ := mime.ParseMediaType(http.DetectContentType(f.head))
		*f.out = append(*f.out, keyOf(mt), "SZ"+strconv.Itoa(sizeBucket(f.n)))
	} else {
		truncated = truncated || f.n > f.fed
		if truncated && !f.bad {
			f.tok.repair()
		}
		switch {
		case f.bad || !f.tok.end():
			*f.out = append(*f.out, "INVALID")
		case f.kind == "JSON":
			*f.out = append(*f.out, sortJSON(f.tokens)...)
		default:
			*f.out = append(*f.out, f.tokens...)
		}
	}
	if truncated {
		*f.out = append(*f.out, "TRUNC")
	}
	return true
}

// sizeBucket is the number of hex digits in n: 0 for empty, 1 up to 15
// bytes, 2 up to 255, 3 up to 4 KiB, 4 up to 64 KiB, and so on.
func sizeBucket(n int64) int {
	b := 0
	for ; n > 0; n >>= 4 {
		b++
	}
	return b
}
