// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"errors"
	"io"
	"mime"
	"strings"
	"sync"
)

// Body wraps a request body, tokenizing it as whoever consumes it reads it,
// so the body is traced without being buffered. It is safe to trace while
// another goroutine reads, as the HTTP transport may still be sending the
// body after the response has arrived.
type Body struct {
	rc   io.ReadCloser
	kind string // JSON, XML, FORM, MULTIPART or OTHER

	mu     sync.Mutex
	tokens []string
	tok    tokenizer // nil once the body failed to parse
	total  int64
	ended  bool // read to the end, or to where the client stopped sending
	err    bool
}

type tokenizer interface {
	write(p []byte) bool
	end() bool
}

// formTok adapts form to tokenizer; its pairs are only emitted at the end,
// once they can be sorted.
type formTok struct {
	f   *form
	out *[]string
}

func (t formTok) write(p []byte) bool { t.f.write(p); return true }
func (t formTok) end() bool           { t.f.end(t.out); return true }

type otherTok struct{}

func (otherTok) write([]byte) bool { return true }
func (otherTok) end() bool         { return true }

// NewBody wraps rc, choosing how to tokenize it from its Content-Type.
func NewBody(rc io.ReadCloser, contentType string) *Body {
	b := &Body{rc: rc}
	mt, params, _ := mime.ParseMediaType(contentType)
	switch {
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		b.kind, b.tok = "JSON", newJSON(&b.tokens)
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		b.kind, b.tok = "XML", newXML(&b.tokens)
	case mt == "application/x-www-form-urlencoded":
		b.kind, b.tok = "FORM", formTok{newForm(), &b.tokens}
	case strings.HasPrefix(mt, "multipart/"):
		b.kind = "MULTIPART"
		if params["boundary"] == "" {
			b.err = true
		} else {
			b.tok = newMultipart(&b.tokens, params["boundary"])
		}
	default:
		b.kind, b.tok = "OTHER", otherTok{}
	}
	return b
}

func (b *Body) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.mu.Lock()
	b.total += int64(n)
	if b.tok != nil && n > 0 && !b.tok.write(p[:n]) {
		b.fail()
	}
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		b.ended = true
		if b.tok != nil && !b.tok.end() {
			b.fail()
		}
		b.tok = nil
	}
	b.mu.Unlock()
	return n, err
}

func (b *Body) fail() {
	b.err, b.tok = true, nil
}

func (b *Body) Close() error { return b.rc.Close() }

// state returns the body's tokens so far, with ERR if it failed to parse,
// and how much of it was read.
func (b *Body) state() (kind string, tokens []string, total int64, ended bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	tokens = append([]string(nil), b.tokens...)
	if b.err {
		tokens = append(tokens, "ERR")
	}
	return b.kind, tokens, b.total, b.ended
}
