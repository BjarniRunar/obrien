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
	rc io.ReadCloser

	mu     sync.Mutex
	tokens []string  // the body's kind, then its tokens
	tok    tokenizer // nil once the body failed to parse
	total  int64
	ended  bool // read to the end, or to where the client stopped sending
	err    bool
}

type tokenizer interface {
	write(p []byte) bool
	end(complete bool) bool // complete is false if the client stopped early
}

// formTok adapts form to tokenizer; its pairs are only emitted at the end,
// once they can be sorted.
type formTok struct {
	f   *form
	out *[]string
}

func (t formTok) write(p []byte) bool { t.f.write(p); return true }
func (t formTok) end(bool) bool       { t.f.end(t.out); return true }

// NewBody wraps rc, choosing how to tokenize it from its Content-Type.
func NewBody(rc io.ReadCloser, contentType string) *Body {
	b := &Body{rc: rc}
	mt, params, _ := mime.ParseMediaType(contentType)
	switch {
	case mt == "application/x-www-form-urlencoded":
		b.tokens = []string{"FORM"}
		b.tok = formTok{newForm(), &b.tokens}
	case strings.HasPrefix(mt, "multipart/"):
		b.tokens = []string{"MULTIPART"}
		if params["boundary"] == "" {
			b.err = true
		} else {
			b.tok = newMultipart(&b.tokens, params["boundary"])
		}
	default:
		b.tok = newFile(&b.tokens, structured(mt))
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
		if b.tok != nil && !b.tok.end(err == io.EOF) {
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

// state returns the body's kind and tokens so far, with ERR if it failed to
// parse, and how much of it was read.
func (b *Body) state() (tokens []string, total int64, ended bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	tokens = append([]string(nil), b.tokens...)
	if b.err {
		tokens = append(tokens, "ERR")
	}
	return tokens, b.total, b.ended
}
