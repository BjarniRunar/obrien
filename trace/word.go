// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"slices"
	"strconv"
	"strings"
)

// words turns a stream of value bytes into word tokens, one per
// whitespace-separated piece, appending them to *out. After maxWords
// tokens, the rest of the value is one REST token instead.
type words struct {
	out   *[]string
	cls   byte // 'A', 'P' or 'B'; 0 between words
	n     int
	some  bool // a token was emitted for this value
	count int  // word tokens emitted for this value

	restCls byte
	restN   int64 // bytes of the rest, from its first non-space byte to its last
	restWS  int64 // spaces after the rest so far, counted once more follows
}

// maxWords caps the word tokens of one value.
const maxWords = 10

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

func class(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return 'A'
	case c > ' ' && c < 0x7f:
		return 'P'
	}
	return 'B'
}

// rank orders classes so that a word takes the widest class of its bytes.
func rank(c byte) int {
	switch c {
	case 'A':
		return 1
	case 'P':
		return 2
	case 'B':
		return 3
	}
	return 0
}

func (w *words) add(c byte) {
	if w.count >= maxWords {
		w.addRest(c)
		return
	}
	if isSpace(c) {
		w.flush()
		return
	}
	if cc := class(c); rank(cc) > rank(w.cls) {
		w.cls = cc
	}
	w.n++
}

func (w *words) flush() {
	if w.n == 0 {
		return
	}
	*w.out = append(*w.out, token(w.cls, w.n))
	w.cls, w.n, w.some = 0, 0, true
	w.count++
}

func (w *words) addRest(c byte) {
	if isSpace(c) {
		if w.restN > 0 {
			w.restWS++
		}
		return
	}
	w.restN += w.restWS + 1
	w.restWS = 0
	if cc := class(c); rank(cc) > rank(w.restCls) {
		w.restCls = cc
	}
}

// done ends a run of words, emitting REST-, the widest class of the rest's
// bytes and its size bucket (as for SZ) if any words were cut off.
func (w *words) done() {
	if w.restN > 0 {
		*w.out = append(*w.out, "REST-"+string(w.restCls)+strconv.Itoa(sizeBucket(w.restN)))
	}
	w.count, w.restCls, w.restN, w.restWS = 0, 0, 0, 0
}

// end finishes a value; a value without any word is B0.
func (w *words) end() {
	w.flush()
	if !w.some {
		*w.out = append(*w.out, "B0")
	}
	w.done()
	w.some = false
}

func token(cls byte, n int) string {
	return string(cls) + strconv.Itoa((n+15)/16)
}

// wordsOf returns the word tokens for a complete value.
func wordsOf(s string) []string {
	var out []string
	w := words{out: &out}
	for i := 0; i < len(s); i++ {
		w.add(s[i])
	}
	w.end()
	return out
}

// maxKey caps the length of a key (or one part of a nested key).
const maxKey = 64

// key normalises a key or name a byte at a time: lowercase, with every run
// of bytes outside [a-z0-9_] replaced by a single '_', at most maxKey long.
type key struct {
	b    []byte
	repl bool // the last byte added was a replacement '_'
}

func (k *key) add(c byte) {
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
		k.repl = false
	} else if k.repl {
		return
	} else {
		c, k.repl = '_', true
	}
	if len(k.b) < maxKey {
		k.b = append(k.b, c)
	}
}

// take returns the key and resets k. An empty key is "_".
func (k *key) take() string {
	s := string(k.b)
	k.b, k.repl = k.b[:0], false
	if s == "" {
		return "_"
	}
	return s
}

func keyOf(s string) string {
	var k key
	for i := 0; i < len(s); i++ {
		k.add(s[i])
	}
	return k.take()
}

// unescaper decodes %XX escapes (and '+' as space, if plus is set) a byte at
// a time, passing decoded bytes to emit. Invalid escapes pass through as is.
type unescaper struct {
	plus bool
	pend []byte
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (u *unescaper) add(c byte, emit func(byte)) {
	if len(u.pend) > 0 {
		u.pend = append(u.pend, c)
		hi, ok := unhex(u.pend[1])
		var lo byte
		if ok && len(u.pend) == 3 {
			lo, ok = unhex(c)
		}
		switch {
		case !ok:
			u.reject(emit)
		case len(u.pend) == 3:
			u.pend = u.pend[:0]
			emit(hi<<4 | lo)
		}
		return
	}
	switch {
	case c == '%':
		u.pend = append(u.pend, c)
	case c == '+' && u.plus:
		emit(' ')
	default:
		emit(c)
	}
}

// reject passes an invalid escape's '%' through, and reads the bytes after
// it again, since one of them may start a new escape.
func (u *unescaper) reject(emit func(byte)) {
	rest := append([]byte(nil), u.pend[1:]...)
	u.pend = u.pend[:0]
	emit('%')
	for _, c := range rest {
		u.add(c, emit)
	}
}

// flush passes any incomplete escape through as is.
func (u *unescaper) flush(emit func(byte)) {
	for _, c := range u.pend {
		emit(c)
	}
	u.pend = u.pend[:0]
}

// comparePairs orders a key followed by its value's tokens by key, then by
// those tokens.
func comparePairs(a, b []string) int {
	if c := strings.Compare(a[0], b[0]); c != 0 {
		return c
	}
	return slices.Compare(a[1:], b[1:])
}
