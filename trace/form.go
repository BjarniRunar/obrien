// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"slices"
	"strings"
)

// form tokenizes application/x-www-form-urlencoded data, which is also the
// syntax of query strings. Pairs are kept as tokens until end, which sorts
// them by key and then by value tokens. Pairs after maxPairs are only
// counted, and MORE follows the sorted pairs for all of them.
type form struct {
	pairs [][]string // key, then its word tokens
	more  bool

	inValue bool
	started bool // the current pair has a byte
	k       key
	vals    []string
	w       words
	u       unescaper
}

// maxPairs caps the pairs traced from a form or query.
const maxPairs = 64

func newForm() *form {
	f := &form{u: unescaper{plus: true}}
	f.w.out = &f.vals
	return f
}

func (f *form) write(p []byte) {
	for _, c := range p {
		switch {
		case c == '&':
			f.u.flush(f.emit)
			f.endPair()
		case c == '=' && !f.inValue:
			f.u.flush(f.emit)
			f.inValue, f.started = true, true
		default:
			f.started = true
			f.u.add(c, f.emit)
		}
	}
}

func (f *form) emit(c byte) {
	if f.inValue {
		f.w.add(c)
	} else {
		f.k.add(c)
	}
}

func (f *form) endPair() {
	if f.started {
		f.w.end()
		if len(f.pairs) < maxPairs {
			f.pairs = append(f.pairs, append([]string{f.k.take()}, f.vals...))
		} else {
			f.more = true
		}
	}
	f.inValue, f.started, f.vals = false, false, nil
	f.k.take()
}

// end appends the sorted pairs to out.
func (f *form) end(out *[]string) {
	f.u.flush(f.emit)
	f.endPair()
	slices.SortStableFunc(f.pairs, func(a, b []string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return slices.Compare(a[1:], b[1:])
	})
	for _, p := range f.pairs {
		*out = append(*out, p...)
	}
	if f.more {
		*out = append(*out, "MORE")
	}
}
