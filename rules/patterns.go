package rules

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Sanity rejects requests whose header could not be parsed, broke the
// sanity rules in checkHeader, or could not be captured at all. It must run
// before any rule that reads the header.
type Sanity struct{}

func (Sanity) Check(r *http.Request) error {
	h := HeaderFrom(r.Context())
	if h == nil {
		return SanityError{errors.New("no header")}
	}
	if h.Err != nil {
		return SanityError{h.Err}
	}
	return nil
}

// SanityError is the error Sanity rejects a request with.
type SanityError struct{ Err error }

func (e SanityError) Error() string { return "sanity: " + e.Err.Error() }
func (e SanityError) Unwrap() error { return e.Err }

// Pattern is a named regular expression matched against the raw header.
type Pattern struct {
	Name   string `msgpack:"name" json:"name"`
	Regexp string `msgpack:"regexp" json:"regexp"`
}

type compiled struct {
	Pattern
	re *regexp.Regexp
}

// MatchFunc is called for every pattern that matches a request.
type MatchFunc func(r *http.Request, name string)

// Patterns is a Rule rejecting requests whose raw header matches any of an
// editable list of patterns. Every pattern is tried, so each match is
// reported to the MatchFunc even when an earlier one already rejected the
// request. It is safe to edit while requests are being checked.
type Patterns struct {
	onMatch MatchFunc
	mu      sync.Mutex // serialises edits; reads use list alone
	list    atomic.Pointer[[]compiled]
}

func NewPatterns(onMatch MatchFunc) *Patterns {
	p := &Patterns{onMatch: onMatch}
	p.list.Store(&[]compiled{})
	return p
}

func (p *Patterns) Check(r *http.Request) error {
	h := HeaderFrom(r.Context())
	if h == nil {
		return errors.New("no header")
	}
	var matched []string
	for _, c := range *p.list.Load() {
		if c.re.Match(h.Raw) {
			matched = append(matched, c.Name)
			if p.onMatch != nil {
				p.onMatch(r, c.Name)
			}
		}
	}
	if len(matched) > 0 {
		return fmt.Errorf("matched %s", strings.Join(matched, ", "))
	}
	return nil
}

// List returns the patterns in the order they are tried.
func (p *Patterns) List() []Pattern {
	list := *p.list.Load()
	out := make([]Pattern, len(list))
	for i, c := range list {
		out[i] = c.Pattern
	}
	return out
}

// Add appends patterns, or with replace set, puts the single pattern in add
// in the place of the one named replace. Either all of add is applied or,
// on error, none of it.
func (p *Patterns) Add(add []Pattern, replace string) error {
	if len(add) == 0 {
		return errors.New("no patterns given")
	}
	if replace != "" && len(add) != 1 {
		return errors.New("replace takes exactly one pattern")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	old := *p.list.Load()
	list := make([]compiled, 0, len(old)+len(add))
	at := -1
	for _, c := range old {
		if c.Name == replace {
			at = len(list)
			continue
		}
		list = append(list, c)
	}
	if replace != "" && at < 0 {
		return fmt.Errorf("no pattern named %q", replace)
	}

	names := make(map[string]bool, len(list))
	for _, c := range list {
		names[c.Name] = true
	}
	var added []compiled
	for _, a := range add {
		if !validName(a.Name) {
			return fmt.Errorf("invalid name %q: use letters, digits, '.', '_' or '-'", a.Name)
		}
		if names[a.Name] {
			return fmt.Errorf("a pattern named %q already exists", a.Name)
		}
		names[a.Name] = true
		re, err := regexp.Compile(a.Regexp)
		if err != nil {
			return fmt.Errorf("pattern %q: %w", a.Name, err)
		}
		added = append(added, compiled{Pattern: a, re: re})
	}

	if at >= 0 {
		list = append(list[:at], append(added, list[at:]...)...)
	} else {
		list = append(list, added...)
	}
	p.list.Store(&list)
	return nil
}

// Remove deletes the named patterns. Unknown names are an error and leave
// the list unchanged.
func (p *Patterns) Remove(names []string) error {
	if len(names) == 0 {
		return errors.New("no names given")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	old := *p.list.Load()
	list := make([]compiled, 0, len(old))
	for _, c := range old {
		if drop[c.Name] {
			delete(drop, c.Name)
			continue
		}
		list = append(list, c)
	}
	for n := range drop {
		return fmt.Errorf("no pattern named %q", n)
	}
	p.list.Store(&list)
	return nil
}

// validName keeps names usable as metric label values and CLI arguments.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
