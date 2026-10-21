// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trace reduces requests to traces: space-separated tokens
// describing the shape of a request without its exact content. See
// README.md for the syntax.
package trace

import (
	"mime"
	"slices"
	"strconv"
	"strings"

	"obrien/rules"
)

// interesting lists the headers traced after HEADERS, by normalised name.
// Only the presence of cookie is traced, not its value.
var interesting = map[string]bool{
	"access_control_request_headers": true,
	"access_control_request_method":  true,
	"authorization":                  true,
	"content_type":                   true,
	"cookie":                         true,
	"origin":                         true,
	"proxy_authorization":            true,
}

// Of returns the trace of a request from its header and body, which may be
// nil if the request had none. A body that is still being read is traced as
// far as it has been. A nil header gives an empty trace.
func Of(h *rules.Header, body *Body) string {
	if h == nil {
		return ""
	}
	var out []string
	out = append(out, special(h.Method))
	path, query := splitTarget(h.Target)
	out = append(out, pathTokens(path)...)
	if query != "" {
		f := newForm()
		f.write([]byte(query))
		f.end(&out)
	}
	out = append(out, "HC"+strconv.Itoa((len(h.Fields)+15)/16))

	var ctype, host, clen string
	var hasCT, hasHost, hasCL bool
	var hdrs [][]string
	for _, f := range h.Fields {
		name := keyOf(f.Name)
		switch name {
		case "content_type":
			if !hasCT {
				ctype, hasCT = f.Value, true
			}
		case "host":
			if !hasHost {
				host, hasHost = f.Value, true
			}
		case "content_length":
			if !hasCL {
				clen, hasCL = f.Value, true
			}
		}
		if interesting[name] {
			hdr := []string{name}
			if name != "cookie" {
				hdr = append(hdr, wordsOf(f.Value)...)
			}
			hdrs = append(hdrs, hdr)
		}
	}
	if hasCT {
		mt, _, err := mime.ParseMediaType(ctype)
		if err != nil {
			mt, _, _ = strings.Cut(ctype, ";")
		}
		out = append(out, "MIME", keyOf(strings.TrimSpace(mt)))
	}
	if hasHost {
		out = append(out, "HOST", keyOf(host))
	}
	if len(hdrs) > 0 {
		slices.SortStableFunc(hdrs, func(a, b []string) int {
			if c := strings.Compare(a[0], b[0]); c != 0 {
				return c
			}
			return slices.Compare(a[1:], b[1:])
		})
		out = append(out, "HEADERS")
		for _, hdr := range hdrs {
			out = append(out, hdr...)
		}
	}

	var total int64
	ended := body == nil
	if body != nil {
		kind, tokens, n, e := body.state()
		total, ended = n, e
		if n > 0 {
			out = append(out, "BODY", kind)
			out = append(out, tokens...)
		}
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(clen), 10, 64); hasCL && err == nil && ended {
		if n == total {
			out = append(out, "CLOK")
		} else {
			out = append(out, "CLBAD")
		}
	}
	return strings.Join(out, " ")
}

// special makes an uppercase token of a method, keeping only letters,
// digits and '_'.
func special(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b = append(b, c-'a'+'A')
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			b = append(b, c)
		}
	}
	if len(b) == 0 {
		return "_"
	}
	return string(b)
}

// splitTarget returns the path and query of a request target, in any of
// its forms. An asterisk or authority (CONNECT) target is a path of one
// segment.
func splitTarget(t string) (path, query string) {
	if i := strings.Index(t, "://"); i >= 0 && !strings.HasPrefix(t, "/") {
		rest := t[i+3:]
		j := strings.IndexAny(rest, "/?")
		if j < 0 {
			return "/", ""
		}
		t = rest[j:]
		if t[0] == '?' {
			t = "/" + t
		}
	}
	path, query, _ = strings.Cut(t, "?")
	return path, query
}

// pathTokens gives the word tokens of each segment of a path; segments are
// percent-decoded, and empty ones are B0.
func pathTokens(path string) []string {
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	var out []string
	w := words{out: &out}
	var u unescaper
	for _, seg := range strings.Split(path, "/") {
		for i := 0; i < len(seg); i++ {
			u.add(seg[i], w.add)
		}
		u.flush(w.add)
		w.end()
	}
	return out
}
