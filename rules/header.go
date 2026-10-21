// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Field is one header field, as it appeared on the wire.
type Field struct {
	Name  string
	Value string
}

// Header is a request's header block. For HTTP/1.x, Raw holds the exact bytes
// the client sent, from the request line up to and including the blank line
// that ends the header. HTTP/2 has no such text, so Raw is rebuilt from the
// decoded request in HTTP/1 form (see headerFromRequest).
//
// Err is set when the header could not be parsed or broke the sanity rules;
// the other fields are then only as complete as parsing got.
type Header struct {
	Raw    []byte
	Method string
	Target string
	Proto  string
	Fields []Field
	Err    error
}

type headerKey struct{}

func withHeader(ctx context.Context, h *Header) context.Context {
	return context.WithValue(ctx, headerKey{}, h)
}

// HeaderFrom returns the header Filter attached to the request's context, or
// nil outside Filter.
func HeaderFrom(ctx context.Context) *Header {
	h, _ := ctx.Value(headerKey{}).(*Header)
	return h
}

// parseHeader strictly parses an HTTP/1.x header block. raw must end with
// the terminating empty line. Every line must end in CRLF.
func parseHeader(raw []byte) *Header {
	h := &Header{Raw: raw}
	lines := bytes.Split(raw, []byte("\r\n"))
	// A well-formed block splits into: request line, fields..., "", "".
	if len(lines) < 3 || len(lines[len(lines)-1]) != 0 || len(lines[len(lines)-2]) != 0 {
		h.Err = errors.New("header block does not end in CRLF CRLF")
		return h
	}
	lines = lines[:len(lines)-2]
	for _, l := range lines {
		if bytes.IndexByte(l, '\n') >= 0 || bytes.IndexByte(l, '\r') >= 0 {
			h.Err = errors.New("bare CR or LF in header")
			return h
		}
	}

	parts := strings.Split(string(lines[0]), " ")
	if len(parts) != 3 {
		h.Err = fmt.Errorf("malformed request line %q", lines[0])
		return h
	}
	h.Method, h.Target, h.Proto = parts[0], parts[1], parts[2]
	if h.Proto != "HTTP/1.1" && h.Proto != "HTTP/1.0" {
		h.Err = fmt.Errorf("unsupported protocol %q", h.Proto)
		return h
	}

	for _, l := range lines[1:] {
		if len(l) > 0 && (l[0] == ' ' || l[0] == '\t') {
			h.Err = errors.New("obsolete line folding in header")
			return h
		}
		name, value, ok := strings.Cut(string(l), ":")
		if !ok {
			h.Err = fmt.Errorf("header line without colon %q", l)
			return h
		}
		h.Fields = append(h.Fields, Field{Name: name, Value: strings.Trim(value, " \t")})
	}
	h.Err = checkHeader(h)
	return h
}

// headerFromRequest builds a Header for a request that has no raw form
// (HTTP/2). Go has already validated the field syntax; the sanity rules are
// applied on top. Fields are sorted by name, since their order is lost.
func headerFromRequest(r *http.Request) *Header {
	h := &Header{Method: r.Method, Target: r.RequestURI, Proto: r.Proto}
	h.Fields = append(h.Fields, Field{Name: "Host", Value: r.Host})
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range r.Header[name] {
			h.Fields = append(h.Fields, Field{Name: name, Value: v})
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s\r\n", h.Method, h.Target, h.Proto)
	for _, f := range h.Fields {
		fmt.Fprintf(&b, "%s: %s\r\n", f.Name, f.Value)
	}
	b.WriteString("\r\n")
	h.Raw = b.Bytes()
	h.Err = checkHeader(h)
	return h
}

// checkHeader applies the sanity rules to a parsed header: the syntax of the
// request line and every field, and the meaning of the fields whose
// misinterpretation enables request smuggling or parser confusion.
func checkHeader(h *Header) error {
	if !isToken(h.Method) {
		return fmt.Errorf("invalid method %q", h.Method)
	}
	if err := checkTarget(h.Method, h.Target); err != nil {
		return err
	}
	counts := make(map[string]int)
	for _, f := range h.Fields {
		if !isToken(f.Name) {
			return fmt.Errorf("invalid header name %q", f.Name)
		}
		for i := 0; i < len(f.Value); i++ {
			if c := f.Value[i]; (c < ' ' && c != '\t') || c == 0x7f {
				return fmt.Errorf("control character in header %s", f.Name)
			}
		}
		name := strings.ToLower(f.Name)
		counts[name]++
		switch name {
		case "content-length":
			if _, err := strconv.ParseUint(f.Value, 10, 63); err != nil || strings.Trim(f.Value, "0123456789") != "" {
				return fmt.Errorf("invalid Content-Length %q", f.Value)
			}
		case "transfer-encoding":
			if !strings.EqualFold(f.Value, "chunked") {
				return fmt.Errorf("unsupported Transfer-Encoding %q", f.Value)
			}
		case "content-type":
			if _, _, err := mime.ParseMediaType(f.Value); err != nil {
				return fmt.Errorf("invalid Content-Type %q: %v", f.Value, err)
			}
		case "host":
			if err := checkHost(f.Value); err != nil {
				return err
			}
		}
	}
	for _, name := range []string{"content-length", "transfer-encoding", "content-type", "host"} {
		if counts[name] > 1 {
			return fmt.Errorf("duplicate %s header", name)
		}
	}
	if counts["content-length"] > 0 && counts["transfer-encoding"] > 0 {
		return errors.New("both Content-Length and Transfer-Encoding")
	}
	if counts["transfer-encoding"] > 0 && h.Proto != "HTTP/1.1" {
		return fmt.Errorf("Transfer-Encoding with %s", h.Proto)
	}
	if counts["host"] == 0 && h.Proto != "HTTP/1.0" {
		return errors.New("missing Host header")
	}
	return nil
}

func checkTarget(method, target string) error {
	switch {
	case target == "":
		return errors.New("empty request target")
	case method == "CONNECT":
		return checkHost(target)
	case target == "*":
		if method != "OPTIONS" {
			return fmt.Errorf("target * with method %s", method)
		}
		return nil
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c <= ' ' || c >= 0x7f {
			return fmt.Errorf("invalid byte in request target %q", target)
		}
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return fmt.Errorf("invalid request target %q: %v", target, err)
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme in request target %q", target)
	}
	return nil
}

func checkHost(host string) error {
	if host == "" {
		return errors.New("empty Host")
	}
	u, err := url.Parse("http://" + host)
	if err != nil || u.Host != host || u.User != nil {
		return fmt.Errorf("invalid Host %q", host)
	}
	return nil
}

// isToken reports whether s is a non-empty RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}
