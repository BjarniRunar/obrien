// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCRS(t *testing.T) {
	var matched []string
	timed := 0
	block, err := NewCRS(CRSConfig{Block: true, Paranoia: 1, OnMatch: func(_ *http.Request, name string) {
		matched = append(matched, name)
	}, OnTime: func(*http.Request, time.Duration) { timed++ }})
	if err != nil {
		t.Fatal(err)
	}
	defer block.Close()

	req := func(method, target, body string) *http.Request {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r := httptest.NewRequest(method, target, rd)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Accept", "text/html")
		if body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return r
	}

	if err := block.Check(req("GET", "/search?q=hello+world", "")); err != nil {
		t.Errorf("clean GET rejected: %v", err)
	}
	if len(matched) != 0 {
		t.Errorf("clean GET matched %v", matched)
	}

	err = block.Check(req("GET", "/search?q=1'+OR+'1'='1", ""))
	var rej Rejection
	if !errors.As(err, &rej) || !errors.As(err, new(CRSError)) || !strings.Contains(err.Error(), "949110") {
		t.Errorf("SQL injection in query: %v", err)
	}
	if len(matched) == 0 {
		t.Error("SQL injection matched no rules")
	}

	if err := block.Check(req("POST", "/login", "user=x&pass=1'+OR+'1'='1")); err == nil {
		t.Error("SQL injection in body passed")
	}

	r := req("POST", "/login", "user=alice&pass=secret")
	if err := block.Check(r); err != nil {
		t.Fatalf("clean POST rejected: %v", err)
	}
	if body, _ := io.ReadAll(r.Body); string(body) != "user=alice&pass=secret" {
		t.Errorf("body after check = %q", body)
	}

	if timed != 4 {
		t.Errorf("OnTime called %d times for 4 checks", timed)
	}

	var detected error
	detect, err := NewCRS(CRSConfig{Paranoia: 1, OnDetect: func(_ *http.Request, err error) { detected = err }})
	if err != nil {
		t.Fatal(err)
	}
	defer detect.Close()
	if err := detect.Check(req("GET", "/search?q=1'+OR+'1'='1", "")); err != nil || detected == nil {
		t.Errorf("detect mode: err %v, detected %v", err, detected)
	}

	if _, err := NewCRS(CRSConfig{Paranoia: 5}); err == nil {
		t.Error("paranoia 5 accepted")
	}
	if _, err := NewCRS(CRSConfig{Paranoia: 1, Directives: "SecBogus On"}); err == nil {
		t.Error("invalid directives accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestCRSErrors(t *testing.T) {
	var kinds []string
	c, err := NewCRS(CRSConfig{Block: true, Paranoia: 1, BodyLimit: 1024, OnError: func(_ *http.Request, kind string, _ error) {
		kinds = append(kinds, kind)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	post := func(ctype string, body io.Reader) *http.Request {
		r := httptest.NewRequest("POST", "/upload", body)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Accept", "*/*")
		r.Header.Set("Content-Type", ctype)
		if r.ContentLength > 0 {
			r.Header.Set("Content-Length", fmt.Sprint(r.ContentLength))
		}
		return r
	}
	for _, tc := range []struct {
		name   string
		r      *http.Request
		kind   string
		reject bool
	}{
		{"bad json", post("application/json", strings.NewReader("{not json")), CRSErrBodyParse, true},
		{"read error", post("application/octet-stream", failingReader{}), CRSErrBodyRead, true},
		{"big body", post("application/x-www-form-urlencoded", strings.NewReader("f="+strings.Repeat("a", 2000))), CRSErrBodyTruncated, false},
	} {
		kinds = nil
		err := c.Check(tc.r)
		if (err != nil) != tc.reject || len(kinds) != 1 || kinds[0] != tc.kind {
			t.Errorf("%s: err %v, kinds %v, want %s", tc.name, err, kinds, tc.kind)
		}
		if tc.name == "big body" {
			if body, _ := io.ReadAll(tc.r.Body); len(body) != 2002 {
				t.Errorf("big body: handler got %d bytes", len(body))
			}
		}
	}
}
