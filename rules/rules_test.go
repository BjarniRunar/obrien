package rules

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseHeader(t *testing.T) {
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{"GET / HTTP/1.1\r\nHost: a\r\n\r\n", true},
		{"GET /x?y=1 HTTP/1.0\r\n\r\n", true},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 3\r\n\r\n", true},
		{"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", true},
		{"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n", true},
		{"GET / HTTP/1.1\nHost: a\n\n", false},                              // bare LF
		{"GET / HTTP/1.1\r\nHost: a\r\nX: b\nc\r\n\r\n", false},             // bare LF in value
		{"GET / HTTP/1.1\r\n\r\n", false},                                   // no Host
		{"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", false},             // duplicate Host
		{"GET  / HTTP/1.1\r\nHost: a\r\n\r\n", false},                       // double space
		{"GET / HTTP/2.0\r\nHost: a\r\n\r\n", false},                        // version
		{"G(T / HTTP/1.1\r\nHost: a\r\n\r\n", false},                        // method
		{"GET /%zz HTTP/1.1\r\nHost: a\r\n\r\n", false},                     // bad escape
		{"GET x HTTP/1.1\r\nHost: a\r\n\r\n", false},                        // relative target
		{"GET * HTTP/1.1\r\nHost: a\r\n\r\n", false},                        // * without OPTIONS
		{"GET / HTTP/1.1\r\nHost: a\r\nX : b\r\n\r\n", false},               // space before colon
		{"GET / HTTP/1.1\r\nHost: a\r\nX: b\r\n c\r\n\r\n", false},          // folding
		{"GET / HTTP/1.1\r\nHost: a\r\nnocolon\r\n\r\n", false},             // no colon
		{"GET / HTTP/1.1\r\nHost: a\r\nX: a\x01b\r\n\r\n", false},           // control char
		{"GET / HTTP/1.1\r\nHost: a b\r\n\r\n", false},                      // bad Host
		{"GET / HTTP/1.1\r\nHost: u@a\r\n\r\n", false},                      // userinfo in Host
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +3\r\n\r\n", false}, // CL sign
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n", false},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", false},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", false},
		{"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", false},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: multipart/form-data; boundary\r\n\r\n", false},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: a/b\r\nContent-Type: a/b\r\n\r\n", false},
	} {
		h := parseHeader([]byte(tc.raw))
		if (h.Err == nil) != tc.ok {
			t.Errorf("%q: err = %v, want ok=%v", tc.raw, h.Err, tc.ok)
		}
	}
}

func TestPatterns(t *testing.T) {
	var mu sync.Mutex
	matches := map[string]int{}
	p := NewPatterns(func(_ *http.Request, name string) {
		mu.Lock()
		matches[name]++
		mu.Unlock()
	})
	if err := p.Add([]Pattern{{Name: "mp", Regexp: `(?im)^content-type:\s*multipart/`}, {Name: "evil", Regexp: `/evil`}}, ""); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]Pattern{
		{{Name: "mp", Regexp: "x"}},                            // duplicate
		{{Name: "a", Regexp: "x"}, {Name: "a", Regexp: "y"}},   // duplicate within add
		{{Name: "a b", Regexp: "x"}},                           // name
		{{Name: "ok", Regexp: "("}},                            // regexp
		{{Name: "u", Regexp: "x", URL: "javascript:alert(1)"}}, // URL scheme
		{{Name: "u", Regexp: "x", URL: "why"}},                 // relative URL
	} {
		if err := p.Add(bad, ""); err == nil {
			t.Errorf("Add(%v) succeeded", bad)
		}
	}
	if err := p.Add([]Pattern{{Name: "x", Regexp: "x"}}, "missing"); err == nil {
		t.Error("replace of missing pattern succeeded")
	}
	if err := p.Add([]Pattern{{Name: "mp2", Regexp: `(?im)^content-type:\s*multipart/form-data`}}, "mp"); err != nil {
		t.Fatal(err)
	}
	if got := p.List(); len(got) != 2 || got[0].Name != "mp2" || got[1].Name != "evil" {
		t.Fatalf("after replace: %v", got)
	}

	check := func(raw string) error {
		r := httptest.NewRequest("POST", "/", nil)
		r = r.WithContext(withHeader(r.Context(), parseHeader([]byte(raw))))
		return p.Check(r)
	}
	if err := check("POST /evil HTTP/1.1\r\nHost: a\r\nCONTENT-TYPE: Multipart/Form-Data; boundary=x\r\n\r\n"); err == nil {
		t.Error("multipart request passed")
	}
	if err := check("POST / HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\n\r\n"); err != nil {
		t.Errorf("plain request rejected: %v", err)
	}
	if matches["mp2"] != 1 || matches["evil"] != 1 {
		t.Errorf("matches = %v", matches)
	}

	if err := p.Update([]Pattern{{Name: "evil", Regexp: "/bad"}, {Name: "new", Regexp: "x"}, {Name: "new", Regexp: "y"}}); err == nil {
		t.Error("Update with a repeated name succeeded")
	}
	if err := p.Update([]Pattern{{Name: "evil", Regexp: "/bad"}, {Name: "new", Regexp: "x"}}); err != nil {
		t.Fatal(err)
	}
	if got := p.List(); len(got) != 3 || got[1] != (Pattern{Name: "evil", Regexp: "/bad"}) || got[2].Name != "new" {
		t.Fatalf("after Update: %v", got)
	}
	p.Remove([]string{"new"})

	if err := p.Remove([]string{"evil", "missing"}); err == nil {
		t.Error("Remove of a missing name succeeded")
	}
	if len(p.List()) != 2 {
		t.Error("failed Remove changed the list")
	}
	if err := p.Remove([]string{"evil", "mp2"}); err != nil || len(p.List()) != 0 {
		t.Errorf("Remove: %v, %v", err, p.List())
	}
}

// serve runs Filter behind Listen on a loopback port, and returns its
// address and a channel of the rejection reasons.
func serve(t *testing.T, tlsConfig *tls.Config) (string, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rejects := make(chan error, 100)
	p := NewPatterns(nil)
	p.Add([]Pattern{{Name: "evil", Regexp: "evil"}}, "")
	h := Filter([]Rule{Sanity{}, p}, "", func(_ *http.Request, err error) { rejects <- err }, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			proto := "plain"
			if r.TLS != nil {
				proto = "tls"
			}
			io.WriteString(w, proto+" "+r.URL.Path)
		}))
	srv := &http.Server{Handler: h, ConnContext: ConnContext, MaxHeaderBytes: 1 << 16, TLSConfig: tlsConfig}
	go srv.Serve(Listen(ln, tlsConfig, srv.MaxHeaderBytes))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), rejects
}

// exchange writes raw to a fresh connection and returns the statuses of the
// responses read back.
func exchange(t *testing.T, addr, raw string, n int) []int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, raw)
	br := bufio.NewReader(c)
	var codes []int
	for i := 0; i < n; i++ {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	return codes
}

func TestCaptureStream(t *testing.T) {
	addr, _ := serve(t, nil)
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"pipelined",
			"GET /a HTTP/1.1\r\nHost: a\r\n\r\n" +
				"POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello" +
				"GET /c HTTP/1.1\r\nHost: a\r\n\r\n",
			"200 200 200"},
		{"chunked",
			"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5;ext=1\r\nhello\r\n0\r\nTrailer: x\r\n\r\n" +
				"GET /b HTTP/1.1\r\nHost: a\r\n\r\n",
			"200 200"},
		{"pattern",
			"GET /evil HTTP/1.1\r\nHost: a\r\n\r\nGET /ok HTTP/1.1\r\nHost: a\r\n\r\n",
			"403 200"},
		{"body is not a header",
			"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nevil" +
				"GET /b HTTP/1.1\r\nHost: a\r\n\r\n",
			"200 200"},
		{"insane, then nothing passes",
			"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: a/b; c\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"403 403"},
		{"refused by net/http",
			"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"400"}, // net/http itself refuses the duplicate Host
		{"bare LF",
			"GET / HTTP/1.1\nHost: a\n\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"403 403"},
	} {
		var got []string
		for _, c := range exchange(t, addr, tc.raw, 3) {
			got = append(got, strconv.Itoa(c))
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.want)
		}
	}
}

func TestCaptureTLS(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	cfg := &tls.Config{Certificates: ts.TLS.Certificates, NextProtos: []string{"h2", "http/1.1"}}
	ts.Close()

	addr, rejects := serve(t, cfg)
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: h2}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		client := &http.Client{Transport: tr}
		for _, path := range []string{"/ok", "/evil"} {
			resp, err := client.Get("https://" + addr + path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			wantCode := 200
			if path == "/evil" {
				wantCode = 403
			}
			if resp.StatusCode != wantCode || (wantCode == 200 && string(body) != "tls "+path) || resp.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
				t.Errorf("h2=%v %s: %s %d %q", h2, path, resp.Proto, resp.StatusCode, body)
			}
		}
	}
	select {
	case err := <-rejects:
		if !strings.Contains(err.Error(), "evil") {
			t.Errorf("rejected for %v", err)
		}
	default:
		t.Error("no rejection reported")
	}
}

func TestForbiddenPage(t *testing.T) {
	p := NewPatterns(nil)
	if err := p.Add([]Pattern{{Name: "a", Regexp: "/a"}, {Name: "b", Regexp: "/b", URL: `https://x.example/why?r=b&q="`}}, ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ infoURL, path, want string }{
		{"/blocked", "/a", `<a href="/blocked">`},
		{"/blocked", "/b", `<a href="https://x.example/why?r=b&amp;q=&#34;">`},
		{"/blocked", "/a/b", `<a href="https://x.example/why?r=b&amp;q=&#34;">`},
		{"", "/a", "blocked.</p>"},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: Filter([]Rule{Sanity{}, p}, tc.infoURL, nil, nil, http.NotFoundHandler()), ConnContext: ConnContext}
		go srv.Serve(Listen(ln, nil, 1<<16))
		resp, err := http.Get("http://" + ln.Addr().String() + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), tc.want) ||
			!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			t.Errorf("%s: %d %q, want %q", tc.path, resp.StatusCode, body, tc.want)
		}
	}
}
