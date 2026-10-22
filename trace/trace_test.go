// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"obrien/rules"
)

var update = flag.Bool("update", false, "rewrite testdata/traces from the current output")

// traceFile traces a raw request, reading its body through Body in chunks
// of the given size (0 for all at once).
func traceFile(t *testing.T, raw []byte, chunk int) string {
	t.Helper()
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		t.Fatal("no end of header")
	}
	h := rules.ParseHeader(raw[:end+4])
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var body *Body
	if r.Body != nil && r.Body != http.NoBody {
		body = NewBody(r.Body, r.Header.Get("Content-Type"))
		buf := make([]byte, max(chunk, 32<<10))
		for {
			n := len(buf)
			if chunk > 0 {
				n = chunk
			}
			if _, err := body.Read(buf[:n]); err != nil {
				break
			}
		}
	}
	return Of(h, body)
}

func TestTraces(t *testing.T) {
	files, err := filepath.Glob("testdata/requests/*.http")
	if err != nil || len(files) == 0 {
		t.Fatal("no test requests", err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".http")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			got := traceFile(t, raw, 0)
			if one := traceFile(t, raw, 1); one != got {
				t.Errorf("byte at a time:\n  %s\nall at once:\n  %s", one, got)
			}
			golden := filepath.Join("testdata", "traces", name+".trace")
			if *update {
				if err := os.WriteFile(golden, []byte(got+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != strings.TrimSuffix(string(want), "\n") {
				t.Errorf("got:\n  %s\nwant:\n  %s", got, want)
			}
		})
	}
}

func TestBodyNotRead(t *testing.T) {
	raw := "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n"
	b := NewBody(io.NopCloser(strings.NewReader(`{"a":1}`)), "application/json")
	if got, want := Of(rules.ParseHeader([]byte(raw)), b), "POST A1 HC1 MIME application_json HOST h HEADERS content_type P1"; got != want {
		t.Errorf("unread body: got %q, want %q", got, want)
	}
	if Of(nil, nil) != "" {
		t.Error("nil header gave a trace")
	}
}

func TestWords(t *testing.T) {
	for in, want := range map[string]string{
		"":                                      "B0",
		"   ":                                   "B0",
		"abc123":                                "A1",
		"a-b":                                   "P1",
		"caf\xc3\xa9":                           "B1",
		"x\x00":                                 "B1",
		strings.Repeat("a", 16):                 "A1",
		strings.Repeat("a", 17):                 "A2",
		"hello big  world":                      "A1 A1 A1",
		"a b c d e f g h i j":                   "A1 A1 A1 A1 A1 A1 A1 A1 A1 A1",
		"a b c d e f g h i j  ":                 "A1 A1 A1 A1 A1 A1 A1 A1 A1 A1",
		"a b c d e f g h i j k":                 "A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 REST-A1",
		"a b c d e f g h i j k-l   m\xc3\xa9  ": "A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 REST-B1",
		"a b c d e f g h i j " + strings.Repeat("x ", 200): "A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 REST-A3",
	} {
		if got := strings.Join(wordsOf(in), " "); got != want {
			t.Errorf("wordsOf(%q) = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"":             "_",
		"Content-Type": "content_type",
		"vnd.api+json": "vnd_api_json",
		"user_id":      "user_id",
		"a--b":         "a_b",
		"tags[]":       "tags_",
	} {
		if got := keyOf(in); got != want {
			t.Errorf("keyOf(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestThroughFilter traces requests the way the daemon does: the header
// comes from rules.Filter through a slot, and the body is read by the
// handler behind it.
func TestThroughFilter(t *testing.T) {
	traces := make(chan string, 1)
	inner := rules.Filter([]rules.Rule{rules.Sanity{}}, http.StatusForbidden, "", nil, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
		}))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, slot := rules.WithHeaderSlot(r.Context())
		r = r.WithContext(ctx)
		var body *Body
		if r.Body != nil && r.Body != http.NoBody {
			body = NewBody(r.Body, r.Header.Get("Content-Type"))
			r.Body = body
		}
		inner.ServeHTTP(w, r)
		traces <- Of(slot.Header(), body)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ConnContext: rules.ConnContext}
	go srv.Serve(rules.Listen(ln, nil, 1<<16))
	defer srv.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /api/Items?ID=7 HTTP/1.1\r\nHost: Example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"a\":[1,\"x\"]}")
	want := "POST A1 A1 id A1 HC1 MIME application_json HOST example_com HEADERS content_type P1 BODY JSON a A1 A1 LE OE CLOK"
	select {
	case got := <-traces:
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no trace")
	}
}

func TestJSONStructure(t *testing.T) {
	for in, want := range map[string]string{
		`{}`:                   "EO",
		`[]`:                   "EL",
		`{"meta":{}}`:          "meta EO OE",
		`{"a":{"b":[]}}`:       "a b EL OE OE",
		`{"a":[{},{"c":{}}]}`:  "a EO c EO OE LE OE",
		`{"a":[[],[1]],"b":1}`: "a EL A1 LE LE b A1 OE",
		`"x y"`:                "A1 A1",
	} {
		var out []string
		j := newJSON(&out)
		if !j.write([]byte(in)) || !j.end() {
			t.Errorf("%s: parse failed", in)
		}
		if got := strings.Join(sortJSON(out), " "); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

// TestTruncatedFiles checks how files cut short are closed.
func TestTruncatedFiles(t *testing.T) {
	for _, c := range []struct{ kind, in, want string }{
		{"JSON", `{"a":1,"b":"x y`, "JSON a A1 OE TRUNC"},
		{"JSON", `{"a":1,"b":`, "JSON a A1 OE TRUNC"},
		{"JSON", `{"a":1,"b"`, "JSON a A1 OE TRUNC"},
		{"JSON", `{"a":1,"b":tr`, "JSON a A1 OE TRUNC"},
		{"JSON", `{"a":12`, "JSON EO TRUNC"},
		{"JSON", `{"a":[1,"x\u00`, "JSON a A1 LE OE TRUNC"},
		{"JSON", `{"z":{"b":[`, "JSON z b EL OE OE TRUNC"},
		{"JSON", `[{"b":1,"a":`, "JSON b A1 OE LE TRUNC"},
		{"JSON", `"abc`, "JSON TRUNC"},
		{"JSON", `{"a":1}x`, "JSON INVALID TRUNC"},
		{"XML", `<a x="1"><b>hello wor`, "XML a x A1 AE b NA A1 TE TE TRUNC"},
		{"XML", `<a><b/><c y="`, "XML a NA b NA EE TE TRUNC"},
		{"XML", `<a><!-- x`, "XML a NA EE TRUNC"},
		{"XML", `<a>x &am`, "XML a NA A1 TE TRUNC"},
		{"", `<r><s>1`, "XML r NA s NA TE TE TRUNC"},
		{"", "\x89PNG\r\n\x1a\n", "OTHER image_png SZ1 TRUNC"},
	} {
		var out []string
		f := newFile(&out, c.kind)
		f.write([]byte(c.in))
		f.end(false)
		if got := strings.Join(out, " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRestInXML checks that each XML text run and attribute value is
// capped on its own.
func TestRestInXML(t *testing.T) {
	ten := "a b c d e f g h i j"
	var out []string
	x := newXML(&out)
	in := `<r v="` + ten + ` k">` + ten + ` k-<c/>` + ten + `</r>`
	if !x.write([]byte(in)) || !x.end() {
		t.Fatal("parse failed")
	}
	want := "r v " + strings.Repeat("A1 ", 10) + "REST-A1 AE " + strings.Repeat("A1 ", 10) + "REST-P1 c NA EE " + strings.Repeat("A1 ", 10) + "TE"
	if got := strings.Join(out, " "); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
