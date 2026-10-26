// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustedXForwardedFor(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Forwarded-For"))
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)

	trusted, err := ParseTrusted("10.0.0.0/8, 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrusted("10.0.0.0/8,bogus"); err == nil {
		t.Error("ParseTrusted accepted bogus input")
	}
	for _, tc := range []struct {
		trusted     bool
		remote, xff string
		want        string
	}{
		{false, "10.1.2.3:5000", "6.6.6.6", "10.1.2.3"},
		{true, "10.1.2.3:5000", "6.6.6.6", "6.6.6.6, 10.1.2.3"},
		{true, "192.0.2.1:5000", "6.6.6.6", "6.6.6.6, 192.0.2.1"},
		{true, "[::ffff:192.0.2.1]:5000", "6.6.6.6", "6.6.6.6, ::ffff:192.0.2.1"},
		{true, "192.0.2.2:5000", "6.6.6.6", "192.0.2.2"},
		{true, "10.1.2.3:5000", "", "10.1.2.3"},
	} {
		tr := trusted
		if !tc.trusted {
			tr = nil
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		w := httptest.NewRecorder()
		New(target, tr, false, nil).ServeHTTP(w, r)
		if got := w.Body.String(); got != tc.want {
			t.Errorf("%v %s %q: got %q, want %q", tc.trusted, tc.remote, tc.xff, got, tc.want)
		}
	}
}

// Per client, upstream connections are reused by that client only, and
// closed with it.
func TestPerClient(t *testing.T) {
	var opened, closed atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	up.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	up.Start()
	defer up.Close()
	target, _ := url.Parse(up.URL)
	for _, perClient := range []bool{false, true} {
		opened.Store(0)
		closed.Store(0)
		px := New(target, nil, perClient, nil)
		front := httptest.NewUnstartedServer(px)
		front.Config.ConnContext = px.ConnContext
		front.Config.ConnState = px.ConnState
		front.Start()
		for client := 0; client < 2; client++ {
			tr := &http.Transport{}
			for i := 0; i < 3; i++ {
				resp, err := (&http.Client{Transport: tr}).Get(front.URL)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			tr.CloseIdleConnections()
		}
		front.Close()
		want := map[bool]int32{false: 1, true: 2}[perClient]
		if n := opened.Load(); n != want {
			t.Errorf("perClient=%v: %d upstream connections, want %d", perClient, n, want)
		}
		if perClient {
			deadline := time.Now().Add(time.Second)
			for closed.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if n := closed.Load(); n != 2 {
				t.Errorf("%d upstream connections closed with their clients, want 2", n)
			}
		}
	}
}
