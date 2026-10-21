// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
		New(target, tr, nil).ServeHTTP(w, r)
		if got := w.Body.String(); got != tc.want {
			t.Errorf("%v %s %q: got %q, want %q", tc.trusted, tc.remote, tc.xff, got, tc.want)
		}
	}
}
