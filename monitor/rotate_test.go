// SPDX-License-Identifier: AGPL-3.0-or-later

package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	r, err := OpenRotatingFile(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	r.now = func() time.Time { return at }
	for _, s := range []string{"aaaaaa\n", "bbbbbb\n", "cc\n"} {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		path:                      "cc\n",
		path + ".20260102-030405": "aaaaaa\nbbbbbb\n",
	} {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != want {
			t.Errorf("%s: %q, %v; want %q", name, got, err, want)
		}
	}
}
