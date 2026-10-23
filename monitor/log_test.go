// SPDX-License-Identifier: AGPL-3.0-or-later

package monitor

import "testing"

func TestLogKeepsNewest(t *testing.T) {
	l := NewLog(3)
	var want []string
	for i := 1; i <= 5; i++ {
		rec := &Record{Status: i}
		l.Observe(rec)
		want = append(want, FormatTraceLine(rec))
	}
	got := l.Recent(0)
	if len(got) != 3 || got[0] != want[2] || got[2] != want[4] {
		t.Fatalf("Recent(0) = %q, want lines 3,4,5", got)
	}
	if got := l.Recent(2); len(got) != 2 || got[0] != want[3] {
		t.Fatalf("Recent(2) = %q, want lines 4,5", got)
	}
	if got := NewLog(3).Recent(0); len(got) != 0 {
		t.Fatalf("empty log returned %q", got)
	}
}
