package monitor

import "testing"

func TestLogKeepsNewest(t *testing.T) {
	l := NewLog(3)
	for i := 1; i <= 5; i++ {
		l.Observe(&Record{Status: i})
	}
	got := l.Recent(0)
	if len(got) != 3 || got[0].Status != 3 || got[2].Status != 5 {
		t.Fatalf("Recent(0) = %+v, want statuses 3,4,5", got)
	}
	if got := l.Recent(2); len(got) != 2 || got[0].Status != 4 {
		t.Fatalf("Recent(2) = %+v, want statuses 4,5", got)
	}
	if got := NewLog(3).Recent(0); len(got) != 0 {
		t.Fatalf("empty log returned %+v", got)
	}
}
