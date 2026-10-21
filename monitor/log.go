package monitor

import "sync"

// Log is a Hook keeping the most recent requests in a fixed-size ring
// buffer, so memory use stays bounded however much traffic passes.
type Log struct {
	mu   sync.Mutex
	buf  []Record
	next int
	full bool
}

// NewLog returns a Log holding at most size records; size must be positive.
func NewLog(size int) *Log {
	return &Log{buf: make([]Record, size)}
}

func (l *Log) Observe(rec *Record) {
	l.mu.Lock()
	l.buf[l.next] = *rec
	l.next++
	if l.next == len(l.buf) {
		l.next = 0
		l.full = true
	}
	l.mu.Unlock()
}

// Recent returns up to n of the newest records, oldest first. n <= 0 returns
// all of them.
func (l *Log) Recent(n int) []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var all []Record
	if l.full {
		all = append(append(all, l.buf[l.next:]...), l.buf[:l.next]...)
	} else {
		all = append(all, l.buf[:l.next]...)
	}
	if n > 0 && n < len(all) {
		all = all[len(all)-n:]
	}
	return all
}
