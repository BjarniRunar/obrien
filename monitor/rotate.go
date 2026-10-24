// SPDX-License-Identifier: AGPL-3.0-or-later

package monitor

import (
	"os"
	"sync"
	"time"
)

// RotateSuffix is the time layout appended to a rotated file's name.
const RotateSuffix = "20060102-150405"

// RotatingFile appends to a file and, once max bytes have been written to
// it, renames it to PATH.<RotateSuffix> and opens a new one. Bytes in an
// existing file at open are not counted.
type RotatingFile struct {
	mu      sync.Mutex
	path    string
	max     int64
	written int64
	f       *os.File
	now     func() time.Time
}

func OpenRotatingFile(path string, max int64) (*RotatingFile, error) {
	r := &RotatingFile{path: path, max: max, now: time.Now}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	r.f, r.written = f, 0
	return nil
}

// Write keeps writing to the current file if rotating fails, so no lines
// are lost.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.f.Write(p)
	r.written += int64(n)
	if r.written >= r.max {
		r.rotate()
	}
	return n, err
}

func (r *RotatingFile) rotate() {
	if os.Rename(r.path, r.path+"."+r.now().Format(RotateSuffix)) != nil {
		return
	}
	old := r.f
	if r.open() != nil {
		r.f = old
		return
	}
	_ = old.Close()
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
