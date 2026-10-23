// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// certCheckInterval bounds how often the key pair files are stat'ed; between
// checks, handshakes use the cached pair without touching the filesystem.
const certCheckInterval = time.Minute

// keyPair serves a TLS key pair, reloading it when its files change.
type keyPair struct {
	certFile, keyFile string

	cert      atomic.Pointer[tls.Certificate]
	nextCheck atomic.Int64 // unix nanoseconds

	mu                sync.Mutex
	certStat, keyStat fileStamp
}

type fileStamp struct {
	mod  time.Time
	size int64
}

func stamp(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{fi.ModTime(), fi.Size()}, nil
}

func newKeyPair(certFile, keyFile string) (*keyPair, error) {
	kp := &keyPair{certFile: certFile, keyFile: keyFile}
	if err := kp.load(); err != nil {
		return nil, err
	}
	return kp, nil
}

// load must be called with mu held, or before kp is shared.
func (kp *keyPair) load() error {
	cs, err := stamp(kp.certFile)
	if err != nil {
		return err
	}
	ks, err := stamp(kp.keyFile)
	if err != nil {
		return err
	}
	if kp.cert.Load() != nil && cs == kp.certStat && ks == kp.keyStat {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(kp.certFile, kp.keyFile)
	if err != nil {
		return err
	}
	kp.cert.Store(&cert)
	kp.certStat, kp.keyStat = cs, ks
	return nil
}

// GetCertificate keeps serving the previous pair if a reload fails (e.g. the
// cert and key are mid-replacement and don't match yet); the stamps are left
// unchanged, so the next check retries.
func (kp *keyPair) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now().UnixNano()
	if next := kp.nextCheck.Load(); now >= next && kp.nextCheck.CompareAndSwap(next, now+int64(certCheckInterval)) {
		kp.mu.Lock()
		_ = kp.load()
		kp.mu.Unlock()
	}
	return kp.cert.Load(), nil
}
