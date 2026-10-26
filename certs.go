// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// certCheckInterval bounds how often certificate files are stat'ed and
// directories rescanned; between checks, handshakes use the cached index
// without touching the filesystem.
const certCheckInterval = time.Minute

// maxPEMFile is the largest file tried as a combined PEM; bigger files in a
// --tls-keys directory are not certificates.
const maxPEMFile = 1 << 20

var errNotPEM = errors.New("not a PEM file")

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

// certFile is one source of a certificate: the --cert/--key pair, or a
// combined PEM file (chain and key) from --tls-keys.
type certFile struct {
	certPath, keyPath string
	tried             [2]fileStamp // stamps at the last load attempt
	cert              *tls.Certificate
	err               error // of the last load attempt
}

// certIndex maps server names to certificates. Wildcards are keyed by the
// parent domain they cover one label under.
type certIndex struct {
	def   *tls.Certificate
	exact map[string][]*tls.Certificate
	wild  map[string][]*tls.Certificate
}

// certStore serves certificates chosen by SNI, reloading files when they
// change. A file that fails to load keeps serving its previous certificate
// (e.g. a cert and key mid-replacement), and is retried once it changes.
type certStore struct {
	pairCert, pairKey string // "" without --cert/--key
	keyPaths          []string
	warn              func(path string, err error)

	idx       atomic.Pointer[certIndex]
	nextCheck atomic.Int64 // unix nanoseconds

	mu     sync.Mutex
	files  map[string]*certFile // by certPath
	order  []string
	warned map[string]string // path to the error last warned of
}

// newCertStore loads the --cert/--key pair (if pairCert is set) and each
// --tls-keys path. A pair that fails to load, or no certificate at all, is
// an error; other unloadable files are passed to warn and skipped.
func newCertStore(pairCert, pairKey string, keyPaths []string, warn func(string, error)) (*certStore, error) {
	s := &certStore{pairCert: pairCert, pairKey: pairKey, keyPaths: keyPaths, warn: warn,
		files: map[string]*certFile{}, warned: map[string]string{}}
	s.load()
	if f := s.files[pairCert]; pairCert != "" && f.cert == nil {
		return nil, f.err
	}
	if s.idx.Load().def == nil {
		return nil, errors.New("no usable TLS certificate found")
	}
	return s, nil
}

// load must be called with mu held, or before s is shared.
func (s *certStore) load() {
	var order []string
	changed := false
	seen := map[string]bool{}
	add := func(certPath, keyPath string) {
		if seen[certPath] {
			return
		}
		seen[certPath] = true
		order = append(order, certPath)
		if s.loadFile(certPath, keyPath) {
			changed = true
		}
	}
	if s.pairCert != "" {
		add(s.pairCert, s.pairKey)
	}
	for _, p := range s.keyPaths {
		fi, err := os.Stat(p)
		if err != nil {
			s.report(p, err)
			continue
		}
		if !fi.IsDir() {
			add(p, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			s.report(p, err)
			continue
		}
		s.report(p, nil)
		for _, e := range entries {
			path := filepath.Join(p, e.Name())
			// Stat follows symlinks, as certificate directories often use them.
			if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
				add(path, path)
			}
		}
	}
	for path := range s.files {
		if !seen[path] {
			delete(s.files, path)
			changed = true
		}
	}
	if changed || s.idx.Load() == nil {
		s.order = order
		s.idx.Store(s.buildIndex())
	}
}

// loadFile (re)loads one file if its stamps changed since the last attempt,
// and reports whether its certificate changed.
func (s *certStore) loadFile(certPath, keyPath string) bool {
	f := s.files[certPath]
	if f == nil {
		f = &certFile{certPath: certPath, keyPath: keyPath}
		s.files[certPath] = f
	}
	cs, err1 := stamp(certPath)
	ks, err2 := stamp(keyPath)
	err := errors.Join(err1, err2)
	if err != nil {
		f.err = err
		s.report(certPath, err)
		return false
	}
	if f.tried == [2]fileStamp{cs, ks} {
		return false
	}
	f.tried = [2]fileStamp{cs, ks}
	var cert tls.Certificate
	if certPath == keyPath {
		cert, err = loadCombined(certPath)
	} else {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	}
	f.err = err
	if errors.Is(err, errNotPEM) {
		return false
	}
	s.report(certPath, err)
	if err != nil {
		return false
	}
	f.cert = &cert
	return true
}

// report warns of err for path unless it was the last warning for path;
// a nil err clears it.
func (s *certStore) report(path string, err error) {
	if err == nil {
		delete(s.warned, path)
		return
	}
	if s.warned[path] != err.Error() {
		s.warned[path] = err.Error()
		s.warn(path, err)
	}
}

func (s *certStore) buildIndex() *certIndex {
	idx := &certIndex{exact: map[string][]*tls.Certificate{}, wild: map[string][]*tls.Certificate{}}
	for _, path := range s.order {
		c := s.files[path].cert
		if c == nil || c.Leaf == nil {
			continue
		}
		if idx.def == nil {
			idx.def = c
		}
		names := c.Leaf.DNSNames
		if len(names) == 0 && c.Leaf.Subject.CommonName != "" {
			names = []string{c.Leaf.Subject.CommonName}
		}
		for _, n := range names {
			n = strings.ToLower(n)
			if parent, ok := strings.CutPrefix(n, "*."); ok {
				idx.wild[parent] = append(idx.wild[parent], c)
			} else {
				idx.exact[n] = append(idx.exact[n], c)
			}
		}
	}
	return idx
}

// loadCombined loads a PEM file holding a certificate chain (leaf first)
// and its private key, in any order.
func loadCombined(path string) (tls.Certificate, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	if fi.Size() > maxPEMFile {
		return tls.Certificate{}, errNotPEM
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !bytes.Contains(data, []byte("-----BEGIN ")) {
		return tls.Certificate{}, errNotPEM
	}
	var certPEM, keyPEM []byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch {
		case b.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		case strings.HasSuffix(b.Type, "PRIVATE KEY") && keyPEM == nil:
			keyPEM = pem.EncodeToMemory(b)
		}
	}
	switch {
	case certPEM == nil:
		return tls.Certificate{}, errors.New("no certificate in PEM file")
	case keyPEM == nil:
		return tls.Certificate{}, errors.New("no private key in PEM file")
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (s *certStore) maybeReload() {
	now := time.Now().UnixNano()
	if next := s.nextCheck.Load(); now >= next && s.nextCheck.CompareAndSwap(next, now+int64(certCheckInterval)) {
		s.mu.Lock()
		s.load()
		s.mu.Unlock()
	}
}

// match returns the certificates for name: exact names first, else
// wildcards one label up.
func (idx *certIndex) match(name string) []*tls.Certificate {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if cs := idx.exact[name]; len(cs) > 0 {
		return cs
	}
	if _, parent, ok := strings.Cut(name, "."); ok {
		return idx.wild[parent]
	}
	return nil
}

// GetCertificate picks a certificate for the client's SNI that the client
// supports (e.g. ECDSA or RSA), else the default: the --cert pair, or the
// first --tls-keys certificate.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.maybeReload()
	idx := s.idx.Load()
	if hello == nil || hello.ServerName == "" {
		return idx.def, nil
	}
	cs := idx.match(hello.ServerName)
	for _, c := range cs {
		if hello.SupportsCertificate(c) == nil {
			return c, nil
		}
	}
	if len(cs) > 0 {
		return cs[0], nil
	}
	return idx.def, nil
}

// Has reports whether a certificate covers name.
func (s *certStore) Has(name string) bool {
	s.maybeReload()
	return len(s.idx.Load().match(name)) > 0
}

// splitPaths splits a comma-separated --tls-keys value.
func splitPaths(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
