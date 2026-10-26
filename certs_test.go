// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makePEM returns a self-signed certificate for cn and names, and its key.
func makePEM(t *testing.T, cn string, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func writePair(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	c, k := makePEM(t, cn)
	os.WriteFile(certFile, c, 0o600)
	os.WriteFile(keyFile, k, 0o600)
}

func servedCN(t *testing.T, s *certStore, name string) string {
	t.Helper()
	hello := &tls.ClientHelloInfo{ServerName: name}
	c, _ := s.GetCertificate(hello)
	if c == nil {
		return ""
	}
	return c.Leaf.Subject.CommonName
}

func noWarn(t *testing.T) func(string, error) {
	return func(path string, err error) { t.Logf("warn %s: %v", path, err) }
}

// Replaced files are picked up at the next check; a broken pair keeps the old one.
func TestCertReload(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair(t, cf, kf, "one")
	s, err := newCertStore(cf, kf, nil, noWarn(t))
	if err != nil {
		t.Fatal(err)
	}
	if cn := servedCN(t, s, ""); cn != "one" {
		t.Fatalf("got %q", cn)
	}

	writePair(t, cf, kf, "two")
	future := time.Now().Add(time.Hour)
	os.Chtimes(cf, future, future)
	if cn := servedCN(t, s, ""); cn != "one" {
		t.Fatalf("reloaded before interval: %q", cn)
	}
	s.nextCheck.Store(0)
	if cn := servedCN(t, s, ""); cn != "two" {
		t.Fatalf("got %q", cn)
	}

	os.WriteFile(kf, []byte("garbage"), 0o600)
	s.nextCheck.Store(0)
	if cn := servedCN(t, s, ""); cn != "two" {
		t.Fatalf("got %q", cn)
	}
}

// Combined PEM files are loaded from a directory and chosen by SNI;
// non-PEM files are skipped.
func TestCertSelect(t *testing.T) {
	dir := t.TempDir()
	c, k := makePEM(t, "a", "a.example.com")
	os.WriteFile(filepath.Join(dir, "a"), append(c, k...), 0o600)
	c, k = makePEM(t, "wild", "*.wild.example.com")
	os.WriteFile(filepath.Join(dir, "wild.pem"), append(k, c...), 0o600)
	os.WriteFile(filepath.Join(dir, "README"), []byte("not a certificate\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "keyonly"), k, 0o600)
	cf, kf := filepath.Join(t.TempDir(), "c"), filepath.Join(t.TempDir(), "k")
	writePair(t, cf, kf, "default")

	var warned []string
	s, err := newCertStore(cf, kf, []string{dir}, func(path string, _ error) { warned = append(warned, filepath.Base(path)) })
	if err != nil {
		t.Fatal(err)
	}
	if len(warned) != 1 || warned[0] != "keyonly" {
		t.Errorf("warned about %v", warned)
	}
	for name, want := range map[string]string{
		"a.example.com":        "a",
		"A.Example.COM.":       "a",
		"x.wild.example.com":   "wild",
		"wild.example.com":     "default",
		"y.x.wild.example.com": "default",
		"other.example.com":    "default",
		"":                     "default",
	} {
		if cn := servedCN(t, s, name); cn != want {
			t.Errorf("%q: got %q, want %q", name, cn, want)
		}
		if has := want != "default"; s.Has(name) != has {
			t.Errorf("Has(%q) = %v", name, !has)
		}
	}

	os.Remove(filepath.Join(dir, "a"))
	s.nextCheck.Store(0)
	if cn := servedCN(t, s, "a.example.com"); cn != "default" {
		t.Errorf("removed file still served: %q", cn)
	}

	if _, err := newCertStore("", "", []string{filepath.Join(dir, "README")}, noWarn(t)); err == nil {
		t.Error("no certificates: want error")
	}
}
