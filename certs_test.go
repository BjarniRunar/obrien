// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
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
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
}

func servedCN(t *testing.T, kp *keyPair) string {
	t.Helper()
	c, _ := kp.GetCertificate(nil)
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// Replaced files are picked up at the next check; a broken pair keeps the old one.
func TestKeyPairReload(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair(t, cf, kf, "one")
	kp, err := newKeyPair(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	if cn := servedCN(t, kp); cn != "one" {
		t.Fatalf("got %q", cn)
	}

	writePair(t, cf, kf, "two")
	future := time.Now().Add(time.Hour)
	os.Chtimes(cf, future, future)
	if cn := servedCN(t, kp); cn != "one" {
		t.Fatalf("reloaded before interval: %q", cn)
	}
	kp.nextCheck.Store(0)
	if cn := servedCN(t, kp); cn != "two" {
		t.Fatalf("got %q", cn)
	}

	os.WriteFile(kf, []byte("garbage"), 0o600)
	kp.nextCheck.Store(0)
	if cn := servedCN(t, kp); cn != "two" {
		t.Fatalf("got %q", cn)
	}
}
