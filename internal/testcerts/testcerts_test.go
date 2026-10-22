package testcerts

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestTheServerCertificateChainsToTheAuthorityAndNamesItsHosts(t *testing.T) {
	s, err := New("localhost", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.CAPEM) {
		t.Fatal("the authority doesn't parse")
	}
	for _, host := range []string{"localhost", "127.0.0.1"} {
		if _, err := s.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	if _, err := s.Leaf.Verify(x509.VerifyOptions{DNSName: "elsewhere", Roots: roots}); err == nil {
		t.Error("the certificate passed for a host it doesn't name")
	}
	if _, err := tls.X509KeyPair(s.CertPEM, s.KeyPEM); err != nil {
		t.Errorf("the certificate and key don't pair: %v", err)
	}
}

func TestWriteLeavesTheKeyToItsOwner(t *testing.T) {
	s, err := New("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "server.crt", "server.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "server.key"))
	if err == nil && info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the key is readable by others: %v", info.Mode())
	}
}
