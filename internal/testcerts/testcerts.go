// Package testcerts makes a throwaway certificate authority and a server certificate it signs, for the client's tests
// and the local test cluster. nothing here is fit for a real server
package testcerts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Set is an authority and one server certificate it signed, in pem, with the certificate parsed
type Set struct {
	CAPEM, CertPEM, KeyPEM []byte
	CADER                  []byte
	Leaf                   *x509.Certificate
}

// New makes an authority and a server certificate for hosts, names and addresses alike, good for a day
func New(hosts ...string) (*Set, error) { return build(false, hosts) }

// NewEd25519 is New with ed25519 keys, so the leaf's signature is ed25519, which has no hash of its own
func NewEd25519(hosts ...string) (*Set, error) { return build(true, hosts) }

func newKey(ed bool) (crypto.Signer, error) {
	if ed {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func build(ed bool, hosts []string) (*Set, error) {
	if len(hosts) == 0 {
		return nil, errors.New("testcerts: a certificate needs a host")
	}
	now := time.Now()
	caKey, err := newKey(ed)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pg test authority"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	key, err := newKey(ed)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Set{
		CAPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CADER:   caDER,
		Leaf:    leaf,
	}, nil
}

// Write puts ca.crt, server.crt and server.key in dir, the key readable by its owner only, as postgres insists
func (s *Set) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, b := range map[string][]byte{"ca.crt": s.CAPEM, "server.crt": s.CertPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "server.key"), s.KeyPEM, 0o600)
}
