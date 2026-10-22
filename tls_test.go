package pg

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/haydencooper/pg/internal/testcerts"
)

// tlsServer listens on loopback for one session. it answers the tls request with answer and, on 'S', does the
// handshake with a certificate for hosts, then runs serve over the encrypted session. the config it returns trusts
// the certificate's authority
func tlsServer(t *testing.T, answer byte, hosts []string, serve func(*fakeServer)) (Config, *x509.Certificate) {
	t.Helper()
	set, err := testcerts.New(hosts...)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(set.CertPEM, set.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(set.CAPEM)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		nc, err := ln.Accept()
		ln.Close()
		if err != nil {
			return
		}
		defer nc.Close()
		_ = nc.SetDeadline(time.Now().Add(5 * time.Second))
		req := make([]byte, 8)
		if _, err := io.ReadFull(nc, req); err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if binary.BigEndian.Uint32(req[4:]) != sslRequestCode {
			t.Errorf("the first message wasn't a tls request: %x", req)
			return
		}
		nc.Write([]byte{answer})
		if answer != 'S' {
			return
		}
		tc := tls.Server(nc, &tls.Config{Certificates: []tls.Certificate{pair}})
		if err := tc.Handshake(); err != nil {
			return
		}
		serve(&fakeServer{t: t, nc: tc, r: bufio.NewReader(tc)})
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	port := ln.Addr().(*net.TCPAddr).Port
	return Config{Host: "localhost", Port: port, User: "u", Password: "p", TLS: TLSVerifyFull, RootCAs: roots}, set.Leaf
}

func connectSoon(cfg Config) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Connect(ctx, cfg)
}

func TestAServerThatWontSpeakTLSIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'N', []string{"localhost"}, nil)
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "won't speak tls") {
		t.Fatalf("got %v", err)
	}
}

func TestAnythingButYesOrNoToTheTLSRequestIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'E', []string{"localhost"}, nil)
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "something else") {
		t.Fatalf("got %v", err)
	}
}

func TestACertificateForAnotherHostIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"db.example"}, func(*fakeServer) {})
	_, err := connectSoon(cfg)
	var host x509.HostnameError
	if !errors.As(err, &host) {
		t.Fatalf("got %v, not a host name failure", err)
	}
}

func TestACertificateFromAnUntrustedAuthorityIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"localhost"}, func(*fakeServer) {})
	cfg.RootCAs = x509.NewCertPool()
	_, err := connectSoon(cfg)
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("got %v, not an unknown authority", err)
	}
}

func TestPlainSessionsNeverAskForTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	first := make(chan []byte, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		defer nc.Close()
		b := make([]byte, 8)
		io.ReadFull(nc, b)
		first <- b
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	Connect(ctx, Config{Host: "127.0.0.1", Port: port, User: "u", TLS: TLSOff})
	b := <-first
	if binary.BigEndian.Uint32(b[4:]) == sslRequestCode {
		t.Error("a session with tls off asked for tls")
	}
}
