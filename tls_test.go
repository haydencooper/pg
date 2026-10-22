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
func tlsServer(t *testing.T, answer byte, hosts []string, extra []byte, serve func(*fakeServer)) (Config, *x509.Certificate) {
	t.Helper()
	return tlsServerMax(t, answer, hosts, extra, 0, serve)
}

// tlsServerMax is tlsServer with the highest tls version the server will speak; 0 leaves it to go
func tlsServerMax(t *testing.T, answer byte, hosts []string, extra []byte, max uint16, serve func(*fakeServer)) (Config, *x509.Certificate) {
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
		nc.Write(append([]byte{answer}, extra...))
		if answer != 'S' {
			return
		}
		conf := &tls.Config{Certificates: []tls.Certificate{pair}}
		if max != 0 {
			conf.MinVersion, conf.MaxVersion = tls.VersionTLS10, max
		}
		tc := tls.Server(nc, conf)
		if err := tc.Handshake(); err != nil {
			return
		}
		serve(&fakeServer{t: t, nc: tc, r: bufio.NewReader(tc)})
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	port := ln.Addr().(*net.TCPAddr).Port
	return Config{Host: "localhost", Port: port, User: "u", Password: "p", RootCAs: roots}, set.Leaf
}

func connectSoon(cfg Config) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Connect(ctx, cfg)
}

func TestAServerThatWontSpeakTLSIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'N', []string{"localhost"}, nil, nil)
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "won't speak tls") {
		t.Fatalf("got %v", err)
	}
}

func TestAnythingButYesOrNoToTheTLSRequestIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'E', []string{"localhost"}, nil, nil)
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "something else") {
		t.Fatalf("got %v", err)
	}
}

func TestACertificateForAnotherHostIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"db.example"}, nil, func(*fakeServer) {})
	_, err := connectSoon(cfg)
	var host x509.HostnameError
	if !errors.As(err, &host) {
		t.Fatalf("got %v, not a host name failure", err)
	}
}

func TestACertificateFromAnUntrustedAuthorityIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"localhost"}, nil, func(*fakeServer) {})
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
	var b []byte
	select {
	case b = <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the dial never reached the server")
	}
	if binary.BigEndian.Uint32(b[4:]) == sslRequestCode {
		t.Error("a session with tls off asked for tls")
	}
}

func TestBytesAfterTheTLSYesAreNeverReadAsPostgres(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"localhost"}, append(authOK(), ready('I')...), func(*fakeServer) {})
	c, err := connectSoon(cfg)
	if err == nil || c != nil {
		t.Fatalf("got %v, %v: bytes sent in the clear after the yes were taken as postgres", c, err)
	}
}

func TestTheHandshakeChecksTheHostTheConfigNames(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"127.0.0.1"}, nil, func(*fakeServer) {})
	cfg.Host = "127.0.0.1"
	_, err := connectSoon(cfg)
	var host x509.HostnameError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &host) || errors.As(err, &unknown) || errors.As(err, &invalid) {
		t.Fatalf("a certificate for the host it dialed was refused: %v", err)
	}
	if err == nil {
		t.Fatal("the fake server says nothing after the handshake, so the connect should fail there")
	}
}

func TestTLS11IsRefused(t *testing.T) {
	cfg, _ := tlsServerMax(t, 'S', []string{"localhost"}, nil, tls.VersionTLS11, func(*fakeServer) {})
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("got %v, wanted a tls version failure", err)
	}
}

func TestAnUnknownTLSModeIsRefusedBeforeDialing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if nc, err := ln.Accept(); err == nil {
			nc.Close()
			dialed <- struct{}{}
		}
	}()
	cfg := Config{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "u", TLS: TLSMode(3)}
	if _, err := connectSoon(cfg); err == nil || !strings.Contains(err.Error(), "tls mode") {
		t.Fatalf("got %v", err)
	}
	select {
	case <-dialed:
		t.Error("an unknown tls mode was dialed")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAVerifiedSessionNeedsAHost(t *testing.T) {
	_, err := connectSoon(Config{User: "u", Port: 1})
	if err == nil || !strings.Contains(err.Error(), "needs a host") {
		t.Fatalf("got %v", err)
	}
}

func TestTLSModesMarshalAsText(t *testing.T) {
	for _, m := range []TLSMode{TLSDefault, TLSOff, TLSVerifyFull} {
		b, err := m.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		got := TLSMode(99)
		if err := got.UnmarshalText(b); err != nil || got != m {
			t.Errorf("%v: %q came back %v, %v", m, b, got, err)
		}
	}
	var m TLSMode
	if err := m.UnmarshalText([]byte("maybe")); err == nil {
		t.Error("maybe was accepted")
	}
	if _, err := TLSMode(3).MarshalText(); err == nil {
		t.Error("an unknown mode marshaled")
	}
}
