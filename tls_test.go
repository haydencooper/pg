package pg

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// saslStart reads the client's first scram message: the mechanism it chose and its client-first
func saslStart(s *fakeServer) (mech, first string) {
	_, body := s.read(false)
	f := fields{b: body}
	mech = f.str()
	n := f.int32()
	return mech, string(f.take(n))
}

func saslOffer(mechs ...string) []byte {
	b := binary.BigEndian.AppendUint32(nil, 10)
	for _, m := range mechs {
		b = append(b, cstr(m)...)
	}
	return backend('R', append(b, 0))
}

func saslContinue(msg string) []byte {
	return backend('R', append(binary.BigEndian.AppendUint32(nil, 11), msg...))
}

func TestOverTLSScramIsBoundToTheServersCertificate(t *testing.T) {
	var mech, first, final string
	cfg, leaf := tlsServer(t, 'S', []string{"localhost"}, nil, func(s *fakeServer) {
		s.read(true)
		s.send(saslOffer("SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"))
		mech, first = saslStart(s)
		nonce := scramAttrs(strings.TrimPrefix(first, "p=tls-server-end-point,,n=,"))["r"]
		s.send(saslContinue("r=" + nonce + "server,s=c2FsdA==,i=4096"))
		_, body := s.read(false)
		final = string(body)
		s.send(backend('E', cstr("SFATAL"), cstr("C28P01"), cstr("Mstop here"), []byte{0}))
	})
	_, err := connectSoon(cfg)
	if err == nil {
		t.Fatal("the session went on past the server's error")
	}
	if mech != "SCRAM-SHA-256-PLUS" {
		t.Errorf("over tls the client chose %q", mech)
	}
	if !strings.HasPrefix(first, "p=tls-server-end-point,,") {
		t.Errorf("the client-first doesn't bind to the channel: %q", first)
	}
	sum := sha256.Sum256(leaf.Raw)
	want := "c=" + base64.StdEncoding.EncodeToString(append([]byte("p=tls-server-end-point,,"), sum[:]...))
	if !strings.HasPrefix(final, want+",") {
		t.Errorf("the client-final's channel binding is %q, want %q", final, want)
	}
}

func TestOverTLSAServerOfferingOnlyUnboundScramIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"localhost"}, nil, func(s *fakeServer) {
		s.read(true)
		s.send(saslOffer("SCRAM-SHA-256"))
	})
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "SCRAM-SHA-256-PLUS") {
		t.Fatalf("got %v", err)
	}
}

func TestOverTLSMd5IsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"localhost"}, nil, func(s *fakeServer) {
		s.read(true)
		s.send(backend('R', []byte{0, 0, 0, 5, 1, 2, 3, 4}))
	})
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "channel binding") {
		t.Fatalf("got %v", err)
	}
}

func TestOverTLSASessionLetInWithoutScramIsRefused(t *testing.T) {
	cfg, _ := tlsServer(t, 'S', []string{"localhost"}, nil, func(s *fakeServer) {
		s.read(true)
		s.send(authOK())
	})
	_, err := connectSoon(cfg)
	if err == nil || !strings.Contains(err.Error(), "channel binding") {
		t.Fatalf("got %v", err)
	}
}

func TestTheBindingHashFollowsTheCertificatesSignature(t *testing.T) {
	set, err := testcerts.New("localhost")
	if err != nil {
		t.Fatal(err)
	}
	got, err := endPoint(set.Leaf)
	sum := sha256.Sum256(set.Leaf.Raw)
	if err != nil || string(got) != string(sum[:]) {
		t.Errorf("an ecdsa-sha256 certificate binds as %x %v", got, err)
	}
	ed := *set.Leaf
	ed.SignatureAlgorithm = x509.PureEd25519
	if _, err := endPoint(&ed); err == nil {
		t.Error("an ed25519 certificate, which has no binding hash, was given one")
	}
}
