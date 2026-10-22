package pg

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

// FuzzServerAnswers: whatever a server answers a query with, the client ends with a result or an error, never a
// panic or a hang. the message cap keeps a claim from allocating past it
func FuzzServerAnswers(f *testing.F) {
	f.Add(append(append(backend('1'), backend('2')...), append(backend('C', cstr("SELECT 0")), ready('I')...)...))
	f.Add(append(backend('E', cstr("SERROR"), cstr("C42P01"), []byte{0}), ready('I')...))
	f.Add([]byte{'D', 0, 0, 0, 10, 0, 5, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{'T', 0x7f, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, answer []byte) {
		client, server := net.Pipe()
		s := &fakeServer{t: t, nc: server, r: bufio.NewReader(server)}
		done := make(chan struct{})
		// the server's reads report through t, so the run waits for it
		defer func() {
			client.Close()
			<-done
		}()
		go func() {
			defer close(done)
			defer server.Close()
			// a query is parse, bind, describe, execute and sync; the answer follows the sync
			for i := 0; i < 5; i++ {
				s.read(false)
			}
			server.Write(answer)
		}()
		c := &Conn{nc: client, r: reader{r: bufio.NewReader(client)}, w: bufio.NewWriter(client), params: map[string]string{}}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, _ = c.Query(ctx, "SELECT 1")
	})
}

// FuzzTLSAnswer: whatever a server answers the tls request with, the client ends with an error, never a panic or a
// hang, and never takes a session no trusted certificate vouched for
func FuzzTLSAnswer(f *testing.F) {
	f.Add([]byte("N"))
	f.Add([]byte("S"))
	f.Add([]byte("E\x00\x00\x00\x08boom"))
	f.Add([]byte("S\x16\x03\x01\x00\x05hello"))
	f.Fuzz(func(t *testing.T, answer []byte) {
		client, server := net.Pipe()
		done := make(chan struct{})
		defer func() {
			client.Close()
			<-done
		}()
		go func() {
			defer close(done)
			defer server.Close()
			req := make([]byte, 8)
			if _, err := io.ReadFull(server, req); err != nil {
				return
			}
			server.Write(answer)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		tc, err := secure(ctx, client, Config{Host: "localhost", TLS: TLSVerifyFull, RootCAs: x509.NewCertPool()})
		if err == nil {
			tc.Close()
			t.Fatal("a session was taken that no trusted certificate vouched for")
		}
	})
}

// FuzzScramServerMessages: whatever a server says in its scram steps, the client answers or refuses, and never panics
func FuzzScramServerMessages(f *testing.F) {
	f.Add("r=abc,s=c2FsdA==,i=4096", "v=c2ln")
	f.Add("r=,s=,i=-1", "")
	f.Add("r=x,s=!!!,i=999999999", "v=")
	f.Fuzz(func(t *testing.T, serverFirst, serverFinal string) {
		for _, binding := range [][]byte{nil, {1, 2, 3}} {
			s := newScram("pw", binding)
			s.first()
			if _, err := s.final(serverFirst); err == nil {
				_ = s.verify(serverFinal)
			}
		}
	})
}

// FuzzBatchAnswers: whatever a server answers a two-statement batch with, the client ends with results or an error,
// never a panic or a hang
func FuzzBatchAnswers(f *testing.F) {
	f.Add(append(append(backend('1'), backend('2')...), append(backend('C', cstr("SELECT 0")), ready('I')...)...))
	f.Add(append(backend('C', cstr("SELECT 1")), append(backend('C', cstr("SELECT 1")), backend('C', cstr("SELECT 1"))...)...))
	f.Add(append(backend('E', cstr("SERROR"), cstr("C42P01"), []byte{0}), ready('I')...))
	f.Fuzz(func(t *testing.T, answer []byte) {
		client, server := net.Pipe()
		s := &fakeServer{t: t, nc: server, r: bufio.NewReader(server)}
		done := make(chan struct{})
		defer func() {
			client.Close()
			<-done
		}()
		go func() {
			defer close(done)
			defer server.Close()
			// two statements are parse, bind, describe and execute each, then one sync
			for i := 0; i < 9; i++ {
				s.read(false)
			}
			server.Write(answer)
		}()
		c := &Conn{nc: client, r: reader{r: bufio.NewReader(client)}, w: bufio.NewWriter(client), params: map[string]string{}, tx: 'I'}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, _ = c.Batch(ctx, Statement{SQL: "SELECT 1"}, Statement{SQL: "SELECT 2"})
	})
}
