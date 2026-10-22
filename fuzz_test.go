package pg

import (
	"bufio"
	"context"
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
