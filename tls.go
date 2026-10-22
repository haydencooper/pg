package pg

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// sslRequestCode asks the server to switch to tls before anything else is said
const sslRequestCode = 80877103

// secure asks for tls and does the handshake, checking the server's certificate chains to cfg's roots and names its
// host. the one-byte answer is read straight off the socket, so nothing a server sends before the handshake is ever
// read as postgres: it goes to the handshake, which fails on it
func secure(ctx context.Context, nc net.Conn, cfg Config) (*tls.Conn, error) {
	stop := context.AfterFunc(ctx, func() { _ = nc.SetDeadline(time.Unix(1, 0)) })
	tc, err := handshake(ctx, nc, cfg)
	if !stop() {
		return nil, own(ctx.Err())
	}
	return tc, err
}

func handshake(ctx context.Context, nc net.Conn, cfg Config) (*tls.Conn, error) {
	req := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), sslRequestCode)
	if _, err := nc.Write(req); err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	var answer [1]byte
	if _, err := io.ReadFull(nc, answer[:]); err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	switch answer[0] {
	case 'S':
	case 'N':
		return nil, errors.New("pg: the server won't speak tls, and this session needs it")
	default:
		return nil, errors.New("pg: the server answered the tls request with something else")
	}
	tc := tls.Client(nc, &tls.Config{ServerName: cfg.Host, RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"postgresql"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	return tc, nil
}
