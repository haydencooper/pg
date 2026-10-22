package pg

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
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

// endPoint is the tls-server-end-point channel binding (rfc 5929): the server certificate's hash, by the hash its
// signature uses, with md5 and sha-1 raised to sha-256. a signature with no hash of its own, as ed25519's, has none
func endPoint(cert *x509.Certificate) ([]byte, error) {
	var h hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
		x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		h = sha256.New()
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		h = sha512.New()
	default:
		return nil, errors.New("pg: the server's certificate is signed in a way channel binding can't name (" + cert.SignatureAlgorithm.String() + ")")
	}
	h.Write(cert.Raw)
	return h.Sum(nil), nil
}
