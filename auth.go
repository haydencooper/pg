package pg

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// md5Password is postgres's md5 answer: md5 of md5(password + user) and the salt, in hex
func md5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

// postgres's default is 4096. the hashing doesn't watch ctx, so a server asking for far more could hold Connect past
// its deadline
const maxScramIterations = 1 << 20

// scram is one scram-sha-256 exchange (rfc 5802 and 7677), bound to the tls channel when binding is set
// (scram-sha-256-plus, rfc 5929's tls-server-end-point). the password is used as it is: saslprep leaves ascii alone,
// and the passwords sent here are ascii
type scram struct {
	user, password, nonce string
	binding               []byte
	clientFirstBare       string
	authMessage           string
	saltedPassword        []byte
}

func newScram(password string, binding []byte) *scram {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return &scram{password: password, binding: binding, nonce: base64.StdEncoding.EncodeToString(b)}
}

// header is the gs2 header: bound to the tls channel, or not bound at all
func (s *scram) header() string {
	if s.binding != nil {
		return "p=tls-server-end-point,,"
	}
	return "n,,"
}

func (s *scram) first() string {
	s.clientFirstBare = "n=" + s.user + ",r=" + s.nonce
	return s.header() + s.clientFirstBare
}

func (s *scram) final(serverFirst string) (string, error) {
	attrs := scramAttrs(serverFirst)
	if _, ok := attrs["m"]; ok {
		return "", errors.New("pg: the server requires a scram extension this client doesn't speak")
	}
	nonce, salt64, iter := attrs["r"], attrs["s"], attrs["i"]
	if !strings.HasPrefix(nonce, s.nonce) || len(nonce) == len(s.nonce) {
		return "", errors.New("pg: the server's scram nonce doesn't extend ours")
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil || len(salt) == 0 {
		return "", errors.New("pg: the server's scram salt doesn't decode")
	}
	n, err := strconv.Atoi(iter)
	if err != nil || n < 1 {
		return "", errors.New("pg: the server's scram iteration count isn't a count")
	}
	if n > maxScramIterations {
		return "", errors.New("pg: the server asks for more scram iterations than this client runs")
	}
	s.saltedPassword = pbkdf2SHA256([]byte(s.password), salt, n)
	// the channel binding is the header and the certificate's hash; unbound, it's base64 of "n,,", which is biws
	withoutProof := "c=" + base64.StdEncoding.EncodeToString(append([]byte(s.header()), s.binding...)) + ",r=" + nonce
	s.authMessage = s.clientFirstBare + "," + serverFirst + "," + withoutProof
	clientKey := hmacSHA256(s.saltedPassword, "Client Key")
	stored := sha256.Sum256(clientKey)
	proof := hmacSHA256(stored[:], s.authMessage)
	for i := range proof {
		proof[i] ^= clientKey[i]
	}
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// verify checks the server's signature, so a server that doesn't know the password can't pass as one that does
func (s *scram) verify(serverFinal string) error {
	attrs := scramAttrs(serverFinal)
	if e, ok := attrs["e"]; ok {
		return errors.New("pg: the server refused scram: " + e)
	}
	got, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil || s.saltedPassword == nil {
		return errors.New("pg: the server's scram signature doesn't decode")
	}
	want := hmacSHA256(hmacSHA256(s.saltedPassword, "Server Key"), s.authMessage)
	if !hmac.Equal(got, want) {
		return errors.New("pg: the server's scram signature doesn't check out")
	}
	return nil
}

func scramAttrs(msg string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(msg, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && len(k) == 1 {
			out[k] = v
		}
	}
	return out
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// pbkdf2SHA256 is pbkdf2 with hmac-sha-256 for one 32-byte block, which is all scram-sha-256 takes
func pbkdf2SHA256(password, salt []byte, iter int) []byte {
	m := hmac.New(sha256.New, password)
	m.Write(salt)
	m.Write([]byte{0, 0, 0, 1})
	u := m.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		m.Reset()
		m.Write(u)
		u = m.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}
