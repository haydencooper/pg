package pg

import (
	"strings"
	"testing"
)

// rfc 7677's example exchange
const (
	rfcNonce       = "rOprNGfwEbeRWgbNEkqO"
	rfcServerFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	rfcClientFinal = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfcServerFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
)

func TestScramFollowsTheRFCsExample(t *testing.T) {
	s := &scram{user: "user", password: "pencil", nonce: rfcNonce}
	if got := s.first(); got != "n,,n=user,r="+rfcNonce {
		t.Fatalf("client first %s", got)
	}
	final, err := s.final(rfcServerFirst)
	if err != nil || final != rfcClientFinal {
		t.Fatalf("client final %s, %v", final, err)
	}
	if err := s.verify(rfcServerFinal); err != nil {
		t.Fatal(err)
	}
	if err := s.verify("v=AAAA"); err == nil {
		t.Error("a wrong server signature checked out")
	}
}

func TestScramRefusesAServerThatDoesntExtendItsNonce(t *testing.T) {
	s := &scram{password: "pencil", nonce: rfcNonce}
	s.first()
	for name, sf := range map[string]string{
		"another nonce":  "r=someoneelse,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		"no iterations":  "r=" + rfcNonce + "x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0",
		"a bad salt":     "r=" + rfcNonce + "x,s=!!,i=4096",
		"missing fields": "r=" + rfcNonce + "x",
	} {
		if _, err := s.final(sf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// postgres's default is 4096; a count far past that would keep the client hashing after its ctx ended
func TestScramRefusesMoreIterationsThanItRuns(t *testing.T) {
	s := &scram{password: "pencil", nonce: rfcNonce}
	s.first()
	if _, err := s.final("r=" + rfcNonce + "x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1048577"); err == nil || !strings.Contains(err.Error(), "iterations") {
		t.Errorf("%v", err)
	}
}

// postgres takes the user from the startup message, so its scram user is empty
func TestAPostgresScramNonceIsFreshAndItsUserEmpty(t *testing.T) {
	a, b := newScram("pw"), newScram("pw")
	if a.nonce == b.nonce || len(a.nonce) < 24 {
		t.Errorf("nonces %q %q", a.nonce, b.nonce)
	}
	if !strings.HasPrefix(a.first(), "n,,n=,r=") {
		t.Errorf("%s", a.first())
	}
}

func TestMd5IsTheHashOfTheHashWithTheSalt(t *testing.T) {
	// md5(md5("secret" + "iris") + salt)
	if got := md5Password("iris", "secret", []byte{1, 2, 3, 4}); got != "md5f1a30d224096025b75e75d8b727c28b2" {
		t.Errorf("%s", got)
	}
}
