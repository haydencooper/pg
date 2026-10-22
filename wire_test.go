package pg

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// backend builds a backend message as a server would send it
func backend(typ byte, body ...[]byte) []byte {
	m := newMsg(typ)
	for _, b := range body {
		m.bytes(b)
	}
	return m.done()
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func TestAMessageIsItsTypeAndABodyOfTheLengthItClaims(t *testing.T) {
	in := append(backend('C', cstr("SELECT 1")), backend('Z', []byte{'I'})...)
	r := reader{r: bufio.NewReader(bytes.NewReader(in))}
	typ, body, err := r.next()
	if err != nil || typ != 'C' || string(body) != "SELECT 1\x00" {
		t.Fatalf("%q %q %v", typ, body, err)
	}
	typ, body, err = r.next()
	if err != nil || typ != 'Z' || string(body) != "I" {
		t.Fatalf("%q %q %v", typ, body, err)
	}
}

func TestAMessageClaimingTooMuchOrTooLittleIsRefused(t *testing.T) {
	for name, head := range map[string][]byte{
		"over the cap":         {'D', 0x7f, 0xff, 0xff, 0xff},
		"under its own length": {'D', 0, 0, 0, 3},
	} {
		r := reader{r: bufio.NewReader(bytes.NewReader(head))}
		if _, _, err := r.next(); err == nil || !strings.Contains(err.Error(), "claims") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestABigMessagesBufferIsntKeptOnceItsRead(t *testing.T) {
	in := append(backend('D', make([]byte, 2<<20)), backend('C', cstr("SELECT 1"))...)
	r := reader{r: bufio.NewReader(bytes.NewReader(in))}
	if _, body, err := r.next(); err != nil || len(body) != 2<<20 {
		t.Fatalf("%d %v", len(body), err)
	}
	if _, _, err := r.next(); err != nil {
		t.Fatal(err)
	}
	if cap(r.buf) > 1<<20 {
		t.Errorf("the reader keeps %d bytes", cap(r.buf))
	}
}

func TestAFrontendMessageCountsItsOwnLength(t *testing.T) {
	q := newMsg('Q')
	q.str("SELECT 1")
	if got := q.done(); !bytes.Equal(got, []byte("Q\x00\x00\x00\x0dSELECT 1\x00")) {
		t.Errorf("%q", got)
	}
	s := newMsg(0)
	s.int32(196608)
	if got := s.done(); !bytes.Equal(got, []byte{0, 0, 0, 8, 0, 3, 0, 0}) {
		t.Errorf("startup %v", got)
	}
}

func TestAFieldPastTheBodysEndLeavesTheWalkNotOK(t *testing.T) {
	b := fields{b: []byte{0, 1}}
	if b.int16() != 1 || !b.ok() {
		t.Fatal("int16")
	}
	b.int32()
	if b.ok() {
		t.Error("a short int32 read as ok")
	}
	s := fields{b: []byte("no terminator")}
	s.str()
	if s.ok() {
		t.Error("a string with no nul read as ok")
	}
}

func TestAServerErrorKeepsItsSqlstateAndMessage(t *testing.T) {
	var body []byte
	for _, f := range []string{"SERROR", "VERROR", "C23505", "Mduplicate key value", "Dkey (id)=(1) already exists", "nt_pkey"} {
		body = append(body, cstr(f)...)
	}
	body = append(body, 0)
	e := parseError(body)
	if e.Severity != "ERROR" || e.Code != "23505" || e.Message != "duplicate key value" || e.Detail == "" || e.Constraint != "t_pkey" {
		t.Fatalf("%+v", e)
	}
	if e.Error() != "pg: ERROR 23505: duplicate key value" {
		t.Errorf("%s", e.Error())
	}
}
