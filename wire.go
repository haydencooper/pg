// Package pg is a postgres client: the frontend/backend protocol, version 3, over tcp or a unix socket. it
// runs scripts through the simple query protocol and everything else through the extended one, with text parameters
// and text results. it has no tls, so it's for a database on the same box
package pg

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// rows are small, so a message past this is a fault, not data
const maxMessage = 64 << 20

// a message past this gets a buffer the reader drops once it's read, so one big row doesn't stay held by the session
const keptBuffer = 1 << 20

// reader reads backend messages: a type byte, then a length that counts itself, then the body
type reader struct {
	r   *bufio.Reader
	buf []byte
}

// next reads one message; its body is good until the next call
func (r *reader) next() (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r.r, head[:]); err != nil {
		return 0, nil, err
	}
	n := int64(binary.BigEndian.Uint32(head[1:])) - 4
	if n < 0 || n > maxMessage {
		return 0, nil, fmt.Errorf("pg: a %q message claims %d bytes", head[0], n)
	}
	if int64(cap(r.buf)) < n {
		r.buf = make([]byte, n)
	}
	body := r.buf[:n]
	if n > keptBuffer {
		r.buf = nil
	}
	if _, err := io.ReadFull(r.r, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

// msg builds one frontend message; the startup message has no type byte
type msg struct {
	b   []byte
	len int
}

func newMsg(typ byte) *msg {
	m := &msg{}
	if typ != 0 {
		m.b = append(m.b, typ)
		m.len = 1
	}
	m.b = append(m.b, 0, 0, 0, 0)
	return m
}

func (m *msg) int16(v int)    { m.b = binary.BigEndian.AppendUint16(m.b, uint16(v)) }
func (m *msg) int32(v int)    { m.b = binary.BigEndian.AppendUint32(m.b, uint32(v)) }
func (m *msg) str(s string)   { m.b = append(append(m.b, s...), 0) }
func (m *msg) bytes(v []byte) { m.b = append(m.b, v...) }

// done writes the length in, which counts itself but not the type byte
func (m *msg) done() []byte {
	binary.BigEndian.PutUint32(m.b[m.len:], uint32(len(m.b)-m.len))
	return m.b
}

// fields walks a backend message's body. a read past its end returns zeros and leaves ok false
type fields struct {
	b   []byte
	bad bool
}

func (f *fields) ok() bool { return !f.bad }

func (f *fields) take(n int) []byte {
	if f.bad || n < 0 || n > len(f.b) {
		f.bad = true
		return nil
	}
	v := f.b[:n]
	f.b = f.b[n:]
	return v
}

func (f *fields) u8() byte {
	if v := f.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (f *fields) int16() int {
	if v := f.take(2); v != nil {
		return int(int16(binary.BigEndian.Uint16(v)))
	}
	return 0
}

func (f *fields) int32() int {
	if v := f.take(4); v != nil {
		return int(int32(binary.BigEndian.Uint32(v)))
	}
	return 0
}

func (f *fields) str() string {
	for i, c := range f.b {
		if c == 0 {
			s := string(f.b[:i])
			f.b = f.b[i+1:]
			return s
		}
	}
	f.bad = true
	return ""
}

func (f *fields) rest() []byte {
	v := f.b
	f.b = nil
	return v
}
