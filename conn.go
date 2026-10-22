package pg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Conn is one session with the server. it's for one goroutine at a time
type Conn struct {
	nc      net.Conn
	r       reader
	w       *bufio.Writer
	params  map[string]string
	pid     int
	tx      byte
	pending []Notification
	broken  error
}

// Notification is a NOTIFY on a channel the session listens to
type Notification struct {
	PID     int
	Channel string
	Payload string
}

// Result is a statement's rows, all read, and its command tag
type Result struct {
	Columns []string
	Rows    []Row
	Tag     string
}

// Affected is the rows a statement changed, from its tag: "INSERT 0 3" is 3 and "UPDATE 2" is 2
func (r *Result) Affected() int {
	f := strings.Fields(r.Tag)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[len(f)-1])
	return n
}

// settings are the session's own, sent at startup. values are written and read under them, so a server that reports
// another value for one, at startup or later, can't be read right. extra_float_digits=3 keeps floats exact whatever
// the server's default
var settings = [][2]string{{"client_encoding", "UTF8"}, {"DateStyle", "ISO, MDY"}, {"TimeZone", "UTC"},
	{"extra_float_digits", "3"}, {"bytea_output", "hex"}}

// ErrRolledBack is a commit that found its transaction failed. postgres rolls it back and answers COMMIT with a
// ROLLBACK tag, not an error
var ErrRolledBack = errors.New("pg: the transaction failed, so it rolled back")

var errLeftOpen = errors.New("pg: the batch left a transaction open, so it was rolled back")

// ErrCommitUnknown is a COMMIT that went out and got no answer, as when ctx ends or the session is cut while Tx waits
// for one. the work may have been applied, so running it again could apply it twice
var ErrCommitUnknown = errors.New("pg: the commit's outcome is unknown")

var errWorkEnded = errors.New("pg: the work ended the transaction itself")

// Connect dials the database, asks for tls when the config's mode needs it, and authenticates. over tls it speaks
// only scram-sha-256-plus, bound to the server's certificate; in the clear it takes trust, md5 or scram-sha-256. a
// cleartext password is refused, since it would cross the wire as it is
func Connect(ctx context.Context, cfg Config) (*Conn, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	network, addr := cfg.address()
	var d net.Dialer
	nc, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	if cfg.mode() == TLSVerifyFull {
		tc, err := secure(ctx, nc, cfg)
		if err != nil {
			nc.Close()
			return nil, err
		}
		nc = tc
	}
	return startup(ctx, nc, cfg)
}

func startup(ctx context.Context, nc net.Conn, cfg Config) (*Conn, error) {
	c := &Conn{nc: nc, r: reader{r: bufio.NewReader(nc)}, w: bufio.NewWriter(nc), params: map[string]string{}}
	if err := c.start(ctx, cfg); err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) start(ctx context.Context, cfg Config) error {
	defer c.watch(ctx)()
	m := newMsg(0)
	m.int32(196608)
	who := [][2]string{{"user", cfg.User}, {"database", cfg.Database}, {"application_name", cfg.AppName}}
	for _, kv := range append(who, settings...) {
		if kv[1] != "" {
			m.str(kv[0])
			m.str(kv[1])
		}
	}
	m.b = append(m.b, 0)
	if err := c.send(m.done()); err != nil {
		return c.cut(ctx, err)
	}
	var sc *scram
	verified := false
	for {
		typ, body, err := c.r.next()
		if err != nil {
			return c.cut(ctx, err)
		}
		f := fields{b: body}
		switch typ {
		case 'R':
			code := f.int32()
			if !f.ok() {
				return errors.New("pg: an authentication message runs short")
			}
			// a switch away from scram partway could be a server after the password in a weaker form
			if sc != nil && code != 0 && code != 11 && code != 12 {
				return errors.New("pg: the server changed auth methods partway through scram")
			}
			switch code {
			case 0:
				// a server that skips its signature could be one that doesn't know the password
				if sc != nil && !verified {
					return errors.New("pg: the server ended scram without its signature")
				}
			case 3:
				return errors.New("pg: the server asks for the password in cleartext, which this client refuses")
			case 5:
				salt := f.take(4)
				if !f.ok() {
					return errors.New("pg: the server's md5 request has no salt")
				}
				p := newMsg('p')
				p.str(md5Password(cfg.User, cfg.Password, salt))
				if err := c.send(p.done()); err != nil {
					return c.cut(ctx, err)
				}
			case 10:
				var mechs []string
				for f.ok() {
					s := f.str()
					if s == "" {
						break
					}
					mechs = append(mechs, s)
				}
				if !slices.Contains(mechs, "SCRAM-SHA-256") {
					return fmt.Errorf("pg: the server offers %v; only SCRAM-SHA-256 is spoken here", mechs)
				}
				sc = newScram(cfg.Password)
				first := sc.first()
				p := newMsg('p')
				p.str("SCRAM-SHA-256")
				p.int32(len(first))
				p.bytes([]byte(first))
				if err := c.send(p.done()); err != nil {
					return c.cut(ctx, err)
				}
			case 11:
				if sc == nil {
					return errors.New("pg: a scram step came before scram began")
				}
				final, err := sc.final(string(f.rest()))
				if err != nil {
					return err
				}
				p := newMsg('p')
				p.bytes([]byte(final))
				if err := c.send(p.done()); err != nil {
					return c.cut(ctx, err)
				}
			case 12:
				if sc == nil {
					return errors.New("pg: a scram step came before scram began")
				}
				if err := sc.verify(string(f.rest())); err != nil {
					return err
				}
				verified = true
			default:
				return fmt.Errorf("pg: the server asks for auth method %d, which this client doesn't speak", code)
			}
		case 'S':
			if err := c.param(body); err != nil {
				return err
			}
		case 'K':
			if len(body) != 8 {
				return errors.New("pg: a backend key message isn't 8 bytes")
			}
			c.pid = f.int32()
		case 'E':
			return parseError(body)
		case 'N':
		case 'Z':
			tx, err := readyStatus(body)
			if err != nil {
				return err
			}
			c.tx = tx
			return nil
		default:
			return fmt.Errorf("pg: an unexpected %q message during startup", typ)
		}
	}
}

// param records a setting the server reported, and refuses another value for one of the session's own
func (c *Conn) param(body []byte) error {
	f := fields{b: body}
	k, v := f.str(), f.str()
	if !f.ok() {
		return errors.New("pg: a parameter status runs short")
	}
	for _, s := range settings {
		if s[0] == k && s[1] != v {
			return fmt.Errorf("pg: the server reports a %s other than the session's, so values would read differently", k)
		}
	}
	c.params[k] = v
	return nil
}

// Param is the latest value the server reported for a setting, such as server_version
func (c *Conn) Param(name string) string { return c.params[name] }

// TxStatus is the server's transaction status after the last statement: I idle, T in a transaction, E in a failed one
func (c *Conn) TxStatus() byte { return c.tx }

// Close ends the session. closing one that's broken or closed already does nothing
func (c *Conn) Close() error {
	if c.broken != nil {
		return nil
	}
	c.broken = errors.New("pg: the session is closed")
	// a server that stopped reading can't hold Close up
	_ = c.nc.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.send(newMsg('X').done())
	return c.nc.Close()
}

// watch puts ctx's deadline and cancellation on the socket for one exchange, and takes them off after
func (c *Conn) watch(ctx context.Context) func() {
	// the socket's deadline waits for ctx to end, so a read that times out always finds ctx.Err set
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.nc.SetDeadline(time.Now())
		close(fired)
	})
	return func() {
		if !stop() {
			<-fired
		}
		_ = c.nc.SetDeadline(time.Time{})
	}
}

// cut marks the session broken after an exchange stopped partway, and answers why: ctx's error when it ended first
func (c *Conn) cut(ctx context.Context, err error) error {
	return c.lost(ctx, nil, err)
}

// lost is cut after a read failed, keeping an error the server sent first. a FATAL or PANIC is why the server hung
// up, as on a shutdown or a terminated backend. any other error is the statement's own, so the cut goes with it: a
// caller that handles the error would otherwise go on with a dead session
func (c *Conn) lost(ctx context.Context, first *Error, err error) error {
	if first != nil && (first.Severity == "FATAL" || first.Severity == "PANIC") {
		err, first = first, nil
	}
	switch {
	case ctx.Err() != nil:
		err = own(ctx.Err())
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		err = &wrapError{"the server closed the session", err}
	default:
		err = own(err)
	}
	if first != nil {
		err = &thenError{first, err}
	}
	c.broken = &wrapError{"the session is broken", err}
	_ = c.nc.Close()
	return err
}

// readyStatus reads a ReadyForQuery, whose body is the transaction status alone
func readyStatus(body []byte) (byte, error) {
	if len(body) != 1 || body[0] != 'I' && body[0] != 'T' && body[0] != 'E' {
		return 0, errors.New("pg: a ready for query message's status isn't I, T or E")
	}
	return body[0], nil
}

// unexpected says what's wrong with a message a statement's answer can't hold
func unexpected(typ byte) error {
	if typ == 'G' || typ == 'H' || typ == 'W' {
		return errors.New("pg: copy isn't supported")
	}
	return fmt.Errorf("pg: an unexpected %q message", typ)
}

// rolledBack says whether a call's first command tag is a COMMIT, END or PREPARE TRANSACTION that found its
// transaction failed. inside a failed transaction every other statement fails with 25P02, so only a call that started
// there gets that tag, and only from its first statement: one that doesn't lead with ROLLBACK or ABORT didn't ask
func rolledBack(started byte, tag, sql string) bool {
	if started != 'E' || tag != "ROLLBACK" {
		return false
	}
	w := leadingWord(sql)
	return !strings.EqualFold(w, "ROLLBACK") && !strings.EqualFold(w, "ABORT")
}

// leadingWord is sql's first word, past whitespace, -- comments and /* */ comments, which nest in postgres
func leadingWord(sql string) string {
	depth := 0
	for i := 0; i < len(sql); {
		rest := sql[i:]
		switch {
		case depth > 0 && strings.HasPrefix(rest, "*/"):
			depth--
			i += 2
		case strings.HasPrefix(rest, "/*"):
			depth++
			i += 2
		case depth > 0:
			i++
		case strings.HasPrefix(rest, "--"):
			if n := strings.IndexAny(rest, "\r\n"); n >= 0 {
				i += n
			} else {
				i = len(sql)
			}
		case strings.IndexByte(" \t\n\r\f\v", sql[i]) >= 0:
			i++
		default:
			n := 0
			for n < len(rest) && wordByte(rest[n]) {
				n++
			}
			return rest[:n]
		}
	}
	return ""
}

func wordByte(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || b == '_' || b == '$' || b >= 0x80
}

func (c *Conn) send(b []byte) error {
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Conn) notified(body []byte) {
	f := fields{b: body}
	n := Notification{PID: f.int32(), Channel: f.str(), Payload: f.str()}
	if f.ok() {
		c.pending = append(c.pending, n)
	}
}

// Script runs sql through the simple query protocol: no arguments and any number of statements, as migrations,
// BEGIN, COMMIT and LISTEN need. rows are read and dropped; the first error the server sends is the answer, and a
// COMMIT that rolled back a failed transaction is an error too
func (c *Conn) Script(ctx context.Context, sql string) error {
	if c.broken != nil {
		return c.broken
	}
	if err := ctx.Err(); err != nil {
		return own(err)
	}
	defer c.watch(ctx)()
	started := c.tx
	q := newMsg('Q')
	q.str(sql)
	if err := c.send(q.done()); err != nil {
		return c.cut(ctx, err)
	}
	var first *Error
	tag, tagged := "", false
	for {
		typ, body, err := c.r.next()
		if err != nil {
			return c.lost(ctx, first, err)
		}
		switch typ {
		case 'E':
			if first == nil {
				first = parseError(body)
			}
		case 'C':
			if !tagged {
				tag, tagged = (&fields{b: body}).str(), true
			}
		case 'Z':
			tx, err := readyStatus(body)
			if err != nil {
				return c.cut(ctx, err)
			}
			c.tx = tx
			switch {
			case first != nil:
				return first
			case rolledBack(started, tag, sql):
				return ErrRolledBack
			}
			return nil
		case 'A':
			c.notified(body)
		case 'S':
			if err := c.param(body); err != nil {
				return c.cut(ctx, err)
			}
		case 'T', 'D', 'I', 'N':
		default:
			return c.cut(ctx, unexpected(typ))
		}
	}
}

// Query runs one statement through the extended protocol, with args as $1, $2 and on, and reads every row
func (c *Conn) Query(ctx context.Context, sql string, args ...any) (*Result, error) {
	res, err := c.Batch(ctx, Statement{SQL: sql, Args: args})
	var be *BatchError
	if errors.As(err, &be) {
		return nil, be.Err
	}
	if err != nil {
		return nil, err
	}
	return res[0], nil
}

// Exec runs one statement and answers the rows it changed
func (c *Conn) Exec(ctx context.Context, sql string, args ...any) (int, error) {
	res, err := c.Query(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	return res.Affected(), nil
}

// Tx runs work inside a transaction. it commits when work succeeds, and rolls back when work fails or panics, or when
// a statement in it failed and work went on. work that commits or rolls back itself is an error. it refuses to begin
// inside an open transaction, so an inner Tx can't commit an outer one.
// a COMMIT that went out and got no answer is ErrCommitUnknown: the work may have been applied
func (c *Conn) Tx(ctx context.Context, work func() error) error {
	if c.broken != nil {
		return c.broken
	}
	if c.tx != 'I' {
		return errors.New("pg: a transaction is open already, so Tx can't begin one")
	}
	if err := c.Script(ctx, "BEGIN"); err != nil {
		return err
	}
	// work that panics never sets ended, so its transaction rolls back as the panic goes on
	ended := false
	defer func() {
		if !ended {
			_ = c.rollback(ctx)
		}
	}()
	err := work()
	ended = true
	switch {
	case err != nil:
	case c.broken != nil:
		return c.broken
	case c.tx == 'E':
		err = ErrRolledBack
	case c.tx == 'I':
		return errWorkEnded
	default:
		err = c.Script(ctx, "COMMIT")
		switch {
		case err == nil:
			return nil
		case c.broken != nil:
			// the session was good before, so the COMMIT went out, or may have
			return &commitError{err}
		case c.tx == 'I':
			// the server answered the COMMIT with an error, which ended the transaction
			return err
		}
	}
	if rerr := c.rollback(ctx); rerr != nil && c.broken == nil {
		return errors.Join(err, rerr)
	}
	return err
}

// rollback ends the open transaction even when ctx has, so the session goes back to idle
func (c *Conn) rollback(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return c.Script(ctx, "ROLLBACK")
}

// Wait answers the next notification on a channel the session listens to, oldest first, waiting for one until ctx
// ends. a wait that ends before any message starts leaves the session good. a wait is ended through its ctx, not by
// Close from another goroutine
func (c *Conn) Wait(ctx context.Context) (Notification, error) {
	if len(c.pending) > 0 {
		n := c.pending[0]
		c.pending = c.pending[1:]
		return n, nil
	}
	if c.broken != nil {
		return Notification{}, c.broken
	}
	if err := ctx.Err(); err != nil {
		return Notification{}, own(err)
	}
	defer c.watch(ctx)()
	for {
		if _, err := c.r.r.Peek(1); err != nil {
			var ne net.Error
			if ctx.Err() != nil && errors.As(err, &ne) && ne.Timeout() {
				return Notification{}, own(ctx.Err())
			}
			return Notification{}, c.cut(ctx, err)
		}
		typ, body, err := c.r.next()
		if err != nil {
			return Notification{}, c.cut(ctx, err)
		}
		switch typ {
		case 'A':
			c.notified(body)
			if len(c.pending) > 0 {
				n := c.pending[0]
				c.pending = c.pending[1:]
				return n, nil
			}
		case 'S':
			if err := c.param(body); err != nil {
				return Notification{}, c.cut(ctx, err)
			}
		case 'N':
		case 'E':
			return Notification{}, c.cut(ctx, parseError(body))
		default:
			return Notification{}, c.cut(ctx, fmt.Errorf("pg: an unexpected %q message while waiting", typ))
		}
	}
}
