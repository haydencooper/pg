package pg

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeServer plays a postgres server's side of a connection from a script
type fakeServer struct {
	t  *testing.T
	nc net.Conn
	r  *bufio.Reader
}

func (s *fakeServer) send(b ...[]byte) {
	for _, m := range b {
		if _, err := s.nc.Write(m); err != nil {
			s.t.Errorf("server write: %v", err)
		}
	}
}

// read takes one frontend message, the startup one when first is set
func (s *fakeServer) read(first bool) (byte, []byte) {
	var typ byte
	if !first {
		b, err := s.r.ReadByte()
		if err != nil {
			s.t.Errorf("server read: %v", err)
			return 0, nil
		}
		typ = b
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(s.r, head); err != nil {
		s.t.Errorf("server read: %v", err)
		return 0, nil
	}
	n := binary.BigEndian.Uint32(head)
	if n < 4 {
		s.t.Errorf("server read: a %q message claims %d bytes", typ, n)
		return 0, nil
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(s.r, body); err != nil {
		s.t.Errorf("server read: %v", err)
		return 0, nil
	}
	return typ, body
}

// script takes one simple query and answers its sql
func (s *fakeServer) script() string {
	_, body := s.read(false)
	return strings.TrimSuffix(string(body), "\x00")
}

func ready(status byte) []byte { return backend('Z', []byte{status}) }

func authOK() []byte { return backend('R', []byte{0, 0, 0, 0}) }

// pipe connects a client to a scripted server that runs serve, and answers the client's connect error
func pipe(t *testing.T, cfg Config, serve func(*fakeServer)) (*Conn, error) {
	t.Helper()
	client, server := net.Pipe()
	return play(t, client, server, cfg, serve)
}

// loopback is pipe over tcp, where closing a closed socket is an error, as it is against a real server
func loopback(t *testing.T, cfg Config, serve func(*fakeServer)) (*Conn, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return play(t, client, server, cfg, serve)
}

func play(t *testing.T, client, server net.Conn, cfg Config, serve func(*fakeServer)) (*Conn, error) {
	t.Helper()
	s := &fakeServer{t: t, nc: server, r: bufio.NewReader(server)}
	// a server left waiting on a client that went quiet fails the test instead of hanging it
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		serve(s)
	}()
	t.Cleanup(func() {
		client.Close()
		<-done
	})
	return startup(context.Background(), client, cfg, nil)
}

// trustStartup reports the session settings as postgres does
func trustStartup(s *fakeServer) {
	s.read(true)
	s.send(authOK(), backend('S', cstr("server_version"), cstr("16.4")), backend('S', cstr("client_encoding"), cstr("UTF8")),
		backend('S', cstr("DateStyle"), cstr("ISO, MDY")), backend('S', cstr("TimeZone"), cstr("UTC")),
		backend('K', []byte{0, 0, 0, 9, 0, 0, 0, 1}), ready('I'))
}

func TestStartupSendsTheSessionSettingsAndTrustNeedsNoPassword(t *testing.T) {
	var startupBody []byte
	c, err := pipe(t, Config{User: "app", Database: "stats", AppName: "app"}, func(s *fakeServer) {
		_, startupBody = s.read(true)
		s.send(authOK(), backend('S', cstr("server_version"), cstr("16.4")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, want := range []string{"user\x00app\x00", "database\x00stats\x00", "application_name\x00app\x00", "TimeZone\x00UTC\x00",
		"client_encoding\x00UTF8\x00", "DateStyle\x00ISO, MDY\x00", "extra_float_digits\x003\x00", "bytea_output\x00hex\x00"} {
		if !strings.Contains(string(startupBody), want) {
			t.Errorf("startup lacks %q", want)
		}
	}
	if c.Param("server_version") != "16.4" {
		t.Errorf("server_version %q", c.Param("server_version"))
	}
}

func TestMd5AnswersWithTheSaltedHash(t *testing.T) {
	var answer []byte
	c, err := pipe(t, Config{User: "app", Password: "secret", Database: "stats"}, func(s *fakeServer) {
		s.read(true)
		s.send(backend('R', []byte{0, 0, 0, 5, 1, 2, 3, 4}))
		_, answer = s.read(false)
		s.send(authOK(), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if string(answer) != md5Password("app", "secret", []byte{1, 2, 3, 4})+"\x00" {
		t.Errorf("%q", answer)
	}
}

func TestACleartextPasswordRequestIsRefused(t *testing.T) {
	_, err := pipe(t, Config{User: "app", Password: "secret", Database: "stats"}, func(s *fakeServer) {
		s.read(true)
		s.send(backend('R', []byte{0, 0, 0, 3}))
	})
	if err == nil || !strings.Contains(err.Error(), "cleartext") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("%v", err)
	}
}

func TestAScramServerThatSkipsItsSignatureIsRefused(t *testing.T) {
	_, err := pipe(t, Config{User: "app", Password: "secret", Database: "stats"}, func(s *fakeServer) {
		s.read(true)
		s.send(backend('R', []byte{0, 0, 0, 10}, cstr("SCRAM-SHA-256"), []byte{0}))
		s.read(false)
		s.send(authOK())
	})
	if err == nil || !strings.Contains(err.Error(), "scram") {
		t.Fatalf("%v", err)
	}
}

func TestAStartupErrorIsTheServersError(t *testing.T) {
	_, err := pipe(t, Config{User: "app", Database: "nope"}, func(s *fakeServer) {
		s.read(true)
		s.send(backend('E', cstr("SFATAL"), cstr("C3D000"), cstr("Mdatabase \"nope\" does not exist"), []byte{0}))
	})
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != "3D000" {
		t.Fatalf("%v", err)
	}
}

func TestAQueryReturnsItsColumnsRowsAndTag(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		for i := 0; i < 5; i++ {
			s.read(false)
		}
		desc := []byte{0, 2}
		for _, name := range []string{"id", "name"} {
			desc = append(desc, cstr(name)...)
			desc = append(desc, make([]byte, 18)...)
		}
		row := []byte{0, 2, 0, 0, 0, 1, '7', 0xff, 0xff, 0xff, 0xff}
		s.send(backend('1'), backend('2'), backend('T', desc), backend('D', row), backend('C', cstr("SELECT 1")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Query(context.Background(), "SELECT id, name FROM t WHERE id = $1", 7)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Columns, ",") != "id,name" || len(res.Rows) != 1 || res.Tag != "SELECT 1" {
		t.Fatalf("%+v", res)
	}
	var id int
	var name *string
	if err := res.Rows[0].Scan(&id, &name); err != nil || id != 7 || name != nil {
		t.Errorf("%d %v %v", id, name, err)
	}
}

// an error ends the statement, but the server goes on to its sync, and the session stays good
func TestAQueryErrorLeavesTheSessionUsable(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		for i := 0; i < 5; i++ {
			s.read(false)
		}
		s.send(backend('E', cstr("SERROR"), cstr("C42P01"), cstr("Mrelation does not exist"), []byte{0}), ready('I'))
		for i := 0; i < 5; i++ {
			s.read(false)
		}
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("UPDATE 3")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var pe *Error
	if _, err := c.Query(context.Background(), "SELECT * FROM nope"); !errors.As(err, &pe) || pe.Code != "42P01" {
		t.Fatalf("%v", err)
	}
	n, err := c.Exec(context.Background(), "UPDATE t SET x = 1")
	if err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestANotificationDuringAQueryIsKeptForWait(t *testing.T) {
	note := append(append([]byte{0, 0, 0, 42}, cstr("app_jobs")...), cstr("7")...)
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.read(false)
		s.send(backend('A', note), backend('C', cstr("LISTEN")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Script(context.Background(), "LISTEN app_jobs"); err != nil {
		t.Fatal(err)
	}
	n, err := c.Wait(context.Background())
	if err != nil || n.Channel != "app_jobs" || n.Payload != "7" || n.PID != 42 {
		t.Fatalf("%+v %v", n, err)
	}
}

// a wait that times out before any message arrives leaves the session good for the next call
func TestAWaitThatTimesOutKeepsTheSession(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.read(false)
		s.send(backend('C', cstr("SELECT 1")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) || !strings.HasPrefix(err.Error(), "pg: ") {
		t.Fatalf("%v", err)
	}
	if err := c.Script(context.Background(), "SELECT 1"); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
}

// a wait whose ctx has ended already reads nothing, not even a notification that's arrived, and leaves the session good
func TestAWaitWhoseContextHasEndedLeavesTheSessionGood(t *testing.T) {
	note := append(append([]byte{0, 0, 0, 42}, cstr("app_jobs")...), cstr("7")...)
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		// one write, so the notification is in hand when the script returns
		s.send(append(append(backend('C', cstr("SELECT 1")), ready('I')...), backend('A', note)...))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Script(context.Background(), "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := c.Wait(ended); !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "pg: ") {
		t.Fatalf("%+v %v", n, err)
	}
	if n, err := c.Wait(context.Background()); err != nil || n.Channel != "app_jobs" || n.Payload != "7" {
		t.Fatalf("after: %+v %v", n, err)
	}
}

// a query cut off mid-answer leaves the session broken, and says so on every later call
func TestACancelledQueryBreaksTheSession(t *testing.T) {
	release := make(chan struct{})
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		for i := 0; i < 5; i++ {
			s.read(false)
		}
		s.send(backend('1'))
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Query(ctx, "SELECT pg_sleep(10)"); !errors.Is(err, context.DeadlineExceeded) || !strings.HasPrefix(err.Error(), "pg: ") {
		t.Fatalf("%v", err)
	}
	_, err = c.Query(context.Background(), "SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "broken") || strings.Count(err.Error(), "pg:") != 1 {
		t.Fatalf("after a cut: %v", err)
	}
	c.Close()
}

func TestATransactionRollsBackWhenItsWorkFails(t *testing.T) {
	var scripts []string
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("BEGIN")), ready('T'))
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("ROLLBACK")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	boom := errors.New("boom")
	if err := c.Tx(context.Background(), func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	if strings.Join(scripts, ";") != "BEGIN;ROLLBACK" {
		t.Errorf("%v", scripts)
	}
}

// postgres answers a COMMIT, END or PREPARE TRANSACTION in a failed transaction with a ROLLBACK tag and no error.
// every other statement there fails, so only a call that starts in a failed transaction gets the tag, from its first
// statement, and that statement's leading word says whether the rollback was asked for
func TestARollbackTagIsAnErrorUnlessTheCallAskedForIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		query  bool
		sql    string
		tags   []string
		status byte
		fails  bool
	}{
		{"a commit", false, "COMMIT", []string{"ROLLBACK"}, 'I', true},
		{"an end", true, "END", []string{"ROLLBACK"}, 'I', true},
		{"a commit and an insert naming abort", false, "COMMIT; INSERT INTO audit (abort_reason) VALUES ('x')", []string{"ROLLBACK", "INSERT 0 1"}, 'I', true},
		{"a prepared transaction named abort", true, "PREPARE TRANSACTION 'abort-42'", []string{"ROLLBACK"}, 'I', true},
		{"a commit behind a comment naming rollback", false, "/* rollback */ COMMIT", []string{"ROLLBACK"}, 'I', true},
		{"a rollback to a savepoint", false, "ROLLBACK TO SAVEPOINT s", []string{"ROLLBACK"}, 'T', false},
		{"a lowercase rollback", true, "rollback", []string{"ROLLBACK"}, 'I', false},
		{"an abort", false, "ABORT", []string{"ROLLBACK"}, 'I', false},
		{"a rollback behind comments", false, "-- undo it\n/* a /* nested */ comment */ ROLLBACK", []string{"ROLLBACK"}, 'I', false},
	} {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			s.script()
			s.send(backend('E', cstr("SERROR"), cstr("VERROR"), cstr("C22012"), cstr("Mdivision by zero"), []byte{0}), ready('E'))
			var answer []byte
			if tc.query {
				for i := 0; i < 5; i++ {
					s.read(false)
				}
				answer = append(append(backend('1'), backend('2')...), backend('n')...)
			} else {
				s.script()
			}
			for _, tag := range tc.tags {
				answer = append(answer, backend('C', cstr(tag))...)
			}
			s.send(append(answer, ready(tc.status)...))
			s.read(false)
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := c.Script(ctx, "BEGIN; SELECT 1/0"); err == nil || c.TxStatus() != 'E' {
			t.Fatalf("%s: into a failed transaction: %v, status %c", tc.name, err, c.TxStatus())
		}
		if tc.query {
			_, err = c.Exec(ctx, tc.sql)
		} else {
			err = c.Script(ctx, tc.sql)
		}
		if tc.fails && !errors.Is(err, ErrRolledBack) || !tc.fails && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		c.Close()
	}
}

// work that swallows a statement's error leaves the transaction failed, so Tx rolls it back and says so
func TestATransactionWhoseStatementFailedRollsBack(t *testing.T) {
	var scripts []string
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("BEGIN")), ready('T'))
		for i := 0; i < 5; i++ {
			s.read(false)
		}
		s.send(backend('E', cstr("SERROR"), cstr("C23505"), cstr("Mduplicate key value"), []byte{0}), ready('E'))
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("ROLLBACK")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	err = c.Tx(ctx, func() error {
		_, err := c.Exec(ctx, "INSERT INTO t VALUES (1)")
		var pe *Error
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil
		}
		return err
	})
	if !errors.Is(err, ErrRolledBack) {
		t.Errorf("%v", err)
	}
	if strings.Join(scripts, ";") != "BEGIN;ROLLBACK" || c.TxStatus() != 'I' {
		t.Errorf("%v, status %c", scripts, c.TxStatus())
	}
}

// work that ended the transaction itself leaves nothing to commit, so Tx sends nothing more and says so
func TestATransactionWhoseWorkEndedItIsAnError(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		answer func(*fakeServer)
		work   func(*Conn) error
	}{
		{"work that rolls back", func(s *fakeServer) {
			s.script()
			s.send(backend('C', cstr("ROLLBACK")), ready('I'))
		}, func(c *Conn) error { return c.Script(ctx, "ROLLBACK") }},
		{"work that commits", func(s *fakeServer) {
			s.script()
			s.send(backend('C', cstr("COMMIT")), ready('I'))
		}, func(c *Conn) error { return c.Script(ctx, "COMMIT") }},
		{"work that swallows its own commit's rollback", func(s *fakeServer) {
			for i := 0; i < 5; i++ {
				s.read(false)
			}
			s.send(backend('E', cstr("SERROR"), cstr("VERROR"), cstr("C23505"), cstr("Mduplicate key value"), []byte{0}), ready('E'))
			s.script()
			s.send(backend('C', cstr("ROLLBACK")), ready('I'))
		}, func(c *Conn) error {
			_, _ = c.Exec(ctx, "INSERT INTO t VALUES (1)")
			if err := c.Script(ctx, "COMMIT"); !errors.Is(err, ErrRolledBack) {
				return err
			}
			return nil
		}},
	} {
		next := make(chan byte, 1)
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			s.script()
			s.send(backend('C', cstr("BEGIN")), ready('T'))
			tc.answer(s)
			typ, _ := s.read(false)
			next <- typ
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Tx(ctx, func() error { return tc.work(c) }); err == nil || !strings.Contains(err.Error(), "ended the transaction") {
			t.Errorf("%s: %v", tc.name, err)
		}
		c.Close()
		if typ := <-next; typ != 'X' {
			t.Errorf("%s: Tx sent a %q message", tc.name, typ)
		}
	}
}

// a COMMIT that went out and got no answer may have been applied, so Tx can't call it a failure, and sends nothing
// after it
func TestACommitThatGotNoAnswerHasAnUnknownOutcome(t *testing.T) {
	var scripts []string
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("BEGIN")), ready('T'))
		scripts = append(scripts, s.script())
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = c.Tx(ctx, func() error { return nil })
	if !errors.Is(err, ErrCommitUnknown) || !errors.Is(err, io.EOF) || strings.Count(err.Error(), "pg:") != 1 {
		t.Errorf("a cut: %v", err)
	}
	if strings.Join(scripts, ";") != "BEGIN;COMMIT" {
		t.Errorf("%v", scripts)
	}
	if err := c.Script(ctx, "SELECT 1"); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("after: %v", err)
	}

	ended, cancel := context.WithCancel(ctx)
	defer cancel()
	c, err = pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		s.send(backend('C', cstr("BEGIN")), ready('T'))
		if sql := s.script(); sql != "COMMIT" {
			t.Errorf("%q", sql)
		}
		cancel()
		_, _ = io.Copy(io.Discard, s.r)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Tx(ended, func() error { return nil })
	if !errors.Is(err, ErrCommitUnknown) || !errors.Is(err, context.Canceled) || strings.Count(err.Error(), "pg:") != 1 {
		t.Errorf("a ctx that ended: %v", err)
	}
}

// a server that sends its reason and then hangs up, as postgres does when it shuts down, is answered with that reason
func TestAServerThatHangsUpAfterAnErrorIsAnsweredWithIt(t *testing.T) {
	fatal := backend('E', cstr("SFATAL"), cstr("VFATAL"), cstr("C57P01"), cstr("Mterminating connection due to administrator command"), []byte{0})
	for name, call := range map[string]struct {
		reads int
		run   func(*Conn) error
	}{
		"a script": {1, func(c *Conn) error { return c.Script(context.Background(), "SELECT 1") }},
		"a query": {5, func(c *Conn) error {
			_, err := c.Query(context.Background(), "SELECT 1")
			return err
		}},
	} {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			for i := 0; i < call.reads; i++ {
				s.read(false)
			}
			s.send(fatal)
		})
		if err != nil {
			t.Fatal(err)
		}
		var pe *Error
		if err := call.run(c); !errors.As(err, &pe) || pe.Code != "57P01" {
			t.Errorf("%s: %v", name, err)
		}
		err = call.run(c)
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), "broken") || strings.Count(err.Error(), "pg:") != 1 {
			t.Errorf("%s, after: %v", name, err)
		}
		c.Close()
	}
}

// a statement's own error and then a hang up are answered with both, so a caller that handles the error, as when a
// unique violation means the work is done already, still learns the session is gone
func TestAStatementErrorThenAHangUpIsAnsweredWithBoth(t *testing.T) {
	dup := backend('E', cstr("SERROR"), cstr("VERROR"), cstr("C23505"), cstr("Mduplicate key value"), []byte{0})
	for name, call := range map[string]struct {
		reads int
		run   func(*Conn) error
	}{
		"a script": {1, func(c *Conn) error { return c.Script(context.Background(), "INSERT INTO t VALUES (1)") }},
		"a query": {5, func(c *Conn) error {
			_, err := c.Query(context.Background(), "INSERT INTO t VALUES (1)")
			return err
		}},
	} {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			for i := 0; i < call.reads; i++ {
				s.read(false)
			}
			s.send(dup)
		})
		if err != nil {
			t.Fatal(err)
		}
		var pe *Error
		err = call.run(c)
		if !errors.As(err, &pe) || pe.Code != "23505" || !errors.Is(err, io.EOF) {
			t.Errorf("%s: %v", name, err)
		} else if msg := err.Error(); strings.Count(msg, "pg:") != 2 || strings.Contains(msg, "pg: pg:") || strings.Count(msg, "23505") != 1 ||
			strings.Count(msg, "closed the session") != 1 || strings.Contains(msg, "\n") {
			t.Errorf("%s: %q", name, msg)
		}
		if err := call.run(c); !errors.As(err, &pe) || !strings.Contains(err.Error(), "broken") {
			t.Errorf("%s, after: %v", name, err)
		}
		c.Close()
	}
}

// a ready message holds the transaction status alone, I, T or E. any other leaves the status unknown, so it refuses
// the connect, and breaks a session that's going
func TestAGarbledReadyStatusIsRefused(t *testing.T) {
	garbled := map[string][]byte{"no status": {}, "an unknown status": {'X'}, "two statuses": {'I', 'T'}}
	for name, body := range garbled {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			s.read(true)
			s.send(append(authOK(), backend('Z', body)...))
		})
		if err == nil || !strings.Contains(err.Error(), "ready") {
			t.Errorf("connecting, %s: %v", name, err)
		}
		if c != nil {
			c.Close()
		}
	}
	for name, body := range garbled {
		for what, call := range map[string]struct {
			reads int
			run   func(*Conn) error
		}{
			"a script": {1, func(c *Conn) error { return c.Script(context.Background(), "SELECT 1") }},
			"a query": {5, func(c *Conn) error {
				_, err := c.Query(context.Background(), "SELECT 1")
				return err
			}},
		} {
			c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
				trustStartup(s)
				for i := 0; i < call.reads; i++ {
					s.read(false)
				}
				s.send(append(backend('C', cstr("SELECT 1")), backend('Z', body)...))
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := call.run(c); err == nil || !strings.Contains(err.Error(), "ready") {
				t.Errorf("%s, %s: %v", what, name, err)
			}
			if err := call.run(c); err == nil || !strings.Contains(err.Error(), "broken") {
				t.Errorf("%s, %s, after: %v", what, name, err)
			}
			c.Close()
		}
	}
}

// a backend key is the pid and the secret, 4 bytes each, under the protocol version this client asks for
func TestABackendKeyThatIsntEightBytesRefusesTheConnect(t *testing.T) {
	for name, key := range map[string][]byte{"a short key": {0, 0, 0, 9}, "a long key": make([]byte, 12)} {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			s.read(true)
			s.send(append(append(authOK(), backend('K', key)...), ready('I')...))
		})
		if err == nil || !strings.Contains(err.Error(), "key") {
			t.Errorf("%s: %v", name, err)
		}
		if c != nil {
			c.Close()
		}
	}
}

func TestAnArgumentThatCantBeSentIsNamedByItsNumber(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Query(context.Background(), "SELECT $1, $2", 1, math.NaN())
	if err == nil || !strings.HasPrefix(err.Error(), "pg: argument 2: ") || strings.Count(err.Error(), "pg:") != 1 {
		t.Errorf("%v", err)
	}
}

func TestMoreArgumentsThanPostgresTakesAreRefused(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Query(context.Background(), "SELECT 1", make([]any, 65536)...); err == nil || !strings.Contains(err.Error(), "65535") {
		t.Errorf("%v", err)
	}
}

// a call whose ctx has already ended sends nothing, so an idle session stays good
func TestACallWhoseContextHasEndedLeavesTheSessionGood(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		s.send(backend('C', cstr("SELECT 1")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Script(ended, "SELECT 1"); !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "pg: ") {
		t.Errorf("a script: %v", err)
	}
	if _, err := c.Query(ended, "SELECT 1"); !errors.Is(err, context.Canceled) {
		t.Errorf("a query: %v", err)
	}
	if err := c.Tx(ended, func() error { t.Error("the work ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("a transaction: %v", err)
	}
	if err := c.Script(context.Background(), "SELECT 1"); err != nil {
		t.Fatalf("after: %v", err)
	}
}

// a ctx that ends during the work still rolls back, so Tx never leaves the session in a transaction
func TestATransactionRollsBackWhenItsContextEndsDuringTheWork(t *testing.T) {
	boom := errors.New("boom")
	for name, result := range map[string]error{"work that fails": boom, "work that succeeds": nil} {
		var scripts []string
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			scripts = append(scripts, s.script())
			s.send(backend('C', cstr("BEGIN")), ready('T'))
			scripts = append(scripts, s.script())
			s.send(backend('C', cstr("ROLLBACK")), ready('I'))
			s.read(false)
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		want := result
		if want == nil {
			want = context.Canceled
		}
		// a ctx that ended before the COMMIT went out is a failure for certain, not an unknown
		if err := c.Tx(ctx, func() error { cancel(); return result }); !errors.Is(err, want) || errors.Is(err, ErrCommitUnknown) {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Join(scripts, ";") != "BEGIN;ROLLBACK" || c.TxStatus() != 'I' {
			t.Errorf("%s: %v, status %c", name, scripts, c.TxStatus())
		}
		c.Close()
	}
}

func TestATransactionCantBeginInsideAnother(t *testing.T) {
	next := make(chan byte, 1)
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		s.send(backend('C', cstr("BEGIN")), ready('T'))
		typ, _ := s.read(false)
		next <- typ
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Script(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := c.Tx(ctx, func() error { ran = true; return nil }); err == nil || ran {
		t.Errorf("a nested transaction: %v, ran %v", err, ran)
	}
	c.Close()
	if typ := <-next; typ != 'X' {
		t.Errorf("Tx sent a %q message", typ)
	}
}

// a panic in the work rolls back, and the panic goes on
func TestAPanicInTheWorkRollsBackAndGoesOn(t *testing.T) {
	var scripts []string
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("BEGIN")), ready('T'))
		scripts = append(scripts, s.script())
		s.send(backend('C', cstr("ROLLBACK")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Errorf("recovered %v", p)
			}
		}()
		_ = c.Tx(context.Background(), func() error { panic("boom") })
	}()
	if strings.Join(scripts, ";") != "BEGIN;ROLLBACK" || c.TxStatus() != 'I' {
		t.Errorf("%v, status %c", scripts, c.TxStatus())
	}
}

func TestASettingReportedAfterStartupIsKept(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		s.send(backend('C', cstr("SET")), backend('S', cstr("application_name"), cstr("app serve")), ready('I'))
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Script(context.Background(), "SET application_name = 'app serve'"); err != nil {
		t.Fatal(err)
	}
	if got := c.Param("application_name"); got != "app serve" {
		t.Errorf("%q", got)
	}
}

var otherSettings = map[string]string{"client_encoding": "SQL_ASCII", "DateStyle": "SQL, DMY", "TimeZone": "Australia/Perth"}

// values are written and read under the session's settings, so a server that reports others is refused
func TestAServerReportingOtherSessionSettingsIsRefused(t *testing.T) {
	for k, v := range otherSettings {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			s.read(true)
			s.send(append(append(authOK(), backend('S', cstr(k), cstr(v))...), ready('I')...))
		})
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s %s: %v", k, v, err)
		}
		if c != nil {
			c.Close()
		}
	}
}

// a statement that changes a setting values are read under, as SET TimeZone does, breaks the session
func TestChangingASessionSettingBreaksTheSession(t *testing.T) {
	for k, v := range otherSettings {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			s.script()
			s.send(append(append(backend('C', cstr("SET")), backend('S', cstr(k), cstr(v))...), ready('I')...))
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := c.Script(ctx, "SET "+k+" = 'x'"); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s: %v", k, err)
		}
		if err := c.Script(ctx, "SELECT 1"); err == nil || !strings.Contains(err.Error(), "broken") {
			t.Errorf("%s, after: %v", k, err)
		}
		c.Close()
	}
}

// once scram has begun, a server can't switch to md5 to get a hash of the password instead
func TestAServerCantSwitchFromScramToMd5Partway(t *testing.T) {
	answered := make(chan bool, 1)
	_, err := pipe(t, Config{User: "app", Password: "secret", Database: "stats"}, func(s *fakeServer) {
		s.read(true)
		s.send(backend('R', []byte{0, 0, 0, 10}, cstr("SCRAM-SHA-256"), []byte{0}))
		s.read(false)
		s.send(backend('R', []byte{0, 0, 0, 5, 9, 9, 9, 9}))
		_, err := s.r.ReadByte()
		answered <- err == nil
	})
	if err == nil || !strings.Contains(err.Error(), "scram") {
		t.Errorf("%v", err)
	}
	if <-answered {
		t.Error("the client answered the md5 request")
	}
}

// a short authentication message is an error, not a zero that reads as ok
func TestAShortAuthenticationMessageIsRefused(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Password: "secret", Database: "stats"}, func(s *fakeServer) {
		s.read(true)
		s.send(append(backend('R', []byte{0}), ready('I')...))
	})
	if err == nil {
		c.Close()
		t.Fatal("a one-byte authentication message read as ok")
	}
}

// a nul would end a startup value early and the rest would read as another setting, so it's refused before dialing
func TestANulByteInAStartupValueIsRefused(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for _, cfg := range []Config{
		{User: "app\x00x", Database: "stats"},
		{User: "app", Database: "stats\x00x"},
		{User: "app", Password: "hunter2\x00x", Database: "stats"},
		{User: "app", Database: "stats", AppName: "app\x00options\x00-c search_path=evil"},
	} {
		cfg.Host, cfg.Port = "127.0.0.1", 5432
		_, err := Connect(ended, cfg)
		if err == nil || !strings.Contains(err.Error(), "nul") || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%v: %v", cfg, err)
		}
	}
}

func TestANegativeCountOrSizeInARowBreaksTheSession(t *testing.T) {
	for name, answer := range map[string][]byte{
		"a description of -1 columns": backend('T', []byte{0xff, 0xff}),
		"a row of -1 values":          backend('D', []byte{0xff, 0xff}),
		"a value of -2 bytes":         backend('D', []byte{0, 1, 0xff, 0xff, 0xff, 0xfe}),
	} {
		c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
			trustStartup(s)
			for i := 0; i < 5; i++ {
				s.read(false)
			}
			s.send(append(append(answer, backend('C', cstr("SELECT 1"))...), ready('I')...))
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Query(context.Background(), "SELECT 1"); err == nil || !strings.Contains(err.Error(), "negative") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := c.Query(context.Background(), "SELECT 1"); err == nil || !strings.Contains(err.Error(), "broken") {
			t.Errorf("%s, after: %v", name, err)
		}
		c.Close()
	}
}

func TestCopyIsRefusedAndBreaksTheSession(t *testing.T) {
	c, err := pipe(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		s.send(backend('G', []byte{0, 0, 0}))
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Script(ctx, "COPY t FROM STDIN"); err == nil || err.Error() != "pg: copy isn't supported" {
		t.Errorf("%v", err)
	}
	if err := c.Script(ctx, "SELECT 1"); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("after: %v", err)
	}
	c.Close()
}

// closing never fails on a session that's broken or closed already
func TestClosingABrokenOrClosedSessionIsQuiet(t *testing.T) {
	broken, err := loopback(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.script()
		s.send(backend('v'))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.Script(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("an unexpected message read as ok")
	}
	if err := broken.Close(); err != nil {
		t.Errorf("closing a broken session: %v", err)
	}
	if err := broken.Close(); err != nil {
		t.Errorf("closing it again: %v", err)
	}
	good, err := loopback(t, Config{User: "app", Database: "stats"}, func(s *fakeServer) {
		trustStartup(s)
		s.read(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := good.Close(); err != nil {
		t.Errorf("closing a good session: %v", err)
	}
	if err := good.Close(); err != nil {
		t.Errorf("closing it again: %v", err)
	}
	if err := good.Script(context.Background(), "SELECT 1"); err == nil {
		t.Error("a closed session ran a script")
	}
}
