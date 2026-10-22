package pg

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func columnsMsg(names ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(names)))
	for _, n := range names {
		b = append(b, cstr(n)...)
		b = append(b, make([]byte, 18)...)
	}
	return backend('T', b)
}

func rowMsg(vals ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(vals)))
	for _, v := range vals {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	return backend('D', b)
}

// readBatch takes a batch of n statements: parse, bind, describe and execute for each, then one sync
func readBatch(s *fakeServer, n int) []byte {
	var types []byte
	for i := 0; i < 4*n+1; i++ {
		typ, _ := s.read(false)
		types = append(types, typ)
	}
	return types
}

func TestABatchIsOneWriteAnsweredInOrder(t *testing.T) {
	var seen []byte
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		seen = readBatch(s, 2)
		s.send(backend('1'), backend('2'), columnsMsg("tenant"), rowMsg("alpha"), backend('C', cstr("SELECT 1")),
			backend('1'), backend('2'), backend('n'), backend('C', cstr("INSERT 0 2")), ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Batch(context.Background(),
		Statement{SQL: "SELECT current_setting('app.tenant')"},
		Statement{SQL: "INSERT INTO t VALUES ($1), ($2)", Args: []any{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if string(seen) != "PBDEPBDES" {
		t.Errorf("the batch went out as %q, not parse, bind, describe and execute twice then one sync", seen)
	}
	if len(res) != 2 || len(res[0].Rows) != 1 || string(res[0].Rows[0][0]) != "alpha" || res[1].Affected() != 2 {
		t.Fatalf("the answers came back as %+v", res)
	}
}

func TestABatchFailureNamesTheStatementThatFailed(t *testing.T) {
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 3)
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("INSERT 0 1")),
			backend('1'), backend('2'), backend('E', cstr("SERROR"), cstr("C22P02"), cstr("Mbad input"), []byte{0}),
			ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Batch(context.Background(), Statement{SQL: "INSERT 1"}, Statement{SQL: "INSERT x"}, Statement{SQL: "SELECT 3"})
	var be *BatchError
	if !errors.As(err, &be) || be.Index != 1 {
		t.Fatalf("got %v, not a failure of statement 1", err)
	}
	var pe *Error
	if !errors.As(err, &pe) {
		t.Errorf("the server's error isn't reachable through the batch error: %v", err)
	}
	if !strings.Contains(err.Error(), "statement 1 of the batch") {
		t.Errorf("the message doesn't name the statement: %v", err)
	}
	if c.broken != nil {
		t.Errorf("a statement's failure broke the session: %v", c.broken)
	}
}

func TestAServerAnsweringMoreStatementsThanTheBatchSentBreaksTheSession(t *testing.T) {
	c, err := loopback(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 1)
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("SELECT 1")), backend('C', cstr("SELECT 1")),
			ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Batch(context.Background(), Statement{SQL: "SELECT 1"}); err == nil || !strings.Contains(err.Error(), "answered more statements") {
		t.Fatal("an answer to a statement never sent was taken")
	}
	if c.broken == nil {
		t.Error("the session went on after the server lost count")
	}
}

func TestAnArgumentThatCantBeSentNamesItsStatement(t *testing.T) {
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) { trustStartup(s) })
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Batch(context.Background(), Statement{SQL: "SELECT 1"}, Statement{SQL: "SELECT $1", Args: []any{struct{}{}}})
	var be *BatchError
	if !errors.As(err, &be) || be.Index != 1 || !strings.Contains(err.Error(), "argument 1") {
		t.Fatalf("got %v", err)
	}
}

func TestAnEmptyBatchSendsNothing(t *testing.T) {
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) { trustStartup(s) })
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Batch(context.Background())
	if err != nil || res != nil {
		t.Fatalf("an empty batch answered %v %v", res, err)
	}
}

func TestACommitTimeFailureIsBlamedOnTheLastStatement(t *testing.T) {
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 2)
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("INSERT 0 1")),
			backend('1'), backend('2'), backend('n'), backend('C', cstr("INSERT 0 1")),
			backend('E', cstr("SERROR"), cstr("C23503"), cstr("Mdeferred"), []byte{0}), ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Batch(context.Background(), Statement{SQL: "INSERT 1"}, Statement{SQL: "INSERT 2"})
	var be *BatchError
	if !errors.As(err, &be) || be.Index != 1 {
		t.Fatalf("got %v, not a failure of statement 1", err)
	}
}

func TestAReadyBeforeEveryStatementAnsweredBreaksTheSession(t *testing.T) {
	c, err := loopback(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 2)
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("SELECT 1")), ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Batch(context.Background(), Statement{SQL: "SELECT 1"}, Statement{SQL: "SELECT 2"})
	if err == nil || !strings.Contains(err.Error(), "fewer statements") || c.broken == nil {
		t.Fatalf("got %v, broken %v", err, c.broken)
	}
}

func TestAPortalSuspendedBreaksTheSession(t *testing.T) {
	c, err := loopback(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 1)
		s.send(backend('1'), backend('2'), backend('s'), ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Batch(context.Background(), Statement{SQL: "SELECT 1"}); err == nil || c.broken == nil {
		t.Fatalf("got %v, broken %v", err, c.broken)
	}
}

func TestABatchThatLeavesATransactionOpenIsRolledBack(t *testing.T) {
	var sql string
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 2)
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("SELECT 1")),
			backend('1'), backend('2'), backend('n'), backend('C', cstr("BEGIN")), ready('T'))
		sql = s.script()
		s.send(backend('C', cstr("ROLLBACK")), ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Batch(context.Background(), Statement{SQL: "SELECT 1"}, Statement{SQL: "BEGIN"})
	var be *BatchError
	if !errors.As(err, &be) || be.Index != 1 || !strings.Contains(err.Error(), "left a transaction open") {
		t.Fatalf("got %v", err)
	}
	if sql != "ROLLBACK" || c.TxStatus() != 'I' || c.broken != nil {
		t.Errorf("sent %q, status %c, broken %v", sql, c.TxStatus(), c.broken)
	}
}

func TestSettingsNoticesAndNotificationsDontUpsetTheAnswerCount(t *testing.T) {
	c, err := pipe(t, Config{User: "u"}, func(s *fakeServer) {
		trustStartup(s)
		readBatch(s, 2)
		s.send(backend('1'), backend('2'), backend('n'), backend('C', cstr("SELECT 1")),
			backend('S', cstr("application_name"), cstr("x")), backend('N', []byte{0}),
			backend('A', binary.BigEndian.AppendUint32(nil, 7), cstr("chan"), cstr("hi")),
			backend('1'), backend('2'), backend('n'), backend('C', cstr("SELECT 1")), ready('I'))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Batch(context.Background(), Statement{SQL: "SELECT 1"}, Statement{SQL: "SELECT 2"}); err != nil {
		t.Fatal(err)
	}
	n, err := c.Wait(context.Background())
	if err != nil || n.Channel != "chan" || n.Payload != "hi" {
		t.Errorf("notification %+v, %v", n, err)
	}
}
