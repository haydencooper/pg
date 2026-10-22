package pg

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// PG_TEST_URL is a scram user on a throwaway database, PG_TEST_MD5_URL an md5 user on the same one;
// scripts/pg-test.sh makes both. never point them at a shared database
func testConn(t *testing.T, env string) *Conn {
	t.Helper()
	u := os.Getenv(env)
	if u == "" {
		t.Skipf("%s is not set", env)
	}
	cfg, err := ParseURL(u)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestIntegrationScramAndMd5UsersConnect(t *testing.T) {
	for _, env := range []string{"PG_TEST_URL", "PG_TEST_MD5_URL"} {
		c := testConn(t, env)
		res, err := c.Query(context.Background(), "SELECT current_user, current_setting('TimeZone')")
		if err != nil || len(res.Rows) != 1 {
			t.Fatalf("%s: %v", env, err)
		}
		var user, zone string
		if err := res.Rows[0].Scan(&user, &zone); err != nil || zone != "UTC" {
			t.Errorf("%s: %s %s %v", env, user, zone, err)
		}
	}
}

func TestIntegrationValuesRoundTrip(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, `CREATE TEMP TABLE v (t text, n bigint, f double precision, b boolean, raw bytea,
		at timestamptz, names text[], missing text)`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 6, 15, 55, 123456000, time.UTC)
	n, err := c.Exec(ctx, "INSERT INTO v VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		"de_anubis 'quoted'", int64(76561198000000000), 1.296921, true, []byte{0, 0xff}, at, []string{"AK-47", `a "b"`}, nil)
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	res, err := c.Query(ctx, "SELECT t, n, f, b, raw, at, names, missing FROM v")
	if err != nil {
		t.Fatal(err)
	}
	var (
		s       string
		big     int64
		f       float64
		b       bool
		raw     []byte
		got     time.Time
		names   []string
		missing *string
	)
	if err := res.Rows[0].Scan(&s, &big, &f, &b, &raw, &got, &names, &missing); err != nil {
		t.Fatal(err)
	}
	if s != "de_anubis 'quoted'" || big != 76561198000000000 || f != 1.296921 || !b || len(raw) != 2 || raw[1] != 0xff ||
		!got.Equal(at) || len(names) != 2 || names[1] != `a "b"` || missing != nil {
		t.Errorf("%q %d %v %v %x %v %q %v", s, big, f, b, raw, got, names, missing)
	}
}

func TestIntegrationAUniqueViolationNamesItsSqlstate(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "CREATE TEMP TABLE u (id int PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "INSERT INTO u VALUES ($1)", 1); err != nil {
		t.Fatal(err)
	}
	_, err := c.Exec(ctx, "INSERT INTO u VALUES ($1)", 1)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != "23505" {
		t.Fatalf("%v", err)
	}
	if _, err := c.Exec(ctx, "INSERT INTO u VALUES ($1)", 2); err != nil {
		t.Errorf("after the error: %v", err)
	}
}

func TestIntegrationAFailedTransactionLeavesNothing(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "CREATE TEMP TABLE r (id int)"); err != nil {
		t.Fatal(err)
	}
	err := c.Tx(ctx, func() error {
		if _, err := c.Exec(ctx, "INSERT INTO r VALUES (1)"); err != nil {
			return err
		}
		_, err := c.Exec(ctx, "INSERT INTO r VALUES ('not a number')")
		return err
	})
	if err == nil {
		t.Fatal("the transaction committed")
	}
	res, err := c.Query(ctx, "SELECT count(*) FROM r")
	var n int
	if err != nil || res.Rows[0].Scan(&n) != nil || n != 0 || c.TxStatus() != 'I' {
		t.Errorf("%d rows, status %c, %v", n, c.TxStatus(), err)
	}
}

func TestIntegrationListenHearsNotify(t *testing.T) {
	listener, sender := testConn(t, "PG_TEST_URL"), testConn(t, "PG_TEST_MD5_URL")
	ctx := context.Background()
	if err := listener.Script(ctx, "LISTEN app_test"); err != nil {
		t.Fatal(err)
	}
	quiet, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := listener.Wait(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a quiet wait: %v", err)
	}
	if _, err := sender.Exec(ctx, "SELECT pg_notify('app_test', $1)", "job 7"); err != nil {
		t.Fatal(err)
	}
	soon, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	n, err := listener.Wait(soon)
	if err != nil || n.Channel != "app_test" || n.Payload != "job 7" {
		t.Fatalf("%+v %v", n, err)
	}
}

func TestIntegrationAScriptRunsManyStatements(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "CREATE TEMP TABLE s (id int); INSERT INTO s VALUES (1), (2); INSERT INTO s VALUES (3);"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Query(ctx, "SELECT count(*) FROM s")
	var n int
	if err != nil || res.Rows[0].Scan(&n) != nil || n != 3 {
		t.Errorf("%d %v", n, err)
	}
}

// postgres answers COMMIT in a failed transaction with a ROLLBACK tag and no error, so both ways of committing say so
func TestIntegrationACommitInAFailedTransactionIsAnError(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "CREATE TEMP TABLE f (id int PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if err := c.Script(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if err := c.Script(ctx, "SELECT 1/0"); err == nil {
		t.Fatal("1/0 ran")
	}
	if err := c.Script(ctx, "COMMIT"); err == nil || !strings.Contains(err.Error(), "rolled back") || c.TxStatus() != 'I' {
		t.Fatalf("a commit after a failure: %v, status %c", err, c.TxStatus())
	}
	err := c.Tx(ctx, func() error {
		if _, err := c.Exec(ctx, "INSERT INTO f VALUES (1)"); err != nil {
			return err
		}
		_, err := c.Exec(ctx, "INSERT INTO f VALUES (1)")
		var pe *Error
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil
		}
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("work that swallowed a unique violation: %v", err)
	}
	res, err := c.Query(ctx, "SELECT count(*) FROM f")
	var n int
	if err != nil || res.Rows[0].Scan(&n) != nil || n != 0 || c.TxStatus() != 'I' {
		t.Errorf("%d rows, status %c, %v", n, c.TxStatus(), err)
	}
}

// in a failed transaction a COMMIT, END or PREPARE TRANSACTION answers ROLLBACK, and only a ROLLBACK or ABORT asked
// for passes, whatever else the sql names
func TestIntegrationARollbackTagPassesOnlyWhenAskedFor(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "CREATE TEMP TABLE audit (abort_reason text)"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sql    string
		query  bool
		fails  bool
		status byte
	}{
		{"COMMIT; INSERT INTO audit (abort_reason) VALUES ('x')", false, true, 'I'},
		{"PREPARE TRANSACTION 'abort-42'", true, true, 'I'},
		{"/* rollback */ END", false, true, 'I'},
		{"ROLLBACK TO SAVEPOINT s", false, false, 'T'},
		{"-- undo it\nabort", true, false, 'I'},
	} {
		if err := c.Script(ctx, "BEGIN; SAVEPOINT s; SELECT 1/0"); err == nil || c.TxStatus() != 'E' {
			t.Fatalf("into a failed transaction: %v, status %c", err, c.TxStatus())
		}
		var err error
		if tc.query {
			_, err = c.Exec(ctx, tc.sql)
		} else {
			err = c.Script(ctx, tc.sql)
		}
		if tc.fails && !errors.Is(err, ErrRolledBack) || !tc.fails && err != nil || c.TxStatus() != tc.status {
			t.Errorf("%q: %v, status %c", tc.sql, err, c.TxStatus())
		}
		if c.TxStatus() != 'I' {
			if err := c.Script(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
		}
	}
	err := c.Tx(ctx, func() error { return c.Script(ctx, "ROLLBACK") })
	if err == nil || !strings.Contains(err.Error(), "ended the transaction") || c.TxStatus() != 'I' {
		t.Errorf("work that rolled back itself: %v, status %c", err, c.TxStatus())
	}
}

// the test database's defaults are escape bytea, 0 extra float digits, SQL dates and perth time, so values that
// round trip show the session's own settings won
func TestIntegrationTheSessionSettingsBeatTheDatabasesDefaults(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	at := time.Date(2026, 10, 21, 6, 15, 55, 123456000, time.UTC)
	res, err := c.Query(context.Background(), "SELECT $1::float8, $2::bytea, $3::timestamptz", 0.30000000000000004, []byte{0, '\\', 0xff}, at)
	if err != nil {
		t.Fatal(err)
	}
	var (
		f   float64
		raw []byte
		got time.Time
	)
	if err := res.Rows[0].Scan(&f, &raw, &got); err != nil {
		t.Fatal(err)
	}
	if f != 0.30000000000000004 || string(raw) != "\x00\\\xff" || !got.Equal(at) {
		t.Errorf("%v %x %v", f, raw, got)
	}
}

func TestIntegrationSettingTheTimeZoneBreaksTheSession(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "SET TimeZone = 'Australia/Perth'"); err == nil || !strings.Contains(err.Error(), "TimeZone") {
		t.Fatalf("%v", err)
	}
	if _, err := c.Query(ctx, "SELECT 1"); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("after: %v", err)
	}
}
func TestIntegrationABatchsTenantLastsOnlyAsLongAsTheBatch(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	res, err := c.Batch(ctx,
		Statement{SQL: "SELECT set_config('app.tenant', $1, true)", Args: []any{"alpha"}},
		Statement{SQL: "SELECT current_setting('app.tenant')"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res[1].Rows[0][0]); got != "alpha" {
		t.Fatalf("the second statement saw tenant %q", got)
	}
	after, err := c.Query(ctx, "SELECT coalesce(current_setting('app.tenant', true), '')")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(after.Rows[0][0]); got != "" {
		t.Errorf("the tenant outlived its batch: %q", got)
	}
}

func TestIntegrationABatchAppliesWhollyOrNotAtAll(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	if err := c.Script(ctx, "CREATE TEMP TABLE batched (v int)"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Batch(ctx,
		Statement{SQL: "INSERT INTO batched VALUES (1)"},
		Statement{SQL: "INSERT INTO batched VALUES ($1::int)", Args: []any{"not a number"}})
	var be *BatchError
	if !errors.As(err, &be) || be.Index != 1 {
		t.Fatalf("got %v, not a failure of statement 1", err)
	}
	res, err := c.Query(ctx, "SELECT count(*) FROM batched")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Rows[0][0]); got != "0" {
		t.Errorf("the first statement stayed after the second failed: %s rows", got)
	}
}

func TestIntegrationABatchThatLeavesATransactionOpenIsRolledBack(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	_, err := c.Batch(ctx,
		Statement{SQL: "SELECT set_config('app.tenant', 'alpha', true)"},
		Statement{SQL: "BEGIN"},
		Statement{SQL: "SELECT 1"})
	if err == nil {
		t.Fatal("a batch that left a transaction open succeeded")
	}
	if c.TxStatus() != 'I' {
		t.Errorf("the session was left in transaction state %c", c.TxStatus())
	}
	res, qerr := c.Query(ctx, "SELECT coalesce(current_setting('app.tenant', true), '')")
	if qerr != nil {
		t.Fatal(qerr)
	}
	if got := string(res.Rows[0][0]); got != "" {
		t.Errorf("the tenant leaked: %q", got)
	}
}

func TestIntegrationABatchThatOpensATransactionAndFailsIsRolledBack(t *testing.T) {
	c := testConn(t, "PG_TEST_URL")
	ctx := context.Background()
	_, err := c.Batch(ctx,
		Statement{SQL: "SELECT set_config('app.tenant', 'alpha', true)"},
		Statement{SQL: "BEGIN"},
		Statement{SQL: "SELECT 1/0"})
	var be *BatchError
	if !errors.As(err, &be) {
		t.Fatalf("got %v, not a BatchError", err)
	}
	if c.TxStatus() != 'I' {
		t.Errorf("the session was left in transaction state %c", c.TxStatus())
	}
	res, qerr := c.Query(ctx, "SELECT coalesce(current_setting('app.tenant', true), '')")
	if qerr != nil {
		t.Fatal(qerr)
	}
	if got := string(res.Rows[0][0]); got != "" {
		t.Errorf("the tenant leaked: %q", got)
	}
}
func TestIntegrationATLSSessionIsEncrypted(t *testing.T) {
	c := testConn(t, "PG_TEST_TLS_URL")
	res, err := c.Query(context.Background(), "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Rows[0][0]); got != "t" {
		t.Errorf("the session isn't encrypted: ssl=%s", got)
	}
}

func TestIntegrationATLSSessionChecksTheHostItDialed(t *testing.T) {
	u := os.Getenv("PG_TEST_TLS_URL")
	if u == "" {
		t.Skip("PG_TEST_TLS_URL is not set")
	}
	cfg, err := ParseURL(u)
	if err != nil {
		t.Fatal(err)
	}
	// the certificate names localhost only
	cfg.Host = "127.0.0.1"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = Connect(ctx, cfg)
	var host x509.HostnameError
	if !errors.As(err, &host) {
		t.Fatalf("got %v, not a host name failure", err)
	}
}
