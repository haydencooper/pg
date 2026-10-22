package pg

import (
	"math"
	"strings"
	"testing"
	"time"
)

type side string

func TestArgumentsAreSentAsPostgresText(t *testing.T) {
	s := "x"
	var none *string
	at := time.Date(2026, 10, 21, 14, 15, 55, 123456000, time.FixedZone("awst", 8*3600))
	cases := []struct {
		in   any
		want string
		null bool
	}{
		{"plain", "plain", false},
		{side("ct"), "ct", false},
		{42, "42", false},
		{int64(-7), "-7", false},
		{uint64(76561198000000000), "76561198000000000", false},
		{true, "t", false},
		{false, "f", false},
		{1.5, "1.5", false},
		{float32(0.1), "0.1", false},
		{[]byte{0xde, 0xad}, `\xdead`, false},
		{at, "2026-10-21 06:15:55.123456Z", false},
		{[]string{"AK-47", `say "hi"`, `back\slash`}, `{"AK-47","say \"hi\"","back\\slash"}`, false},
		{[]string{}, "{}", false},
		{&s, "x", false},
		{none, "", true},
		{nil, "", true},
	}
	for _, c := range cases {
		got, err := encode(c.in)
		if err != nil {
			t.Errorf("%T: %v", c.in, err)
			continue
		}
		if (got == nil) != c.null || string(got) != c.want {
			t.Errorf("%T %v: %q (null %v)", c.in, c.in, got, got == nil)
		}
	}
}

func TestAnArgumentPostgresCantHoldIsRefused(t *testing.T) {
	for _, v := range []any{math.NaN(), math.Inf(1), struct{}{}, map[string]int{}} {
		if _, err := encode(v); err == nil {
			t.Errorf("%T sent", v)
		}
	}
}

func TestARowScansIntoGoValues(t *testing.T) {
	row := Row{[]byte("app"), []byte("42"), []byte("t"), []byte("1.25"), []byte(`\xdead`),
		[]byte("2026-10-21 06:15:55.123456+00"), []byte(`{AK-47,"say \"hi\"",plain}`), nil, []byte("7")}
	var (
		name    string
		n       int64
		ok      bool
		f       float64
		b       []byte
		at      time.Time
		weapons []string
		missing *string
		present *int
	)
	if err := row.Scan(&name, &n, &ok, &f, &b, &at, &weapons, &missing, &present); err != nil {
		t.Fatal(err)
	}
	if name != "app" || n != 42 || !ok || f != 1.25 || string(b) != "\xde\xad" || missing != nil || present == nil || *present != 7 {
		t.Errorf("%q %d %v %v %x %v %v", name, n, ok, f, b, missing, present)
	}
	if !at.Equal(time.Date(2026, 10, 21, 6, 15, 55, 123456000, time.UTC)) {
		t.Errorf("time %v", at)
	}
	if len(weapons) != 3 || weapons[1] != `say "hi"` || weapons[2] != "plain" {
		t.Errorf("array %q", weapons)
	}
}

func TestNullIntoAValueThatCantHoldItIsAnError(t *testing.T) {
	var s string
	if err := (Row{nil}).Scan(&s); err == nil {
		t.Error("null into a string")
	}
	if err := (Row{[]byte("1"), []byte("2")}).Scan(&s); err == nil {
		t.Error("two values into one destination")
	}
	var small int8
	if err := (Row{[]byte("300")}).Scan(&small); err == nil {
		t.Error("300 into an int8")
	}
	// columns count from 1, as arguments do
	var n int
	if err := (Row{[]byte("1"), nil}).Scan(&n, &s); err == nil || !strings.Contains(err.Error(), "column 2") {
		t.Errorf("null into the second destination: %v", err)
	}
}

func TestTimesAndDatesInEveryFormPostgresWrites(t *testing.T) {
	for in, want := range map[string]time.Time{
		"2026-10-21 06:15:55+00":      time.Date(2026, 10, 21, 6, 15, 55, 0, time.UTC),
		"2026-10-21 06:15:55.5+05:30": time.Date(2026, 10, 21, 0, 45, 55, 500000000, time.UTC),
		"2026-10-21 06:15:55.000001":  time.Date(2026, 10, 21, 6, 15, 55, 1000, time.UTC),
		"2026-10-21":                  time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
	} {
		var got time.Time
		if err := (Row{[]byte(in)}).Scan(&got); err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
}
