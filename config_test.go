package pg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haydencooper/pg/internal/testcerts"
)

func TestAURLGivesItsHostPortUserPasswordAndDatabase(t *testing.T) {
	c, err := ParseURL("postgres://app_writer:s3cret@127.0.0.1:5433/stats?application_name=app")
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "127.0.0.1" || c.Port != 5433 || c.User != "app_writer" || c.Password != "s3cret" || c.Database != "stats" || c.AppName != "app" {
		t.Errorf("%+v", c)
	}
	if n, a := c.address(); n != "tcp" || a != "127.0.0.1:5433" {
		t.Errorf("%s %s", n, a)
	}
}

func TestAHostThatIsADirectoryIsTheServersUnixSocket(t *testing.T) {
	c, err := ParseURL("postgres://app_writer@/stats?host=/var/run/postgresql")
	if err != nil {
		t.Fatal(err)
	}
	if n, a := c.address(); n != "unix" || a != "/var/run/postgresql/.s.PGSQL.5432" {
		t.Errorf("%s %s", n, a)
	}
}

func TestTheDatabaseDefaultsToTheUser(t *testing.T) {
	c, err := ParseURL("postgresql://app@localhost")
	if err != nil || c.Database != "app" || c.Port != 5432 {
		t.Errorf("%+v %v", c, err)
	}
}

// a password with an unescaped ? or # spills into the query or fragment, so no part of a url is ever repeated
func TestAURLThatCantBeUsedIsRefusedWithoutShowingIt(t *testing.T) {
	for _, u := range []string{
		"mysql://app:hunter2@localhost/db",
		"postgres://app:hunter2@localhost/db?sslmode=require",
		"postgres://app:hunter2@localhost/db?sslmode=hunter2",
		"postgres://app:hunter2@localhost/db?connect_timeout=5",
		"postgres://app@localhost/db?hunter2",
		"postgres://app:12?34hunter2@localhost/db",
		"postgres://app:?hunter2@localhost/db",
		"postgres://app:12#hunter2@localhost/db",
		"postgres://app:hunter2@localhost:99999/db",
		"postgres://:hunter2@localhost/db",
		"postgres://app:hunter2@local host/db",
		"postgres://app:hun%00ter2@localhost/db",
		"postgres://ir%00is@localhost/db",
		"postgres://app@localhost/d%00b",
		"postgres://app@localhost/db?application_name=x%00options%00-c%20search_path%3Devil",
	} {
		_, err := ParseURL(u)
		if err == nil {
			t.Errorf("%s parsed", u)
			continue
		}
		if strings.Contains(err.Error(), "hun") || strings.Contains(err.Error(), "ter2") {
			t.Errorf("the error shows part of the url: %v", err)
		}
	}
	if _, err := ParseURL("postgres://app:pw@localhost/db?sslmode=disable"); err != nil {
		t.Errorf("sslmode=disable: %v", err)
	}
}

var withPassword = Config{Host: "127.0.0.1", Port: 5433, User: "app_writer", Password: "hunter2", Database: "stats"}

func hidesThePassword(t *testing.T, shown []string) {
	t.Helper()
	for _, s := range shown {
		if strings.Contains(s, "hunter2") || !strings.Contains(s, "app_writer") {
			t.Errorf("%q", strings.ReplaceAll(s, "hunter2", "…"))
		}
	}
}

// every verb prints the config the same way, so none can reach the password
func TestAConfigPrintsWithoutItsPassword(t *testing.T) {
	c := withPassword
	shown := []string{c.String(), fmt.Sprint(c), fmt.Sprint(&c)}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%10.3v"} {
		shown = append(shown, fmt.Sprintf(verb, c), fmt.Sprintf(verb, &c))
	}
	hidesThePassword(t, shown)
}

func TestAConfigMarshalsAndLogsWithoutItsPassword(t *testing.T) {
	c := withPassword
	j, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("connect", "cfg", c)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("connect", "cfg", c)
	hidesThePassword(t, []string{string(j), text.String(), js.String()})
}

func TestTheURLsTLSSettings(t *testing.T) {
	dir := t.TempDir()
	set, err := testcerts.New("localhost")
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Write(dir); err != nil {
		t.Fatal(err)
	}
	ca := filepath.ToSlash(filepath.Join(dir, "ca.crt"))
	cases := []struct {
		url  string
		mode TLSMode
		bad  string
	}{
		{url: "postgres://u@db.example/d", mode: TLSVerifyFull},
		{url: "postgres://u@/d?host=/var/run/postgresql", mode: TLSOff},
		{url: "postgres://u@db.example/d?sslmode=disable", mode: TLSOff},
		{url: "postgres://u@db.example/d?sslmode=verify-full&sslrootcert=" + ca, mode: TLSVerifyFull},
		{url: "postgres://u@db.example/d?sslmode=require", bad: "sslmode must be disable or verify-full"},
		{url: "postgres://u@db.example/d?sslmode=prefer", bad: "sslmode must be disable or verify-full"},
		{url: "postgres://u@db.example/d?sslmode=disable&sslrootcert=" + ca, bad: "means nothing with sslmode=disable"},
		{url: "postgres://u@db.example/d?sslmode=disable&sslmode=verify-full", bad: "sslmode twice"},
		{url: "postgres://u@db.example/d?application_name=a&application_name=b", bad: "application_name twice"},
		{url: "postgres://u@/d?host=/var/run/postgresql&sslmode=verify-full", bad: "unix socket"},
		{url: "postgres://u@db.example/d?sslrootcert=" + filepath.ToSlash(filepath.Join(dir, "missing.crt")), bad: "can't be read"},
		{url: "postgres://u@db.example/d?sslrootcert=" + filepath.ToSlash(filepath.Join(dir, "server.key")), bad: "holds no certificate"},
	}
	for _, c := range cases {
		cfg, err := ParseURL(c.url)
		if c.bad != "" {
			if err == nil || !strings.Contains(err.Error(), c.bad) {
				t.Errorf("%s: got %v, want an error about %q", c.url, err, c.bad)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.url, err)
			continue
		}
		if cfg.mode() != c.mode {
			t.Errorf("%s: mode %v, want %v", c.url, cfg.mode(), c.mode)
		}
	}
	cfg, _ := ParseURL("postgres://u@db.example/d?sslmode=verify-full&sslrootcert=" + ca)
	if cfg.RootCAs == nil {
		t.Error("sslrootcert set no roots")
	}
}
