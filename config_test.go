package pg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestAURLGivesItsHostPortUserPasswordAndDatabase(t *testing.T) {
	c, err := ParseURL("postgres://iris_writer:s3cret@127.0.0.1:5433/stats?application_name=iris")
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "127.0.0.1" || c.Port != 5433 || c.User != "iris_writer" || c.Password != "s3cret" || c.Database != "stats" || c.AppName != "iris" {
		t.Errorf("%+v", c)
	}
	if n, a := c.address(); n != "tcp" || a != "127.0.0.1:5433" {
		t.Errorf("%s %s", n, a)
	}
}

func TestAHostThatIsADirectoryIsTheServersUnixSocket(t *testing.T) {
	c, err := ParseURL("postgres://iris_writer@/stats?host=/var/run/postgresql")
	if err != nil {
		t.Fatal(err)
	}
	if n, a := c.address(); n != "unix" || a != "/var/run/postgresql/.s.PGSQL.5432" {
		t.Errorf("%s %s", n, a)
	}
}

func TestTheDatabaseDefaultsToTheUser(t *testing.T) {
	c, err := ParseURL("postgresql://iris@localhost")
	if err != nil || c.Database != "iris" || c.Port != 5432 {
		t.Errorf("%+v %v", c, err)
	}
}

// a password with an unescaped ? or # spills into the query or fragment, so no part of a url is ever repeated
func TestAURLThatCantBeUsedIsRefusedWithoutShowingIt(t *testing.T) {
	for _, u := range []string{
		"mysql://iris:hunter2@localhost/db",
		"postgres://iris:hunter2@localhost/db?sslmode=require",
		"postgres://iris:hunter2@localhost/db?sslmode=hunter2",
		"postgres://iris:hunter2@localhost/db?connect_timeout=5",
		"postgres://iris@localhost/db?hunter2",
		"postgres://iris:12?34hunter2@localhost/db",
		"postgres://iris:?hunter2@localhost/db",
		"postgres://iris:12#hunter2@localhost/db",
		"postgres://iris:hunter2@localhost:99999/db",
		"postgres://:hunter2@localhost/db",
		"postgres://iris:hunter2@local host/db",
		"postgres://iris:hun%00ter2@localhost/db",
		"postgres://ir%00is@localhost/db",
		"postgres://iris@localhost/d%00b",
		"postgres://iris@localhost/db?application_name=x%00options%00-c%20search_path%3Devil",
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
	if _, err := ParseURL("postgres://iris:pw@localhost/db?sslmode=disable"); err != nil {
		t.Errorf("sslmode=disable: %v", err)
	}
}

var withPassword = Config{Host: "127.0.0.1", Port: 5433, User: "iris_writer", Password: "hunter2", Database: "stats"}

func hidesThePassword(t *testing.T, shown []string) {
	t.Helper()
	for _, s := range shown {
		if strings.Contains(s, "hunter2") || !strings.Contains(s, "iris_writer") {
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
