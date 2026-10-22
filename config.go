package pg

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
)

// Config says where a database is and who connects to it
type Config struct {
	// Host is a host name or address, or the directory holding the server's unix socket
	Host     string
	Port     int
	User     string
	Password string `json:"-"`
	Database string
	// AppName shows in pg_stat_activity
	AppName string
	// TLS is the session's encryption; the zero value verifies over tcp and is off over a unix socket
	TLS TLSMode
	// RootCAs are the authorities a server's certificate must chain to; nil means the system's
	RootCAs *x509.CertPool `json:"-"`
}

// TLSMode is how a session is encrypted
type TLSMode int

const (
	// TLSDefault verifies the server over tcp and leaves a unix socket's session in the clear, since it never leaves
	// the box
	TLSDefault TLSMode = iota
	// TLSOff sends the session in the clear
	TLSOff
	// TLSVerifyFull speaks tls, checks the server's certificate chains to RootCAs and names Host, and binds scram to it
	TLSVerifyFull
)

func (m TLSMode) String() string {
	switch m {
	case TLSOff:
		return "off"
	case TLSVerifyFull:
		return "verify-full"
	}
	return "default"
}

// ParseURL reads postgres://user:password@host:port/database. the query may carry host (a socket directory),
// application_name, sslmode=disable or verify-full, and sslrootcert, a pem file of authorities. an error never
// repeats any part of the url: a password with an unescaped ? would spill into the query
func ParseURL(s string) (Config, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Config{}, errors.New("pg: the database url doesn't parse")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return Config{}, errors.New("pg: a database url starts postgres://")
	}
	c := Config{Host: u.Hostname(), Port: 5432, Database: strings.TrimPrefix(u.Path, "/")}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, errors.New("pg: the database url's port isn't a port")
		}
		c.Port = n
	}
	if u.User != nil {
		c.User = u.User.Username()
		c.Password, _ = u.User.Password()
	}
	q := u.Query()
	for k := range q {
		switch v := q.Get(k); k {
		case "host":
			c.Host = v
		case "application_name":
			c.AppName = v
		case "sslmode":
			switch v {
			case "disable":
				c.TLS = TLSOff
			case "verify-full":
				c.TLS = TLSVerifyFull
			default:
				return Config{}, errors.New("pg: the database url's sslmode must be disable or verify-full")
			}
		case "sslrootcert":
			b, err := os.ReadFile(v)
			if err != nil {
				return Config{}, errors.New("pg: the database url's sslrootcert can't be read")
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				return Config{}, errors.New("pg: the database url's sslrootcert holds no certificate")
			}
			c.RootCAs = pool
		default:
			return Config{}, errors.New("pg: the database url may set only host, application_name, sslmode and sslrootcert")
		}
	}
	if c.User == "" {
		return Config{}, errors.New("pg: the database url names no user")
	}
	if c.Host == "" {
		c.Host = "localhost"
	}
	if c.Database == "" {
		c.Database = c.User
	}
	if err := c.check(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// check refuses a nul in a startup value: it would end the value early, and the server would read the rest as more
// settings
func (c Config) check() error {
	if c.mode() == TLSVerifyFull && c.unix() {
		return errors.New("pg: tls over a unix socket isn't spoken; a socket's session needs sslmode=disable")
	}
	for _, v := range []string{c.User, c.Password, c.Database, c.AppName} {
		if strings.IndexByte(v, 0) >= 0 {
			return errors.New("pg: the user, password, database and application name can't hold a nul byte")
		}
	}
	return nil
}

// String shows the config with its password hidden, so a config can be logged or printed in a test failure
func (c Config) String() string {
	password := ""
	if c.Password != "" {
		password = " password=[hidden]"
	}
	return fmt.Sprintf("host=%s port=%d user=%s%s database=%s application_name=%s tls=%s", c.Host, c.Port, c.User,
		password, c.Database, c.AppName, c.mode())
}

// Format prints String for every verb and flag, since fmt would show the fields as they are for %d, and slog's text
// handler prints with %+v
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// unix is whether the host is the directory of a unix socket
func (c Config) unix() bool { return strings.HasPrefix(c.Host, "/") }

// mode is the session's tls once the default is settled
func (c Config) mode() TLSMode {
	if c.TLS != TLSDefault {
		return c.TLS
	}
	if c.unix() {
		return TLSOff
	}
	return TLSVerifyFull
}

// address is where to dial: a unix socket when the host is a directory
func (c Config) address() (network, addr string) {
	if c.unix() {
		return "unix", path.Join(c.Host, fmt.Sprintf(".s.PGSQL.%d", c.Port))
	}
	return "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}
