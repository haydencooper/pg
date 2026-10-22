package pg

import (
	"fmt"
	"strings"
)

// Error is an error the server sent. Code is its sqlstate, such as 23505 for a unique violation
type Error struct {
	Severity   string
	Code       string
	Message    string
	Detail     string
	Hint       string
	Constraint string
}

func (e *Error) Error() string { return fmt.Sprintf("pg: %s %s: %s", e.Severity, e.Code, e.Message) }

// the non-localized severity (V) wins over the localized one (S)
func parseError(body []byte) *Error {
	e := &Error{}
	f := fields{b: body}
	for {
		code := f.u8()
		if code == 0 || !f.ok() {
			return e
		}
		v := f.str()
		switch code {
		case 'V':
			e.Severity = v
		case 'S':
			if e.Severity == "" {
				e.Severity = v
			}
		case 'C':
			e.Code = v
		case 'M':
			e.Message = v
		case 'D':
			e.Detail = v
		case 'H':
			e.Hint = v
		case 'n':
			e.Constraint = v
		}
	}
}

// wrapError puts what failed in front of err, with pg: once at the start, and keeps err for errors.Is and errors.As
type wrapError struct {
	what string
	err  error
}

func (e *wrapError) Error() string {
	msg := strings.TrimPrefix(e.err.Error(), "pg: ")
	if e.what == "" {
		return "pg: " + msg
	}
	return "pg: " + e.what + ": " + msg
}

func (e *wrapError) Unwrap() error { return e.err }

// thenError is a statement's error and what became of the session after it, on one line, and matches either
type thenError struct {
	first *Error
	then  error
}

func (e *thenError) Error() string { return e.first.Error() + "; " + e.then.Error() }

func (e *thenError) Unwrap() []error { return []error{e.first, e.then} }

// commitError is ErrCommitUnknown with the reason no answer came, and matches either
type commitError struct{ err error }

func (e *commitError) Error() string {
	return ErrCommitUnknown.Error() + ": " + strings.TrimPrefix(e.err.Error(), "pg: ")
}

func (e *commitError) Unwrap() []error { return []error{ErrCommitUnknown, e.err} }

// own makes err read as this package's, such as a ctx's error or a socket's
func own(err error) error {
	if strings.HasPrefix(err.Error(), "pg: ") {
		return err
	}
	return &wrapError{err: err}
}
