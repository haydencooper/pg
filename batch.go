package pg

import (
	"context"
	"errors"
	"fmt"
	"math"
)

// Statement is one statement of a batch, with its arguments as $1, $2 and on
type Statement struct {
	SQL  string
	Args []any
}

// BatchError is the statement of a batch that failed, counted from 0, and why
type BatchError struct {
	Index int
	Err   error
}

func (e *BatchError) Error() string {
	return fmt.Sprintf("pg: statement %d of the batch: %v", e.Index, e.Err)
}
func (e *BatchError) Unwrap() error { return e.Err }

// Batch sends every statement in one write and reads the answers in order, so a batch costs one round trip. outside
// a transaction postgres runs the batch as one of its own: every statement applies or none does, and a setting made
// with set_config(..., true) lasts until the batch ends. inside Tx the batch joins Tx's transaction. the first
// statement to fail is the answer, as a *BatchError
func (c *Conn) Batch(ctx context.Context, stmts ...Statement) ([]*Result, error) {
	if len(stmts) == 0 {
		return nil, nil
	}
	if c.broken != nil {
		return nil, c.broken
	}
	if err := ctx.Err(); err != nil {
		return nil, own(err)
	}
	var out []byte
	for i, st := range stmts {
		b, err := extended(st)
		if err != nil {
			return nil, &BatchError{Index: i, Err: err}
		}
		out = append(out, b...)
	}
	out = append(out, newMsg('S').done()...)
	defer c.watch(ctx)()
	started := c.tx
	if err := c.send(out); err != nil {
		return nil, c.cut(ctx, err)
	}
	results := make([]*Result, len(stmts))
	for i := range results {
		results[i] = &Result{}
	}
	at, failed := 0, -1
	var first *Error
	// current is the statement the server is answering; an answer past the last one is the server losing count
	current := func() (*Result, error) {
		if at >= len(results) {
			return nil, errors.New("pg: the server answered more statements than the batch sent")
		}
		return results[at], nil
	}
	for {
		typ, body, err := c.r.next()
		if err != nil {
			return nil, c.lost(ctx, first, err)
		}
		f := fields{b: body}
		switch typ {
		case '1', '2', 'n', 's', 'N':
		case 'S':
			if err := c.param(body); err != nil {
				return nil, c.cut(ctx, err)
			}
		case 'T':
			res, err := current()
			if err != nil {
				return nil, c.cut(ctx, err)
			}
			n := f.int16()
			if n < 0 {
				return nil, c.cut(ctx, errors.New("pg: a row description claims a negative number of columns"))
			}
			res.Columns = make([]string, 0, n)
			for i := 0; i < n && f.ok(); i++ {
				res.Columns = append(res.Columns, f.str())
				f.take(18)
			}
			if !f.ok() {
				return nil, c.cut(ctx, errors.New("pg: a row description runs short"))
			}
		case 'D':
			res, err := current()
			if err != nil {
				return nil, c.cut(ctx, err)
			}
			n := f.int16()
			if n < 0 {
				return nil, c.cut(ctx, errors.New("pg: a row claims a negative number of values"))
			}
			row := make(Row, 0, n)
			for i := 0; i < n && f.ok(); i++ {
				switch size := f.int32(); {
				case size == -1:
					row = append(row, nil)
				case size < -1:
					return nil, c.cut(ctx, errors.New("pg: a value claims a negative size"))
				default:
					row = append(row, append([]byte{}, f.take(size)...))
				}
			}
			if !f.ok() {
				return nil, c.cut(ctx, errors.New("pg: a row runs short"))
			}
			res.Rows = append(res.Rows, row)
		case 'C', 'I':
			res, err := current()
			if err != nil {
				return nil, c.cut(ctx, err)
			}
			if typ == 'C' {
				res.Tag = f.str()
			}
			at++
		case 'E':
			if first == nil {
				first, failed = parseError(body), at
			}
		case 'A':
			c.notified(body)
		case 'Z':
			tx, err := readyStatus(body)
			if err != nil {
				return nil, c.cut(ctx, err)
			}
			c.tx = tx
			if first != nil {
				return nil, &BatchError{Index: failed, Err: first}
			}
			for i, st := range stmts {
				if rolledBack(started, results[i].Tag, st.SQL) {
					return nil, ErrRolledBack
				}
			}
			return results, nil
		default:
			return nil, c.cut(ctx, unexpected(typ))
		}
	}
}

// extended is one statement's parse, bind, describe and execute, ready to send
func extended(st Statement) ([]byte, error) {
	if len(st.Args) > math.MaxUint16 {
		return nil, fmt.Errorf("pg: a statement takes at most %d arguments", math.MaxUint16)
	}
	params := make([][]byte, len(st.Args))
	for i, a := range st.Args {
		v, err := encode(a)
		if err != nil {
			return nil, fmt.Errorf("pg: argument %d: %w", i+1, err)
		}
		params[i] = v
	}
	parse := newMsg('P')
	parse.str("")
	parse.str(st.SQL)
	parse.int16(0)
	bind := newMsg('B')
	bind.str("")
	bind.str("")
	bind.int16(0)
	bind.int16(len(params))
	for _, p := range params {
		if p == nil {
			bind.int32(-1)
			continue
		}
		bind.int32(len(p))
		bind.bytes(p)
	}
	bind.int16(0)
	describe := newMsg('D')
	describe.bytes([]byte{'P'})
	describe.str("")
	execute := newMsg('E')
	execute.str("")
	execute.int32(0)
	var out []byte
	for _, m := range []*msg{parse, bind, describe, execute} {
		out = append(out, m.done()...)
	}
	return out, nil
}
