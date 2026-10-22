package pg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// the session's TimeZone is UTC, so every time is written and read in it
const timeLayout = "2006-01-02 15:04:05.999999Z07:00"

// encode writes one argument as postgres text; nil is NULL. a nil pointer is NULL and any other is what it points at
func encode(v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case []byte:
		if v == nil {
			return nil, nil
		}
		return append([]byte(`\x`), hex.EncodeToString(v)...), nil
	case time.Time:
		return []byte(v.UTC().Format(timeLayout)), nil
	case []string:
		return textArray(v), nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return nil, nil
		}
		return encode(rv.Elem().Interface())
	case reflect.String:
		return []byte(rv.String()), nil
	case reflect.Bool:
		if rv.Bool() {
			return []byte("t"), nil
		}
		return []byte("f"), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.AppendInt(nil, rv.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.AppendUint(nil, rv.Uint(), 10), nil
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.New("a float that isn't finite can't be sent")
		}
		return strconv.AppendFloat(nil, f, 'g', -1, rv.Type().Bits()), nil
	}
	return nil, fmt.Errorf("a %T can't be sent", v)
}

// textArray writes a one-dimensional text[] literal, every element quoted
func textArray(vs []string) []byte {
	b := []byte{'{'}
	for i, v := range vs {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '"')
		for _, c := range []byte(v) {
			if c == '"' || c == '\\' {
				b = append(b, '\\')
			}
			b = append(b, c)
		}
		b = append(b, '"')
	}
	return append(b, '}')
}

// Row is one row's values as the server wrote them, as text; nil is NULL
type Row [][]byte

// Scan reads the row into one destination per value: a pointer to a string, []byte, bool, int or uint of any size,
// float32, float64, time.Time or []string. a pointer to a pointer of one of those takes NULL as nil; NULL into
// anything else is an error. a []byte is for bytea, which the session writes in hex. columns count from 1, as
// arguments do
func (r Row) Scan(dsts ...any) error {
	if len(dsts) != len(r) {
		return fmt.Errorf("pg: %d values into %d destinations", len(r), len(dsts))
	}
	for i, d := range dsts {
		if err := scan(r[i], d); err != nil {
			return fmt.Errorf("pg: column %d: %w", i+1, err)
		}
	}
	return nil
}

func scan(v []byte, dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("a destination isn't a pointer")
	}
	e := rv.Elem()
	if e.Kind() == reflect.Pointer {
		if v == nil {
			e.Set(reflect.Zero(e.Type()))
			return nil
		}
		p := reflect.New(e.Type().Elem())
		if err := scan(v, p.Interface()); err != nil {
			return err
		}
		e.Set(p)
		return nil
	}
	if v == nil {
		return errors.New("NULL into a value that can't hold it")
	}
	switch d := dst.(type) {
	case *[]byte:
		s, ok := strings.CutPrefix(string(v), `\x`)
		if !ok {
			return errors.New("bytea isn't in hex form")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return err
		}
		*d = b
		return nil
	case *time.Time:
		t, err := parseTime(string(v))
		if err != nil {
			return err
		}
		*d = t
		return nil
	case *[]string:
		a, err := parseTextArray(string(v))
		if err != nil {
			return err
		}
		*d = a
		return nil
	}
	s := string(v)
	switch e.Kind() {
	case reflect.String:
		e.SetString(s)
	case reflect.Bool:
		switch s {
		case "t":
			e.SetBool(true)
		case "f":
			e.SetBool(false)
		default:
			return fmt.Errorf("%q isn't a boolean", s)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, e.Type().Bits())
		if err != nil {
			return err
		}
		e.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(s, 10, e.Type().Bits())
		if err != nil {
			return err
		}
		e.SetUint(n)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(s, e.Type().Bits())
		if err != nil {
			return err
		}
		e.SetFloat(f)
	default:
		return fmt.Errorf("a %s can't be read into", e.Type())
	}
	return nil
}

// parseTime reads a timestamp with or without its zone, or a date; one without a zone is utc, the session's zone
func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999Z07", "2006-01-02 15:04:05.999999999", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q isn't a time postgres writes", s)
}

// parseTextArray reads a one-dimensional text[] literal; a NULL element is an error, since []string can't hold it
func parseTextArray(s string) ([]string, error) {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' || strings.HasPrefix(s, "{{") {
		return nil, fmt.Errorf("%q isn't a one-dimensional array", s)
	}
	inner := s[1 : len(s)-1]
	out := []string{}
	for i := 0; i < len(inner); {
		var el strings.Builder
		if inner[i] == '"' {
			i++
			for ; i < len(inner) && inner[i] != '"'; i++ {
				if inner[i] == '\\' && i+1 < len(inner) {
					i++
				}
				el.WriteByte(inner[i])
			}
			if i >= len(inner) {
				return nil, fmt.Errorf("%q has an unclosed quote", s)
			}
			i++
		} else {
			j := strings.IndexByte(inner[i:], ',')
			if j < 0 {
				j = len(inner) - i
			}
			raw := inner[i : i+j]
			if raw == "NULL" {
				return nil, errors.New("a NULL array element can't be read into []string")
			}
			el.WriteString(raw)
			i += j
		}
		out = append(out, el.String())
		if i < len(inner) {
			if inner[i] != ',' {
				return nil, fmt.Errorf("%q has a stray character", s)
			}
			i++
		}
	}
	return out, nil
}
