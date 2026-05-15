// Package canon implements RFC 8785 JSON Canonicalization Scheme (JCS).
//
// The canonicalization is load-bearing: the assertion ID is sha256(canon-bytes),
// and the signature is over the same canon-bytes. Two writers observing the
// same fact must produce byte-identical canonical encodings. This package is
// implemented directly (no external dep) so the algorithm is auditable
// alongside the code that depends on it.
//
// RFC 8785 in summary:
//   - object keys sorted by their UTF-16 code-unit sequence
//   - no insignificant whitespace
//   - strings use the JSON string production with the minimal-escape rule
//     of RFC 8259 §7 (only the required escapes, lowercase \uXXXX for the
//     few cases that need them)
//   - numbers serialized per ECMAScript 6 §7.1.12.1 (we restrict to integers
//     and avoid floats in our schema; see CanonicalizeStrictInt)
//
// Because our assertion schema deliberately contains no floating-point
// numbers, we sidestep the JCS number serialization rules. If a float ever
// reaches this code, Canonicalize will return an error. This is intentional.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Canonicalize takes an arbitrary Go value (typically the result of
// json.Unmarshal into any) and returns its canonical JSON encoding.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeJSON parses raw JSON, then canonicalizes it. Convenience for
// the common case of "I already have JSON bytes; give me canonical bytes."
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after top-level JSON value")
	}
	return Canonicalize(v)
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeString(buf, x)
	case json.Number:
		return writeNumber(buf, string(x))
	case float64:
		// Should not happen if callers use UseNumber. We refuse rather than
		// silently produce a non-deterministic encoding.
		return fmt.Errorf("float64 not permitted in canonical encoding (got %v); use json.Number or integers", x)
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case []any:
		return writeArray(buf, x)
	case map[string]any:
		return writeObject(buf, x)
	default:
		// Try a marshal/unmarshal round-trip to normalise via json.Number.
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("canon: unsupported type %T: %w", v, err)
		}
		var rt any
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(&rt); err != nil {
			return fmt.Errorf("canon: round-trip failed for %T: %w", v, err)
		}
		return writeValue(buf, rt)
	}
	return nil
}

func writeArray(buf *bytes.Buffer, a []any) error {
	buf.WriteByte('[')
	for i, item := range a {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeValue(buf, item); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func writeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// JCS specifies UTF-16 code-unit order. Compare via UTF-16 units rather
	// than naive byte order; the two diverge for characters above U+FFFF
	// (surrogate pair handling) and a few BMP cases.
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeValue(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString implements JCS-compatible JSON string escaping: the JSON-string
// production where only the characters that *must* be escaped are escaped,
// using the shortest legal escape (lowercase \uXXXX where required).
func writeString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else if r > 0xFFFF {
				// Encode as surrogate pair, lowercase hex.
				units := utf16.Encode([]rune{r})
				for _, u := range units {
					fmt.Fprintf(buf, `\u%04x`, u)
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeNumber emits a JSON number. Our schema permits only integers and
// fixed-point string literals (e.g. timestamps as strings). If a non-integer
// JSON number arrives, we reject.
func writeNumber(buf *bytes.Buffer, s string) error {
	// json.Number is the literal as it appeared in the source. We require it
	// to parse as int64 to ensure determinism. Floats are rejected.
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return fmt.Errorf("canon: non-integer JSON number %q not permitted in this schema", s)
	}
	buf.WriteString(s)
	return nil
}
