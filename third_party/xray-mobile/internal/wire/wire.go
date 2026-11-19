// Package wire is the line protocol between vless_core.exe and the Flutter
// plugin that drives it.
//
// Space-separated key=value pairs, one message per line, with every value
// percent-encoded so it can carry anything — including the Xray config and
// error messages with spaces or quotes in them.
//
// Deliberately not JSON: the other end is a Flutter Windows plugin, which has
// no JSON library available to it, and hand-rolling a parser there to read
// something this small is a worse trade than a format with nothing to get
// wrong.
package wire

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Fields is one message.
type Fields map[string]string

// Encode renders fields as a single line, without the newline. Keys are
// sorted so the output is deterministic and diffable in logs.
func Encode(f Fields) string {
	keys := make([]string, 0, len(f))
	for key := range f {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var out strings.Builder
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(escape(f[key]))
	}
	return out.String()
}

// Decode parses a line produced by [Encode].
func Decode(line string) (Fields, error) {
	fields := Fields{}
	for _, pair := range strings.Fields(line) {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("malformed pair %q", pair)
		}
		unescaped, err := unescape(value)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		fields[key] = unescaped
	}
	return fields, nil
}

// unreserved is RFC 3986's set, the bytes that never need encoding. Everything
// else is escaped, including '=' and ' ', which would otherwise end a value.
func unreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' ||
		c >= 'a' && c <= 'z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

const hexDigits = "0123456789ABCDEF"

func escape(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) {
			out.WriteByte(c)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hexDigits[c>>4])
		out.WriteByte(hexDigits[c&0x0f])
	}
	return out.String()
}

func unescape(s string) (string, error) {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("truncated escape")
		}
		hi, err := hexValue(s[i+1])
		if err != nil {
			return "", err
		}
		lo, err := hexValue(s[i+2])
		if err != nil {
			return "", err
		}
		out.WriteByte(hi<<4 | lo)
		i += 2
	}
	return out.String(), nil
}

func hexValue(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	}
	return 0, fmt.Errorf("invalid escape digit %q", string(c))
}
