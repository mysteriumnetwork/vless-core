package wire

import (
	"strings"
	"testing"
)

func TestEncodeSortsKeys(t *testing.T) {
	got := Encode(Fields{"zulu": "1", "alpha": "2", "mike": "3"})
	if want := "alpha=2 mike=3 zulu=1"; got != want {
		t.Errorf("Encode = %q, want %q", got, want)
	}
}

func TestRoundTripsAwkwardValues(t *testing.T) {
	values := map[string]string{
		"empty":     "",
		"spaces":    "a b  c",
		"equals":    "k=v=w",
		"quotes":    `he said "hi"`,
		"newline":   "line1\nline2",
		"percent":   "100%",
		"json":      `{"inbounds":[{"port":0,"tag":"socks-in"}]}`,
		"unicode":   "тунель 🇲🇰",
		"backslash": `C:\Program Files\app.exe`,
	}

	line := Encode(values)
	if strings.ContainsAny(line, "\n") {
		t.Fatalf("encoded line contains a newline: %q", line)
	}

	decoded, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for key, want := range values {
		if got := decoded[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestDecodeRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"no equals", "justakey"},
		{"empty key", "=value"},
		{"truncated escape", "key=%4"},
		{"bare percent", "key=%"},
		{"invalid digit", "key=%zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.line); err == nil {
				t.Errorf("Decode(%q) = nil error, want one", tt.line)
			}
		})
	}
}

func TestDecodeAcceptsAnEmptyLine(t *testing.T) {
	fields, err := Decode("")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(fields) != 0 {
		t.Errorf("fields = %v, want empty", fields)
	}
}

func TestDecodeToleratesExtraWhitespace(t *testing.T) {
	fields, err := Decode("  a=1   b=2  ")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fields["a"] != "1" || fields["b"] != "2" {
		t.Errorf("fields = %v, want a=1 b=2", fields)
	}
}
