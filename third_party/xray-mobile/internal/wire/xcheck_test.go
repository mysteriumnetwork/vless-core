package wire

import "testing"

// goldenFields and goldenLine are duplicated in the plugin's own test, at
// vless_dart/windows/test/wire_test.cpp. The two implementations have to agree
// byte for byte or the plugin and the core cannot talk, and nothing else in
// either build would notice if they drifted.
var goldenFields = Fields{
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

const goldenLine = "backslash=C%3A%5CProgram%20Files%5Capp.exe empty= " +
	"equals=k%3Dv%3Dw " +
	"json=%7B%22inbounds%22%3A%5B%7B%22port%22%3A0%2C%22tag%22%3A%22socks-in%22%7D%5D%7D " +
	"newline=line1%0Aline2 percent=100%25 quotes=he%20said%20%22hi%22 " +
	"spaces=a%20b%20%20c " +
	"unicode=%D1%82%D1%83%D0%BD%D0%B5%D0%BB%D1%8C%20%F0%9F%87%B2%F0%9F%87%B0"

func TestGoldenVectorMatchesThePlugin(t *testing.T) {
	if got := Encode(goldenFields); got != goldenLine {
		t.Errorf("Encode mismatch.\n got: %s\nwant: %s", got, goldenLine)
	}

	decoded, err := Decode(goldenLine)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for key, want := range goldenFields {
		if got := decoded[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
