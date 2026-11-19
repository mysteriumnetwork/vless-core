package XRay

import (
	"encoding/json"
	"strings"
	"testing"
)

const placeholderConfig = `{
  "inbounds": [
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 0,
      "settings": {"auth": "password", "accounts": [], "udp": true}
    }
  ],
  "outbounds": [{"tag": "proxy", "protocol": "vless"}]
}`

func prepared(t *testing.T, config string, port int, user, pass string) map[string]any {
	t.Helper()
	raw, err := PrepareSocksInbound([]byte(config), port, user, pass)
	if err != nil {
		t.Fatalf("PrepareSocksInbound: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("result is not valid json: %v", err)
	}
	return parsed
}

func socksInbound(t *testing.T, parsed map[string]any) map[string]any {
	t.Helper()
	for _, entry := range parsed["inbounds"].([]any) {
		inbound := entry.(map[string]any)
		if inbound["tag"] == "socks-in" {
			return inbound
		}
	}
	t.Fatal("no socks-in inbound in the result")
	return nil
}

func TestPrepareSocksInboundBindsPortAndCredentials(t *testing.T) {
	inbound := socksInbound(t, prepared(t, placeholderConfig, 10808, "user", "pass"))

	if got := inbound["port"].(float64); got != 10808 {
		t.Errorf("port = %v, want 10808", got)
	}

	settings := inbound["settings"].(map[string]any)
	if got := settings["auth"]; got != "password" {
		t.Errorf("auth = %v, want password", got)
	}

	accounts := settings["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(accounts))
	}
	account := accounts[0].(map[string]any)
	if account["user"] != "user" || account["pass"] != "pass" {
		t.Errorf("account = %v, want user/pass", account)
	}
}

func TestPrepareSocksInboundLeavesTheRestAlone(t *testing.T) {
	parsed := prepared(t, placeholderConfig, 1080, "u", "p")

	outbounds := parsed["outbounds"].([]any)
	if len(outbounds) != 1 {
		t.Fatalf("outbounds = %d, want 1", len(outbounds))
	}
	if tag := outbounds[0].(map[string]any)["tag"]; tag != "proxy" {
		t.Errorf("outbound tag = %v, want proxy", tag)
	}

	// udp carries the DNS queries the routing rules depend on; dropping it
	// while rewriting the sibling fields would disable them silently.
	if udp := socksInbound(t, parsed)["settings"].(map[string]any)["udp"]; udp != true {
		t.Errorf("udp = %v, want true", udp)
	}
}

func TestPrepareSocksInboundRejectsBadInput(t *testing.T) {
	tests := []struct {
		name   string
		config string
		port   int
		user   string
		pass   string
		want   string
	}{
		{"no inbounds", `{"outbounds": []}`, 1080, "u", "p", "no inbounds"},
		{"wrong tag", `{"inbounds": [{"tag": "other"}]}`, 1080, "u", "p", `no "socks-in" inbound`},
		{"no settings", `{"inbounds": [{"tag": "socks-in"}]}`, 1080, "u", "p", "no settings"},
		{"malformed", `{`, 1080, "u", "p", "parse config"},
		{"port zero", placeholderConfig, 0, "u", "p", "out of range"},
		{"port too high", placeholderConfig, 70000, "u", "p", "out of range"},
		{"empty user", placeholderConfig, 1080, "", "p", "credentials are empty"},
		{"empty pass", placeholderConfig, 1080, "u", "", "credentials are empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrepareSocksInbound([]byte(tt.config), tt.port, tt.user, tt.pass)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

const proxyConfig = `{
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {"vnext": [{"address": "exit.example.com", "port": 443}]},
      "streamSettings": {
        "tlsSettings": {"serverName": "exit.example.com"},
        "wsSettings": {"host": "exit.example.com", "path": "/vless"}
      }
    }
  ]
}`

func TestProxyAddressReadsTheServerName(t *testing.T) {
	address, err := ProxyAddress([]byte(proxyConfig))
	if err != nil {
		t.Fatalf("ProxyAddress: %v", err)
	}
	if address != "exit.example.com" {
		t.Errorf("address = %q, want exit.example.com", address)
	}
}

func TestPinProxyAddressLeavesTheHandshakeNamesAlone(t *testing.T) {
	raw, err := PinProxyAddress([]byte(proxyConfig), "203.0.113.7")
	if err != nil {
		t.Fatalf("PinProxyAddress: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("result is not valid json: %v", err)
	}

	var proxy map[string]any
	for _, entry := range parsed["outbounds"].([]any) {
		if outbound := entry.(map[string]any); outbound["tag"] == "proxy" {
			proxy = outbound
		}
	}
	if proxy == nil {
		t.Fatal("no proxy outbound in the result")
	}

	vnext := proxy["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if got := vnext["address"]; got != "203.0.113.7" {
		t.Errorf("address = %v, want 203.0.113.7", got)
	}

	// TLS and the WebSocket Host must keep the hostname: pinning them to the
	// literal fails the handshake, and the failure looks like a dead exit.
	stream := proxy["streamSettings"].(map[string]any)
	if sni := stream["tlsSettings"].(map[string]any)["serverName"]; sni != "exit.example.com" {
		t.Errorf("serverName = %v, want exit.example.com", sni)
	}
	if host := stream["wsSettings"].(map[string]any)["host"]; host != "exit.example.com" {
		t.Errorf("ws host = %v, want exit.example.com", host)
	}
}

func TestProxyConfigRejectsBadInput(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{"no outbounds", `{"inbounds": []}`, "no outbounds"},
		{"no proxy tag", `{"outbounds": [{"tag": "direct"}]}`, `no "proxy" outbound`},
		{"no settings", `{"outbounds": [{"tag": "proxy"}]}`, "no settings"},
		{"no vnext", `{"outbounds": [{"tag": "proxy", "settings": {}}]}`, "no vnext"},
		{"empty vnext", `{"outbounds": [{"tag": "proxy", "settings": {"vnext": []}}]}`, "no vnext"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ProxyAddress([]byte(tt.config)); err == nil {
				t.Error("ProxyAddress: expected an error, got none")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ProxyAddress error = %q, want it to contain %q", err, tt.want)
			}
			if _, err := PinProxyAddress([]byte(tt.config), "203.0.113.7"); err == nil {
				t.Error("PinProxyAddress: expected an error, got none")
			}
		})
	}
}

func TestPinProxyAddressRejectsAnEmptyResolution(t *testing.T) {
	if _, err := PinProxyAddress([]byte(proxyConfig), ""); err == nil {
		t.Fatal("expected an error, got none")
	}
}
