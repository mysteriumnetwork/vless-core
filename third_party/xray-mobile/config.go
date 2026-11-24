package XRay

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// socksInboundTag is the inbound the clients reserve for the tun bridge.
	socksInboundTag = "socks-in"
	// proxyOutboundTag is the outbound that carries traffic to the exit.
	proxyOutboundTag = "proxy"
)

// PrepareSocksInbound fills in the SOCKS inbound the clients leave as a
// placeholder, binding it to [port] behind [user] and [pass] so nothing else
// on the machine can reach the proxy while it is up.
//
// Returns an error rather than adding the inbound if it is missing: a config
// without one would start, and then silently carry no traffic.
func PrepareSocksInbound(config []byte, port int, user, pass string) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("socks port %d out of range", port)
	}
	if user == "" || pass == "" {
		return nil, errors.New("socks credentials are empty")
	}

	var parsed map[string]any
	if err := json.Unmarshal(config, &parsed); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok {
		return nil, errors.New("config has no inbounds")
	}

	for _, entry := range inbounds {
		inbound, ok := entry.(map[string]any)
		if !ok || inbound["tag"] != socksInboundTag {
			continue
		}
		settings, ok := inbound["settings"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("inbound %q has no settings", socksInboundTag)
		}
		inbound["port"] = port
		settings["auth"] = "password"
		settings["accounts"] = []any{
			map[string]any{"user": user, "pass": pass},
		}
		return json.Marshal(parsed)
	}

	return nil, fmt.Errorf("config has no %q inbound", socksInboundTag)
}

// ProxyAddress reports the VLESS server as the config names it, before any
// resolution.
func ProxyAddress(config []byte) (string, error) {
	parsed, err := parseConfig(config)
	if err != nil {
		return "", err
	}
	vnext, err := proxyVnext(parsed)
	if err != nil {
		return "", err
	}
	address, ok := vnext["address"].(string)
	if !ok || address == "" {
		return "", errors.New("proxy outbound has no address")
	}
	return address, nil
}

// PinProxyAddress replaces the proxy outbound's address with a resolved IP
// literal.
//
// The host resolver does the lookup rather than Xray's, because a lookup
// attempted once the tunnel is up would route into it. The TLS serverName and
// the WebSocket Host header are deliberately untouched and keep the hostname,
// or the handshake fails.
func PinProxyAddress(config []byte, resolved string) ([]byte, error) {
	if resolved == "" {
		return nil, errors.New("resolved address is empty")
	}
	parsed, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	vnext, err := proxyVnext(parsed)
	if err != nil {
		return nil, err
	}
	vnext["address"] = resolved
	return json.Marshal(parsed)
}

func parseConfig(config []byte) (map[string]any, error) {
	var parsed map[string]any
	if err := json.Unmarshal(config, &parsed); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return parsed, nil
}

func proxyVnext(parsed map[string]any) (map[string]any, error) {
	outbounds, ok := parsed["outbounds"].([]any)
	if !ok {
		return nil, errors.New("config has no outbounds")
	}
	for _, entry := range outbounds {
		outbound, ok := entry.(map[string]any)
		if !ok || outbound["tag"] != proxyOutboundTag {
			continue
		}
		settings, ok := outbound["settings"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("outbound %q has no settings", proxyOutboundTag)
		}
		vnext, ok := settings["vnext"].([]any)
		if !ok || len(vnext) == 0 {
			return nil, fmt.Errorf("outbound %q has no vnext", proxyOutboundTag)
		}
		first, ok := vnext[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("outbound %q has a malformed vnext", proxyOutboundTag)
		}
		return first, nil
	}
	return nil, fmt.Errorf("config has no %q outbound", proxyOutboundTag)
}
