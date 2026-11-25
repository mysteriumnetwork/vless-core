package XRay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xtls/xray-core/features/dns"
)

const (
	defaultProbeDomain    = "cloudflare.com"
	defaultProbeTimeoutMs = 8000
)

// Probe resolves a name through the running instance, which routes the query
// over the proxy outbound. A tunnel can be established and carry nothing: a
// server that refuses our credentials completes the transport handshake and
// then closes without answering, so this is what separates a working tunnel
// from one that only looks connected.
func Probe(domain string, timeoutMs int) error {
	return probe(context.Background(), domain, timeoutMs)
}

// probe is [Probe] with a way to give up early. Not exported from here: the
// mobile bindings cannot carry a context, and only the Windows core has a
// caller that can be interrupted.
func probe(ctx context.Context, domain string, timeoutMs int) error {
	mu.Lock()
	instance := running
	mu.Unlock()

	if instance == nil {
		return errors.New("xray is not running")
	}
	client, ok := instance.GetFeature(dns.ClientType()).(dns.Client)
	if !ok || client == nil {
		return errors.New("xray has no dns client")
	}
	if domain == "" {
		domain = defaultProbeDomain
	}
	if timeoutMs <= 0 {
		timeoutMs = defaultProbeTimeoutMs
	}

	// Buffered: LookupIP takes no deadline of its own, so it can outlive the
	// timeout, and an unbuffered send would leak the goroutine forever.
	done := make(chan error, 1)
	go func() {
		_, _, err := client.LookupIP(domain, dns.IPOption{IPv4Enable: true})
		done <- err
	}()

	timeout := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
	defer timeout.Stop()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("resolve %s through the tunnel: %w", domain, err)
		}
		return nil
	case <-timeout.C:
		return fmt.Errorf("resolving %s through the tunnel timed out after %dms", domain, timeoutMs)
	case <-ctx.Done():
		return ctx.Err()
	}
}
