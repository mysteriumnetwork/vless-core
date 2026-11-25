//go:build windows

// Command vless_core hosts Xray and the tun bridge in a process of its own.
//
// The Flutter plugin spawns it and drives it over stdin/stdout with the line
// protocol in internal/wire. A separate process rather than a DLL because a Go
// panic, or tun2socks reaching zap's Fatal level, calls os.Exit — in-process
// that would take the host app down with it.
//
// It inherits the host app's token, and creating the adapter and writing
// routes need administrator rights, so the host has to be elevated — the
// Mysterium runner links with requireAdministrator. A start refuses early and
// says so when it is not.
//
// The plugin is expected to put this process in a job object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so an app crash cannot leave a
// configured adapter behind.
//
// The protocol itself, and the ordering of starts and stops, is
// internal/control. This file is what a start and a stop do on Windows.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	XRay "github.com/mysteriumnetwork/vless-core/xray-mobile"
	"github.com/mysteriumnetwork/vless-core/xray-mobile/internal/control"
)

// The tunnel's own parameters, matching what VlessVpnService hands
// VpnService.Builder on Android so the two platforms present the same tunnel.
var (
	adapterName = "Mysterium VPN"
	tunAddress4 = netip.MustParsePrefix("198.18.0.1/24")
	tunAddress6 = netip.MustParsePrefix("fd00:2::1/64")
	// What clients are told to query. Which resolver actually answers is
	// decided by the config's own dns block, because dns-out intercepts the
	// query whatever address it was sent to.
	//
	// Inside the tunnel's own subnet rather than a public resolver: naming one
	// lets the OS recognise it and upgrade to encrypted DNS on its own port,
	// which no port-53 rule intercepts, so AAAA reaches the client. Android
	// was measured doing exactly that; Windows 11 auto-upgrades known
	// resolvers to DoH. Nothing answers those ports here. Not .1, which is
	// the adapter's own address and would be answered locally.
	tunDNS = []netip.Addr{netip.MustParseAddr("198.18.0.2")}
)

const (
	tunMTU = 1500

	probeDomain    = "cloudflare.com"
	probeTimeoutMs = 8000
)

func main() {
	// Before anything else: a previous run killed with the host app leaves its
	// DNS policy behind, and that policy points the whole machine at a
	// resolver that is no longer reachable.
	XRay.ClearStaleDNSPolicy()

	// A closing console, a logoff and a shutdown arrive as SIGTERM, and
	// Windows ends the process a few seconds later whatever it is doing.
	// Without this nothing ran in between, and the DNS policy stayed.
	//
	// Not to be leaned on for the last two. Windows stops sending them to a
	// process once user32 is loaded into it, which a library can do without
	// saying so. The plugin has a window and is told of a session ending
	// through that; this covers the core when it is run by anything else.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		<-signals
		close(interrupt)
	}()

	// Returns once stdin closes or the signal arrives, with the tunnel down.
	control.Run(os.Stdin, os.Stdout, engine{}, interrupt)
}

// engine is the tunnel on Windows: Xray, the bridge to a wintun adapter, the
// interface configuration and the DNS policy, brought up in that order and
// taken down in reverse.
type engine struct{}

func (engine) Version() string { return XRay.GetVersion() }

func (engine) Start(ctx context.Context, rawConfig string, onLost func(error)) (err error) {
	// Checked up front so the failure names the cause. Without it the first
	// symptom is ACCESS_DENIED from wintun's adapter creation, several steps
	// further in and far less obviously about privileges.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("the core must run elevated to create a tunnel adapter")
	}

	port, err := freePort()
	if err != nil {
		return err
	}
	user, pass, err := credentials()
	if err != nil {
		return err
	}
	config, err := XRay.PrepareSocksInbound([]byte(rawConfig), port, user, pass)
	if err != nil {
		return err
	}

	// Resolved here, while the machine still has its own routing: once the
	// tunnel is up the lookup would route into it, and the exit is what the
	// tunnel depends on.
	server, err := XRay.ProxyAddress(config)
	if err != nil {
		return err
	}
	exit, err := resolveExit(ctx, server)
	if err != nil {
		return err
	}
	if config, err = XRay.PinProxyAddress(config, exit.String()); err != nil {
		return err
	}

	// Between every step from here: none of them can be interrupted, and the
	// adapter alone can take seconds the first time its driver is installed.
	// A start that was called off meanwhile stops at the next one.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Unwound in reverse by every failure path below, so a partial start
	// never leaves Xray up or the interface configured.
	if err := XRay.Start(config); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}
	defer func() {
		if err != nil {
			XRay.Stop()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}

	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := XRay.StartTun2SocksTun(adapterName, socksAddr, user, pass, tunMTU); err != nil {
		return fmt.Errorf("start tun bridge: %w", err)
	}
	defer func() {
		if err != nil {
			XRay.StopTun2Socks()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := XRay.ConfigureTun(XRay.TunNetConfig{
		Address4: tunAddress4,
		Address6: tunAddress6,
		DNS:      tunDNS,
		ExitIP:   exit,
		MTU:      tunMTU,
		OnLost:   onLost,
	}); err != nil {
		return fmt.Errorf("configure interface: %w", err)
	}
	defer func() {
		if err != nil {
			XRay.UnconfigureTun()
		}
	}()

	// Established is not the same as working: a server that refuses our
	// credentials completes the handshake and then closes, which would
	// otherwise be reported as a healthy tunnel.
	if err := XRay.ProbeContext(ctx, probeDomain, probeTimeoutMs); err != nil {
		return err
	}

	// Last, and only for a tunnel that works and that nobody has called off.
	// This is the one piece that does harm if the process dies holding it,
	// so it is held for as short a time as there is.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := XRay.ApplyDNSPolicy(tunDNS); err != nil {
		return fmt.Errorf("dns policy: %w", err)
	}
	return nil
}

// Stop takes down whatever is up, whether a start finished or not.
//
// Interface first: that removes the DNS policy before anything else, and once
// the routes are gone the machine is back on its own default route, so
// tearing down the rest cannot strand traffic in a tunnel that no longer
// carries it.
func (engine) Stop() {
	XRay.UnconfigureTun()
	XRay.StopTun2Socks()
	XRay.Stop()
}

func (engine) Stats() (uplink, downlink int64) {
	for _, line := range strings.Split(XRay.QueryStats("proxy"), "\n") {
		name, value, ok := strings.Cut(line, ">>>")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "uplink":
			uplink = n
		case "downlink":
			downlink = n
		}
	}
	return uplink, downlink
}

// resolveExit turns the config's server address into the IPv4 literal the host
// route needs. IPv4 only: the exits have no IPv6 egress, and a v6 host route
// would not keep the proxy's own connection out of the tunnel.
func resolveExit(ctx context.Context, server string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(server); err == nil {
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("server %s is not ipv4", server)
		}
		return addr, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", server)
	if err != nil {
		if ctx.Err() != nil {
			return netip.Addr{}, ctx.Err()
		}
		return netip.Addr{}, fmt.Errorf("resolve %s: %w", server, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			addr, _ := netip.AddrFromSlice(v4)
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no ipv4 address", server)
}

// freePort asks the OS for one and hands it straight back. The window between
// the two is a race in principle; in practice the port goes to Xray
// immediately and nothing else on the machine is bidding for loopback ports.
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve a loopback port: %w", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func credentials() (user, pass string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("mint socks credentials: %w", err)
	}
	return hex.EncodeToString(buf[:16]), hex.EncodeToString(buf[16:]), nil
}
