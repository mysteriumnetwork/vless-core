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
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/windows"

	XRay "github.com/mysteriumnetwork/vless-core/xray-mobile"
	"github.com/mysteriumnetwork/vless-core/xray-mobile/internal/wire"
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
	tunDNS = []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
	}
)

const (
	tunMTU = 1500

	probeDomain    = "cloudflare.com"
	probeTimeoutMs = 8000
)

var (
	out   = bufio.NewWriter(os.Stdout)
	outMu sync.Mutex

	// Serialises start and stop. Xray keeps one package-wide instance, so a
	// stop landing inside a start leaves it set and every later start fails
	// with "xray is already running".
	runMu   sync.Mutex
	running bool
)

func main() {
	// Before anything else: a previous run killed with the host app leaves its
	// DNS policy behind, and that policy points the whole machine at a
	// resolver that is no longer reachable.
	XRay.ClearStaleDNSPolicy()

	emit(wire.Fields{"event": "ready", "version": XRay.GetVersion()})

	scanner := bufio.NewScanner(os.Stdin)
	// Configs run to a few KB, and percent-encoding inflates them further.
	// The default 64 KB cap would truncate one into a parse error that looks
	// like a malformed request.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields, err := wire.Decode(line)
		if err != nil {
			emit(wire.Fields{"event": "error", "message": fmt.Sprintf("parse request: %v", err)})
			continue
		}
		handle(fields)
	}

	// stdin closed: the plugin is gone, so take the tunnel down rather than
	// leaving the machine routed into a tunnel nothing is driving.
	stop()
}

// reply emits a response, tagging it with the request's id so the plugin can
// match it. Commands sent without one (connect, disconnect) get no id field
// rather than an empty one.
func reply(id string, fields wire.Fields) {
	if id != "" {
		fields["id"] = id
	}
	emit(fields)
}

func handle(req wire.Fields) {
	id := req["id"]
	switch req["cmd"] {
	case "start":
		if err := start(req["config"]); err != nil {
			reply(id, wire.Fields{"event": "error", "message": err.Error()})
			// Only when nothing is up. A start refused because a tunnel is
			// already running tears nothing down, and reporting disconnected
			// would leave the UI claiming so while traffic is still flowing.
			if !isRunning() {
				emit(wire.Fields{"event": "status", "status": "disconnected"})
			}
			return
		}
		reply(id, wire.Fields{"event": "started"})
		emit(wire.Fields{"event": "status", "status": "connected"})

	case "stop":
		stop()
		reply(id, wire.Fields{"event": "stopped"})

	case "stats":
		up, down := stats()
		reply(id, wire.Fields{
			"event":    "stats",
			"uplink":   strconv.FormatInt(up, 10),
			"downlink": strconv.FormatInt(down, 10),
		})

	case "version":
		reply(id, wire.Fields{"event": "version", "version": XRay.GetVersion()})

	default:
		reply(id, wire.Fields{"event": "error", "message": "unknown command " + req["cmd"]})
	}
}

func isRunning() bool {
	runMu.Lock()
	defer runMu.Unlock()
	return running
}

func start(rawConfig string) (err error) {
	runMu.Lock()
	defer runMu.Unlock()

	if running {
		return errors.New("a tunnel is already running")
	}
	if rawConfig == "" {
		return errors.New("no config")
	}
	// Checked up front so the failure names the cause. Without it the first
	// symptom is ACCESS_DENIED from wintun's adapter creation, several steps
	// further in and far less obviously about privileges.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("the core must run elevated to create a tunnel adapter")
	}

	emit(wire.Fields{"event": "status", "status": "connecting"})

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
	exit, err := resolveExit(server)
	if err != nil {
		return err
	}
	if config, err = XRay.PinProxyAddress(config, exit.String()); err != nil {
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

	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := XRay.StartTun2SocksTun(adapterName, socksAddr, user, pass, tunMTU); err != nil {
		return fmt.Errorf("start tun bridge: %w", err)
	}
	defer func() {
		if err != nil {
			XRay.StopTun2Socks()
		}
	}()

	if err := XRay.ConfigureTun(XRay.TunNetConfig{
		Address4: tunAddress4,
		Address6: tunAddress6,
		DNS:      tunDNS,
		ExitIP:   exit,
		MTU:      tunMTU,
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
	if err := XRay.Probe(probeDomain, probeTimeoutMs); err != nil {
		return err
	}

	running = true
	return nil
}

func stop() {
	runMu.Lock()
	defer runMu.Unlock()

	if !running {
		// Still unwind: a failed start can leave pieces up, and stop is the
		// only thing that runs when stdin closes.
		XRay.UnconfigureTun()
		XRay.StopTun2Socks()
		XRay.Stop()
		return
	}

	emit(wire.Fields{"event": "status", "status": "disconnecting"})

	// Interface first: once the routes are gone the machine is back on its
	// own default route, so tearing down the rest cannot strand traffic in a
	// tunnel that no longer carries it.
	XRay.UnconfigureTun()
	XRay.StopTun2Socks()
	XRay.Stop()

	running = false
	emit(wire.Fields{"event": "status", "status": "disconnected"})
}

func stats() (uplink, downlink int64) {
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
func resolveExit(server string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(server); err == nil {
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("server %s is not ipv4", server)
		}
		return addr, nil
	}

	ips, err := net.LookupIP(server)
	if err != nil {
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

// emit writes one message and flushes it. Flushed every time on purpose: the
// plugin is waiting on these, and a buffered status change would arrive only
// once something else happened to push it out.
func emit(fields wire.Fields) {
	outMu.Lock()
	defer outMu.Unlock()
	_, _ = out.WriteString(wire.Encode(fields) + "\n")
	_ = out.Flush()
}
