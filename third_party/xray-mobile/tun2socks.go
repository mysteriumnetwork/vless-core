//go:build android || windows

// Linked only on the platforms that drive a tun device themselves. Apple uses
// hev-socks5-tunnel from Tun2SocksKit and must not carry a second, unused
// TCP/IP stack into a memory-limited Network Extension.

package XRay

import (
	"errors"
	"fmt"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	glog "gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// defaultMTU matches the tunnel MTU the clients configure.
const defaultMTU = 1500

// bridgeLogLevel is the lowest level the bridge may log at.
//
// tun2socks installs a logger of its own at Info, and at Info it writes a
// line for every flow it carries, with the destination; at Warn, one for
// every dial that fails, with the destination again. They go to stderr,
// which gomobile forwards to logcat on Android and which is the plugin's
// pipe on Windows, so left alone it is a record of where the user went, kept
// by a VPN. Everything that names a destination is below Error, and nothing
// in the pieces linked here logs at Error or above, so this is silence in
// practice.
const bridgeLogLevel = t2slog.ErrorLevel

func init() {
	// After tun2socks's own init, which this package imports and so runs
	// first.
	quietBridge()
}

// quietBridge replaces the logger tun2socks installed for itself.
func quietBridge() {
	logger, err := t2slog.NewLeveled(bridgeLogLevel)
	if err != nil {
		// Its own logger stays, which is the behaviour before this existed.
		return
	}
	t2slog.SetLogger(logger)
	// SetLogger also levels gVisor's logger from the one it is given, as
	// 1 minus the level in an unsigned type: for anything above Warn that
	// wraps round to "everything". None of it would be written, since it all
	// arrives at the logger above, but each line would be put together first.
	glog.SetLevel(glog.Warning)
}

var (
	tunMu     sync.Mutex
	tunDevice device.Device
	tunStack  *stack.Stack
)

// startTun2Socks bridges a tun device to the local SOCKS inbound Xray serves,
// so packets the OS routes into the tunnel reach the proxy.
//
// [open] runs with the lock held, so a second concurrent start cannot bring up
// a device before the first has published its stack. Whatever it returns is
// owned here: closed on every failure path, and by [StopTun2Socks] otherwise,
// so no caller has to decide.
//
// Built from tun2socks's own pieces rather than its engine package on purpose.
// engine.Start reports a start failure through zap's Fatal level, which calls
// os.Exit — in-process that takes the host down, and the logger it would have
// to be caught with is replaced before the failure can happen.
func startTun2Socks(open func() (device.Device, error), socksAddr, user, pass string) error {
	tunMu.Lock()
	defer tunMu.Unlock()

	if tunStack != nil {
		return errors.New("tun2socks is already running")
	}
	if socksAddr == "" {
		return errors.New("empty socks address")
	}

	dev, err := open()
	if err != nil {
		return err
	}

	// Before the stack: gVisor would complete an IPv6 handshake before Xray
	// could refuse one, and the client never falls back.
	dev = &ipv4OnlyDevice{Device: dev}

	proxy, err := socks5.New(socksAddr, user, pass)
	if err != nil {
		dev.Close()
		return fmt.Errorf("socks5 proxy: %w", err)
	}
	tunnel.T().SetProxy(proxy)

	created, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: tunnel.T(),
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("create stack: %w", err)
	}

	tunDevice = dev
	tunStack = created
	return nil
}

// StopTun2Socks tears the bridge down and closes the tun device. Safe to call
// when nothing is running.
//
// Device before stack, matching tun2socks's own teardown.
func StopTun2Socks() {
	tunMu.Lock()
	defer tunMu.Unlock()

	if tunDevice != nil {
		tunDevice.Close()
		tunDevice = nil
	}
	if tunStack != nil {
		tunStack.Close()
		tunStack.Wait()
		tunStack = nil
	}
}

// Tun2SocksRunning reports whether the bridge is up.
func Tun2SocksRunning() bool {
	tunMu.Lock()
	defer tunMu.Unlock()
	return tunStack != nil
}
