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
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// defaultMTU matches the tunnel MTU the clients configure.
const defaultMTU = 1500

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
