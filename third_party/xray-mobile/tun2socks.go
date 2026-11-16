//go:build android

// Android links tun2socks; Apple uses hev-socks5-tunnel from Tun2SocksKit and
// must not carry a second, unused TCP/IP stack into a memory-limited
// Network Extension.

package XRay

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"syscall"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
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

// StartTun2Socks bridges a tun descriptor to the local SOCKS inbound Xray
// serves, so packets the OS routes into the tunnel reach the proxy.
//
// [fd] is handed over: the caller must detach it and must not close it
// itself. It is closed here on every failure path, and by [StopTun2Socks]
// otherwise, so the caller never has to decide.
//
// Built from tun2socks's own pieces rather than its engine package on
// purpose. engine.Start reports a start failure through zap's Fatal level,
// which calls os.Exit — in-process that takes the host app down, and the
// logger it would have to be caught with is replaced before the failure can
// happen.
func StartTun2Socks(fd int32, socksAddr, user, pass string, mtu int32) error {
	tunMu.Lock()
	defer tunMu.Unlock()

	if tunStack != nil {
		return errors.New("tun2socks is already running")
	}
	if socksAddr == "" {
		return errors.New("empty socks address")
	}
	if mtu <= 0 {
		mtu = defaultMTU
	}

	dev, err := fdbased.Open(strconv.Itoa(int(fd)), uint32(mtu), 0)
	if err != nil {
		// Open does not take ownership until it succeeds, and the caller has
		// already detached the descriptor, so nothing else would close it.
		_ = syscall.Close(int(fd))
		return fmt.Errorf("open tun fd: %w", err)
	}

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

// StopTun2Socks tears the bridge down and closes the tun descriptor. Safe to
// call when nothing is running.
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
