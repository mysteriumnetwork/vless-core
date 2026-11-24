//go:build android || windows || linux

package XRay

import (
	"sync/atomic"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// IPv6 dies at the device, before gVisor sees it.
//
// gVisor completes the three-way handshake inside CreateEndpoint before
// tun2socks dials the proxy (its own comment in core/tcp.go reads "Perform a
// TCP three-way handshake"), so by the time Xray reports the exit cannot carry
// IPv6 the client is already connected. It sees "connected, then closed", and
// Happy Eyeballs does not recover from that: the IPv6 race was won, so no IPv4
// attempt follows. Measured on device as a 7.5ms connect followed by
// SSL_ERROR_SYSCALL, and reported by testers as Chrome loading a page but not
// its stylesheets -- a cold socket pool, which is why incognito reproduces it
// and a warm window does not.
//
// Dropping the frame before the stack sees it turns that into silence, which
// Happy Eyeballs does recover from. Apple already does exactly this in
// VlessPacketBridge.c; hiddify hit the same wall and refuses IPv6 in its
// router instead, which works there only because sing-box decides the route
// before completing the handshake.
//
// The ::/0 route stays. IPv6 is still captured, so it cannot fall through to
// the physical interface and leak the real address -- only the packets die.
// Delete this once the exits carry IPv6.
//
// linux is in the build constraint purely so ipv4only_test.go runs: nothing
// ships for it. Adding darwin instead would link a second TCP/IP stack into
// the Network Extension, which is the one thing that must not happen.

var droppedIPv6 atomic.Int64

// DroppedIPv6 counts IPv6 frames refused since the process started.
//
// Exported because the fault it belongs to is invisible from the outside: a
// tunnel dropping every IPv6 packet and one never offered any look identical
// from the app. int64 rather than a counter type because gomobile binds only
// signed integers.
func DroppedIPv6() int64 { return droppedIPv6.Load() }

// ipv4OnlyDevice is [device.Device] with IPv6 filtered out on the way in.
//
// Inbound only. The stack cannot originate IPv6 it was never given, so
// filtering writes as well would cost a rebuilt PacketBufferList and the
// reference-counting that goes with it, to catch packets that cannot exist.
type ipv4OnlyDevice struct {
	device.Device
}

func (d *ipv4OnlyDevice) Attach(dispatcher stack.NetworkDispatcher) {
	d.Device.Attach(&ipv4OnlyDispatcher{NetworkDispatcher: dispatcher})
}

type ipv4OnlyDispatcher struct {
	stack.NetworkDispatcher
}

// DeliverNetworkPacket drops IPv6 and passes everything else through.
//
// Returning without delivering is all that is needed: the caller owns the
// buffer and DecRefs it once this returns (iobased.Endpoint.dispatchLoop).
func (d *ipv4OnlyDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if protocol == header.IPv6ProtocolNumber {
		droppedIPv6.Add(1)
		return
	}
	d.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}
