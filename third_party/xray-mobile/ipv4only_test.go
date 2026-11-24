//go:build android || windows || linux

package XRay

import (
	"testing"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Both fakes embed the interface so the methods a test does not exercise
// exist but panic if reached, which is louder than a silent zero value.

type recordingDispatcher struct {
	stack.NetworkDispatcher
	delivered []tcpip.NetworkProtocolNumber
}

// The filter returns before touching pkt for IPv6 and only forwards the
// pointer for IPv4, so tests pass nil rather than managing PacketBuffer
// reference counts for a value nothing reads.
func (r *recordingDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	r.delivered = append(r.delivered, protocol)
}

type fakeDevice struct {
	device.Device
	attached stack.NetworkDispatcher
}

func (f *fakeDevice) Attach(dispatcher stack.NetworkDispatcher) { f.attached = dispatcher }

func TestIPv6IsDroppedAndCounted(t *testing.T) {
	inner := &recordingDispatcher{}
	filtered := &ipv4OnlyDispatcher{NetworkDispatcher: inner}

	// A delta, because the counter is process-wide and other tests move it.
	before := DroppedIPv6()
	filtered.DeliverNetworkPacket(header.IPv6ProtocolNumber, nil)

	if len(inner.delivered) != 0 {
		t.Fatalf("IPv6 reached the stack: %v", inner.delivered)
	}
	if moved := DroppedIPv6() - before; moved != 1 {
		t.Fatalf("DroppedIPv6 moved by %d, want 1", moved)
	}
}

func TestIPv4PassesThrough(t *testing.T) {
	inner := &recordingDispatcher{}
	filtered := &ipv4OnlyDispatcher{NetworkDispatcher: inner}

	before := DroppedIPv6()
	filtered.DeliverNetworkPacket(header.IPv4ProtocolNumber, nil)

	if len(inner.delivered) != 1 || inner.delivered[0] != header.IPv4ProtocolNumber {
		t.Fatalf("IPv4 did not reach the stack: %v", inner.delivered)
	}
	if moved := DroppedIPv6() - before; moved != 0 {
		t.Fatalf("IPv4 was counted as dropped (delta %d)", moved)
	}
}

// Attach is where the filter is actually installed. Without this the wrapper
// still compiles and reports nothing, while every IPv6 packet reaches gVisor
// and the bug is back.
func TestAttachInstallsTheFilter(t *testing.T) {
	inner := &recordingDispatcher{}
	dev := &fakeDevice{}

	(&ipv4OnlyDevice{Device: dev}).Attach(inner)

	if dev.attached == nil {
		t.Fatal("Attach never reached the device")
	}
	if dev.attached == stack.NetworkDispatcher(inner) {
		t.Fatal("the device was attached to the unfiltered dispatcher")
	}

	dev.attached.DeliverNetworkPacket(header.IPv6ProtocolNumber, nil)
	if len(inner.delivered) != 0 {
		t.Fatalf("IPv6 passed through the attached dispatcher: %v", inner.delivered)
	}
}
