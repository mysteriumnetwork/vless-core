package XRay

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// Protector hands an outbound socket to Android's VpnService so its traffic
// leaves on the underlying network instead of routing back into the tunnel.
//
// Implemented in Kotlin; gomobile binds it as a Java interface. It has no
// meaning on Apple, where the Network Extension excludes its own traffic.
type Protector interface {
	// Protect reports whether the socket was protected.
	Protect(fd int32) bool
}

var (
	protectorMu sync.RWMutex
	protector   Protector
	registerCtl sync.Once
)

// SetProtector installs the protector used for every socket Xray opens, and
// registers the dialer controller on first call. Pass nil to clear it.
//
// Xray offers no way to remove a controller once registered, so one is
// registered exactly once and reads the current protector on each dial.
// Registering per connect would stack a new controller every time.
func SetProtector(p Protector) error {
	protectorMu.Lock()
	protector = p
	protectorMu.Unlock()

	var err error
	registerCtl.Do(func() {
		err = internet.RegisterDialerController(protectSocket)
	})
	return err
}

// protectSocket runs for every TCP dial and every UDP listen the default
// system dialer performs, which is every socket an outbound opens.
//
// The returned error is logged by Xray and does not abort the dial, so a
// failure here surfaces in the log as an unprotected socket that will loop
// back into the tunnel rather than as a refused connection.
func protectSocket(network, address string, conn syscall.RawConn) error {
	protectorMu.RLock()
	p := protector
	protectorMu.RUnlock()

	if p == nil {
		return nil
	}

	protected := false
	if err := conn.Control(func(fd uintptr) {
		protected = p.Protect(int32(fd))
	}); err != nil {
		return fmt.Errorf("reach fd for %s %s: %w", network, address, err)
	}
	if !protected {
		return fmt.Errorf("VpnService refused to protect %s %s", network, address)
	}
	return nil
}
