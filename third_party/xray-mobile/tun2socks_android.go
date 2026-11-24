package XRay

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
)

// StartTun2Socks bridges a tun descriptor to the local SOCKS inbound.
//
// [fd] is handed over: the caller must detach it and must not close it itself.
// It is closed here on every failure path, and by [StopTun2Socks] otherwise,
// so the caller never has to decide.
func StartTun2Socks(fd int32, socksAddr, user, pass string, mtu int32) error {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	return startTun2Socks(func() (device.Device, error) {
		dev, err := fdbased.Open(strconv.Itoa(int(fd)), uint32(mtu), 0)
		if err != nil {
			// Open does not take ownership until it succeeds, and the caller
			// has already detached the descriptor, so nothing else would
			// close it.
			_ = syscall.Close(int(fd))
			return nil, fmt.Errorf("open tun fd: %w", err)
		}
		return dev, nil
	}, socksAddr, user, pass)
}
