package XRay

import (
	"fmt"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	t2stun "github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// StartTun2SocksTun bridges a named wintun adapter to the local SOCKS inbound.
//
// Named rather than descriptor-based because Windows hands out no tun fd: the
// adapter is created here by name and destroyed by [StopTun2Socks], which also
// drops the addresses and routes configured on it.
func StartTun2SocksTun(name, socksAddr, user, pass string, mtu int32) error {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	return startTun2Socks(func() (device.Device, error) {
		// Set before the adapter is created, because that is the only moment
		// wireguard-go reads them. The tunnel type is what Windows network
		// settings displays; left at its default this tunnel would present
		// itself as a WireGuard one, next to the adapter the WireGuard engine
		// creates for real.
		wgtun.WintunTunnelType = adapterTunnelType
		wgtun.WintunStaticRequestedGUID = &adapterGUID

		dev, err := t2stun.Open(name, uint32(mtu))
		if err != nil {
			return nil, fmt.Errorf("open tun %q: %w", name, err)
		}
		return dev, nil
	}, socksAddr, user, pass)
}
