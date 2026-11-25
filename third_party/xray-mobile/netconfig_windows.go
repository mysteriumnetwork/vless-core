package XRay

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Android gets addressing, routing and DNS from VpnService.Builder, and Apple
// from NEPacketTunnelProvider. On Windows nothing does it for us, so this file
// does: it is the only part of the tunnel with no mobile counterpart.

const (
	// What Windows network settings displays for the adapter.
	adapterTunnelType = "Mysterium VPN"

	// Low enough to beat the physical interface, without touching automatic
	// metrics anywhere else.
	tunInterfaceMetric = 1
)

// Fixed rather than random so the adapter's LUID is known before the adapter
// exists. Resolving it by name instead would race the interface table, which a
// freshly created adapter takes a moment to appear in.
var adapterGUID = windows.GUID{
	Data1: 0x6041f8d3,
	Data2: 0x1cd4,
	Data3: 0x49a9,
	Data4: [8]byte{0x9c, 0xb3, 0x63, 0xc4, 0x8c, 0x87, 0xa4, 0xf8},
}

// Halves rather than a single default route. They win on longest-prefix match
// without replacing the existing default route, so tearing the tunnel down
// cannot leave the machine with no default route at all.
var defaultHalves = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"),
	netip.MustParsePrefix("8000::/1"),
}

var (
	netMu sync.Mutex
	// The one piece of configuration that does not die with the adapter: it
	// lives on the physical interface, so teardown has to remove it by hand.
	exitRoute *exitRouteState
)

type exitRouteState struct {
	luid   winipcfg.LUID
	prefix netip.Prefix
	hop    netip.Addr
}

// TunNetConfig is what Windows has to be told about the tunnel interface.
type TunNetConfig struct {
	// Address4 is assigned to the adapter, e.g. 198.18.0.1/24.
	Address4 netip.Prefix
	// Address6 is captured rather than left out. An address family with no
	// route does not get dropped, it falls through to the physical interface,
	// which leaks the real address while the UI says connected. The exits are
	// IPv4-only, so v6 is refused inside the tunnel instead, which is where
	// the client can see it fail.
	Address6 netip.Prefix
	// DNS servers published on the adapter. Queries to them are routed into
	// the tunnel and answered by Xray's dns-out.
	DNS []netip.Addr
	// ExitIP is the proxy endpoint, which must stay reachable off-tunnel.
	ExitIP netip.Addr
	MTU    uint32
}

// ConfigureTun assigns the addresses, routes and DNS for the adapter opened by
// [StartTun2SocksTun]. Call it once the adapter exists and before reporting a
// tunnel as up.
//
// Any failure rolls the whole thing back, so a half-configured interface never
// outlives the call.
//
// It does not install the DNS policy. That is [ApplyDNSPolicy], and it comes
// last.
func ConfigureTun(cfg TunNetConfig) error {
	netMu.Lock()
	defer netMu.Unlock()

	if !cfg.Address4.IsValid() {
		return errors.New("no tunnel address")
	}

	luid, err := winipcfg.LUIDFromGUID(&adapterGUID)
	if err != nil {
		return fmt.Errorf("resolve adapter luid: %w", err)
	}

	// Before the default routes below, not after. In between the two the
	// proxy's own connection would be routed into the tunnel it is carrying.
	if cfg.ExitIP.IsValid() {
		if err := addExitRouteLocked(cfg.ExitIP, luid); err != nil {
			return err
		}
	}

	addresses := []netip.Prefix{cfg.Address4}
	if cfg.Address6.IsValid() {
		addresses = append(addresses, cfg.Address6)
	}
	if err := luid.SetIPAddresses(addresses); err != nil {
		unconfigureLocked(luid)
		return fmt.Errorf("set addresses: %w", err)
	}

	families := []winipcfg.AddressFamily{windows.AF_INET}
	if cfg.Address6.IsValid() {
		families = append(families, windows.AF_INET6)
	}

	// Not SetRoutes, which flushes and adds in one call. Its flush reports the
	// last delete failure even though it carried on, and a fresh adapter's
	// auto-created routes -- link-local, multicast, the on-link subnet -- are
	// routinely gone between being enumerated and being deleted. That returned
	// "Element not found" before a single route had been added, which is
	// exactly the failure this replaces.
	for _, family := range families {
		if err := luid.FlushRoutes(family); err != nil &&
			!errors.Is(err, windows.ERROR_NOT_FOUND) {
			unconfigureLocked(luid)
			return fmt.Errorf("flush routes: %w", err)
		}
	}

	for _, half := range defaultHalves {
		if half.Addr().Is6() && !cfg.Address6.IsValid() {
			continue
		}
		hop := netip.IPv4Unspecified()
		if half.Addr().Is6() {
			hop = netip.IPv6Unspecified()
		}
		// Named individually: one prefix failing says which family and which
		// half, where the batch call could only say that something did.
		if err := luid.AddRoute(half, hop, 0); err != nil {
			unconfigureLocked(luid)
			return fmt.Errorf("add route %s: %w", half, err)
		}
	}
	for _, family := range families {
		if err := setInterfaceParams(luid, family, cfg.MTU); err != nil {
			unconfigureLocked(luid)
			return err
		}
	}

	// The adapter's own servers are not enough on their own: see the comment
	// in nrpt_windows.go for why the query would otherwise still reach the
	// LAN router in the clear.
	if len(cfg.DNS) > 0 {
		if err := luid.SetDNS(windows.AF_INET, cfg.DNS, nil); err != nil {
			unconfigureLocked(luid)
			return fmt.Errorf("set dns: %w", err)
		}
	}

	return nil
}

// UnconfigureTun removes what [ConfigureTun] added. Safe to call when nothing
// was configured, and safe to call before the adapter is closed or after.
func UnconfigureTun() {
	netMu.Lock()
	defer netMu.Unlock()

	luid, err := winipcfg.LUIDFromGUID(&adapterGUID)
	if err != nil {
		// The adapter is already gone, which takes its own configuration with
		// it. The exit route and the DNS policy live outside the adapter and
		// are not covered by that, so they still have to go.
		removeNRPT()
		removeExitRouteLocked()
		return
	}
	unconfigureLocked(luid)
}

func unconfigureLocked(luid winipcfg.LUID) {
	// Best effort throughout: this runs on failure paths, where the thing
	// being undone may never have been applied.
	//
	// The policy first. It outlives the adapter, so leaving it in place while
	// the rest goes would point every lookup on the machine at a resolver
	// reached through a tunnel that no longer exists.
	removeNRPT()
	_ = luid.FlushDNS(windows.AF_INET)
	_ = luid.FlushRoutes(windows.AF_UNSPEC)
	_ = luid.FlushIPAddresses(windows.AF_UNSPEC)
	removeExitRouteLocked()
}

func addExitRouteLocked(exit netip.Addr, tunLUID winipcfg.LUID) error {
	if !exit.Is4() {
		return fmt.Errorf("exit address %s is not ipv4", exit)
	}

	hop, physical, err := defaultGatewayExcluding(tunLUID)
	if err != nil {
		return err
	}

	prefix := netip.PrefixFrom(exit, exit.BitLen())
	if err := physical.AddRoute(prefix, hop, 0); err != nil &&
		!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("add exit route %s via %s: %w", prefix, hop, err)
	}

	exitRoute = &exitRouteState{luid: physical, prefix: prefix, hop: hop}
	return nil
}

func removeExitRouteLocked() {
	if exitRoute == nil {
		return
	}
	_ = exitRoute.luid.DeleteRoute(exitRoute.prefix, exitRoute.hop)
	exitRoute = nil
}

// defaultGatewayExcluding finds the default route the machine would use if the
// tunnel were not there, which is the one the proxy's own traffic has to keep
// using.
func defaultGatewayExcluding(exclude winipcfg.LUID) (netip.Addr, winipcfg.LUID, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("read route table: %w", err)
	}

	var (
		bestHop  netip.Addr
		bestLUID winipcfg.LUID
		best     uint32
		found    bool
	)
	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceLUID == exclude {
			continue
		}
		hop := row.NextHop.Addr()
		if !hop.IsValid() || hop.IsUnspecified() {
			continue
		}
		// Windows ranks by route metric plus interface metric, so comparing
		// route metrics alone picks the wrong gateway on a machine with both
		// wifi and ethernet up.
		total := row.Metric + interfaceMetric(row.InterfaceLUID)
		if !found || total < best {
			bestHop, bestLUID, best, found = hop, row.InterfaceLUID, total, true
		}
	}
	if !found {
		return netip.Addr{}, 0, errors.New("no default route to reach the exit through")
	}
	return bestHop, bestLUID, nil
}

func interfaceMetric(luid winipcfg.LUID) uint32 {
	row, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return 0
	}
	return row.Metric
}

func setInterfaceParams(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu uint32) error {
	row, err := luid.IPInterface(family)
	if err != nil {
		return fmt.Errorf("read interface: %w", err)
	}
	row.UseAutomaticMetric = false
	row.Metric = tunInterfaceMetric
	if mtu > 0 {
		row.NLMTU = mtu
	}
	if err := row.Set(); err != nil {
		return fmt.Errorf("set interface metric: %w", err)
	}
	return nil
}
