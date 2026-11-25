package XRay

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// These run against the machine's real interfaces and route table, which is
// the only place the calls underneath can be exercised at all. Nothing here
// touches a route the machine uses: the one address routed is TEST-NET-1,
// which is reserved for documentation and goes nowhere.

// No interface has this.
const noSuchAdapter = winipcfg.LUID(0x00ffffffffffffff)

var testExit = netip.MustParseAddr("192.0.2.1")

func physicalInterface(t *testing.T) winipcfg.LUID {
	t.Helper()
	hop, luid, err := defaultGatewayExcluding(0)
	if err != nil {
		t.Skipf("this machine has no default route: %v", err)
	}
	if !hop.Is4() || hop.IsUnspecified() {
		t.Fatalf("default gateway %v is not a usable next hop", hop)
	}
	return luid
}

func TestFindsTheDefaultGateway(t *testing.T) {
	luid := physicalInterface(t)
	if _, err := luid.Interface(); err != nil {
		t.Fatalf("the default route names an interface that is not there: %v", err)
	}
}

func TestAnAdapterThatIsThereIsNotLost(t *testing.T) {
	if err := adapterLost(physicalInterface(t)); err != nil {
		t.Fatalf("a working interface was reported lost: %v", err)
	}
}

func TestAnAdapterThatIsGoneIsLost(t *testing.T) {
	if err := adapterLost(noSuchAdapter); err == nil {
		t.Fatal("an interface that does not exist was not reported lost")
	}
}

// The whole path, with the real notifications: registered, woken, and the
// loss carried out to whoever asked. The adapter is one that was never
// there, which is what a removed one looks like.
func TestTheWatcherReportsALostAdapter(t *testing.T) {
	lost := make(chan error, 1)

	netMu.Lock()
	startWatchLocked(noSuchAdapter, func(err error) { lost <- err })
	w := watch
	netMu.Unlock()
	if w == nil {
		t.Fatal("no change notification could be registered")
	}
	t.Cleanup(func() {
		netMu.Lock()
		stopWatchLocked()
		netMu.Unlock()
	})

	w.poke()

	select {
	case err := <-lost:
		if err == nil {
			t.Fatal("a loss was reported without a reason")
		}
	case <-time.After(watchSettle + watchRecheck + 5*time.Second):
		t.Fatal("the lost adapter was never reported")
	}
}

func TestTheWatcherSaysNothingAboutAHealthyAdapter(t *testing.T) {
	luid := physicalInterface(t)
	lost := make(chan error, 1)

	netMu.Lock()
	startWatchLocked(luid, func(err error) { lost <- err })
	w := watch
	netMu.Unlock()
	if w == nil {
		t.Fatal("no change notification could be registered")
	}

	w.poke()

	select {
	case err := <-lost:
		t.Fatalf("a working interface was reported lost: %v", err)
	case <-time.After(watchSettle + watchRecheck + time.Second):
	}

	// Stopping must come back, with the notifications still registered and
	// the goroutine possibly mid-check.
	stopped := make(chan struct{})
	go func() {
		netMu.Lock()
		stopWatchLocked()
		netMu.Unlock()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stopping the watcher did not return")
	}
}

// A network switch, as far as the exit's route is concerned: the route is
// gone and the default route says where it belongs now.
func TestTheExitRouteIsPutBackWhenItGoesMissing(t *testing.T) {
	requireElevated(t)
	physicalInterface(t)

	netMu.Lock()
	defer netMu.Unlock()
	t.Cleanup(func() {
		netMu.Lock()
		removeExitRouteLocked()
		netMu.Unlock()
	})

	if err := addExitRouteLocked(testExit, 0); err != nil {
		t.Fatalf("pin the exit: %v", err)
	}
	pinned := *exitRoute
	if _, err := pinned.luid.Route(pinned.prefix, pinned.hop); err != nil {
		t.Fatalf("the exit route is not in the table: %v", err)
	}

	// What an interface going down and coming back does to it.
	if err := pinned.luid.DeleteRoute(pinned.prefix, pinned.hop); err != nil {
		t.Fatalf("drop the exit route: %v", err)
	}

	followDefaultRouteLocked(0)

	if exitRoute == nil {
		t.Fatal("the exit route was forgotten")
	}
	if _, err := exitRoute.luid.Route(exitRoute.prefix, exitRoute.hop); err != nil {
		t.Fatalf("the exit route was not put back: %v", err)
	}

	removeExitRouteLocked()
	if _, err := pinned.luid.Route(pinned.prefix, pinned.hop); err == nil {
		t.Fatal("the exit route outlived its removal")
	}
}

// With the route where it should be there is nothing to do, and doing
// something anyway would notify the watcher, which would do it again.
func TestAnExitRouteThatIsInPlaceIsLeftAlone(t *testing.T) {
	requireElevated(t)
	physicalInterface(t)

	netMu.Lock()
	defer netMu.Unlock()
	t.Cleanup(func() {
		netMu.Lock()
		removeExitRouteLocked()
		netMu.Unlock()
	})

	if err := addExitRouteLocked(testExit, 0); err != nil {
		t.Fatalf("pin the exit: %v", err)
	}
	before := exitRoute

	followDefaultRouteLocked(0)

	if exitRoute != before {
		t.Fatal("a route that was already right was replaced")
	}
}
