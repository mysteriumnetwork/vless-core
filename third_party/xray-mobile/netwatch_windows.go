package XRay

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// What keeps a configured tunnel true after the moment it was configured.
//
// Two things on the machine change under it. The default route moves when the
// user changes network, and the exit is pinned to the gateway that was the
// default at connect: left alone, the proxy's own connection goes to a gateway
// that is no longer there and the tunnel is dead while still reported as up.
// And the adapter itself can go, which takes its routes with it and lets
// traffic out through the physical interface instead.
//
// The first is repaired here. The second cannot be, so it is reported.

const (
	// A network switch arrives as a burst of changes, and the table is only
	// worth reading once it has stopped moving.
	watchSettle = 500 * time.Millisecond
	// How long an adapter must stay missing to count as lost rather than as
	// something passing.
	watchRecheck = 3 * time.Second
)

// Guarded by netMu.
var watch *tunWatch

type tunWatch struct {
	luid   winipcfg.LUID
	onLost func(error)

	wake chan struct{}
	done chan struct{}

	routes     *winipcfg.RouteChangeCallback
	interfaces *winipcfg.InterfaceChangeCallback
}

// startWatchLocked is best effort. A tunnel without a watcher is the tunnel
// every release before this one had, so failing to register is said on stderr
// and nothing more.
func startWatchLocked(luid winipcfg.LUID, onLost func(error)) {
	stopWatchLocked()

	w := &tunWatch{
		luid:   luid,
		onLost: onLost,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}

	var err error
	w.routes, err = winipcfg.RegisterRouteChangeCallback(
		func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) { w.poke() })
	if err != nil {
		fmt.Fprintf(os.Stderr, "vless_core: not watching routes: %v\n", err)
	}
	w.interfaces, err = winipcfg.RegisterInterfaceChangeCallback(
		func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) { w.poke() })
	if err != nil {
		fmt.Fprintf(os.Stderr, "vless_core: not watching interfaces: %v\n", err)
	}
	if w.routes == nil && w.interfaces == nil {
		return
	}

	watch = w
	go w.run()
}

func stopWatchLocked() {
	w := watch
	if w == nil {
		return
	}
	watch = nil
	close(w.done)
	// Unregister waits for callbacks already running. They only ever poke,
	// which cannot block, so this is safe with the lock held. The goroutine
	// is not waited for: it may be waiting for this same lock, and finds
	// itself replaced once it has it.
	if w.routes != nil {
		_ = w.routes.Unregister()
	}
	if w.interfaces != nil {
		_ = w.interfaces.Unregister()
	}
}

// poke is what the system's notifications call. Never blocks: a wake already
// pending covers this one too.
func (w *tunWatch) poke() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *tunWatch) run() {
	for {
		select {
		case <-w.done:
			return
		case <-w.wake:
		}
		if !w.pause(watchSettle) {
			return
		}
		// Everything that arrived while settling is covered by the read
		// about to happen.
		select {
		case <-w.wake:
		default:
		}

		err := w.check()
		if err == nil {
			continue
		}
		if !w.pause(watchRecheck) {
			return
		}
		if err = w.check(); err != nil {
			if w.onLost != nil {
				w.onLost(err)
			}
			return
		}
	}
}

// pause reports false when the watch was stopped meanwhile.
func (w *tunWatch) pause(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-w.done:
		return false
	case <-timer.C:
		return true
	}
}

// check returns an error only for an adapter that is gone.
func (w *tunWatch) check() error {
	netMu.Lock()
	defer netMu.Unlock()

	// Stopped while waiting for the lock, which a teardown holds.
	if watch != w {
		return nil
	}
	if err := adapterLost(w.luid); err != nil {
		return err
	}
	followDefaultRouteLocked(w.luid)
	return nil
}

// adapterLost reports an adapter that is no longer there.
//
// Only that. One that is there but reports itself down is left alone: a
// machine coming back from sleep can show that for a while, and taking a
// working tunnel down on it leaves the user unprotected without having asked
// to be, which is worse than noticing a dead one late.
func adapterLost(luid winipcfg.LUID) error {
	if _, err := luid.Interface(); err != nil {
		return fmt.Errorf("the tunnel adapter is gone: %w", err)
	}
	return nil
}

// followDefaultRouteLocked moves the exit's host route to wherever the
// machine's default route is now.
//
// Best effort, and silent: with no default route at all there is nowhere to
// move it, and the change that brings one back wakes the watcher again.
func followDefaultRouteLocked(tunLUID winipcfg.LUID) {
	if exitRoute == nil {
		return
	}
	hop, physical, err := defaultGatewayExcluding(tunLUID)
	if err != nil {
		return
	}

	current := *exitRoute
	if current.luid == physical && current.hop == hop {
		// Same gateway, but an interface that went down and came back did so
		// without the routes that were on it.
		if _, err := current.luid.Route(current.prefix, current.hop); err == nil {
			return
		}
	}

	// The new one before the old one goes, so the exit is never without a
	// host route: in between, its traffic would follow the tunnel's own
	// routes into the tunnel it is carrying.
	if err := physical.AddRoute(current.prefix, hop, 0); err != nil &&
		!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return
	}
	exitRoute = &exitRouteState{luid: physical, prefix: current.prefix, hop: hop}
	if current.luid != physical || current.hop != hop {
		_ = current.luid.DeleteRoute(current.prefix, current.hop)
	}
}
