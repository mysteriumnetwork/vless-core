package control_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/mysteriumnetwork/vless-core/xray-mobile/internal/control"
	"github.com/mysteriumnetwork/vless-core/xray-mobile/internal/wire"
)

// Long enough that a loaded CI machine does not trip it, short enough that a
// loop which is stuck fails the test rather than the job.
const patience = 5 * time.Second

// fakeEngine is a tunnel that comes up when the test lets it.
type fakeEngine struct {
	mu     sync.Mutex
	starts int
	stops  int
	lost   []func(error)

	// One value per Start, sent as it is entered.
	entered chan struct{}
	// When set, Start waits here: for a value, or for its context.
	hold chan struct{}
	// A start that cannot be interrupted, like the steps before the probe.
	deaf bool
	// What a Start that was not interrupted returns.
	err error
}

func newEngine() *fakeEngine {
	return &fakeEngine{entered: make(chan struct{}, 8)}
}

func (e *fakeEngine) Start(ctx context.Context, _ string, onLost func(error)) error {
	e.mu.Lock()
	e.starts++
	e.lost = append(e.lost, onLost)
	hold, deaf, err := e.hold, e.deaf, e.err
	e.mu.Unlock()

	e.entered <- struct{}{}

	if hold != nil {
		if deaf {
			<-hold
		} else {
			select {
			case <-hold:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return err
}

func (e *fakeEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stops++
}

func (e *fakeEngine) Stats() (int64, int64) { return 7, 9 }
func (e *fakeEngine) Version() string       { return "test" }

func (e *fakeEngine) counts() (starts, stops int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.starts, e.stops
}

func (e *fakeEngine) set(change func(*fakeEngine)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	change(e)
}

// lose reports the tunnel of the n-th start as gone.
func (e *fakeEngine) lose(n int, err error) {
	e.mu.Lock()
	report := e.lost[n]
	e.mu.Unlock()
	report(err)
}

type session struct {
	t         *testing.T
	engine    *fakeEngine
	stdin     *io.PipeWriter
	interrupt chan struct{}
	events    chan wire.Fields
	returned  chan struct{}
}

func serve(t *testing.T, engine *fakeEngine) *session {
	t.Helper()
	stdinRead, stdinWrite := io.Pipe()
	stdoutRead, stdoutWrite := io.Pipe()

	s := &session{
		t:         t,
		engine:    engine,
		stdin:     stdinWrite,
		interrupt: make(chan struct{}),
		events:    make(chan wire.Fields, 64),
		returned:  make(chan struct{}),
	}

	go func() {
		control.Run(stdinRead, stdoutWrite, engine, s.interrupt)
		stdoutWrite.Close()
		close(s.returned)
	}()
	go func() {
		defer close(s.events)
		scanner := bufio.NewScanner(stdoutRead)
		for scanner.Scan() {
			fields, err := wire.Decode(scanner.Text())
			if err != nil {
				t.Errorf("the loop wrote a line that does not decode: %q", scanner.Text())
				continue
			}
			s.events <- fields
		}
	}()

	t.Cleanup(func() {
		stdinWrite.Close()
		select {
		case <-s.returned:
		case <-time.After(patience):
			t.Error("Run did not return after stdin closed")
		}
	})

	s.expect(wire.Fields{"event": "ready", "version": "test"})
	return s
}

func (s *session) send(fields wire.Fields) {
	s.t.Helper()
	if _, err := io.WriteString(s.stdin, wire.Encode(fields)+"\n"); err != nil {
		s.t.Fatalf("write to the loop: %v", err)
	}
}

func (s *session) next() wire.Fields {
	s.t.Helper()
	select {
	case fields, ok := <-s.events:
		if !ok {
			s.t.Fatal("the loop returned while an event was still expected")
		}
		return fields
	case <-time.After(patience):
		s.t.Fatal("no event from the loop")
		return nil
	}
}

func (s *session) expect(want ...wire.Fields) {
	s.t.Helper()
	for _, fields := range want {
		if got := s.next(); !maps.Equal(got, fields) {
			s.t.Fatalf("got %v, want %v", got, fields)
		}
	}
}

// rest waits for the loop to return and hands back what it wrote meanwhile.
func (s *session) rest() []wire.Fields {
	s.t.Helper()
	var all []wire.Fields
	deadline := time.After(patience)
	for {
		select {
		case fields, ok := <-s.events:
			if !ok {
				return all
			}
			all = append(all, fields)
		case <-deadline:
			s.t.Fatal("the loop did not return")
			return nil
		}
	}
}

func (s *session) enteredStart() {
	s.t.Helper()
	select {
	case <-s.engine.entered:
	case <-time.After(patience):
		s.t.Fatal("the engine was never asked to start")
	}
}

func status(name string) wire.Fields {
	return wire.Fields{"event": "status", "status": name}
}

func has(events []wire.Fields, want wire.Fields) bool {
	for _, fields := range events {
		if maps.Equal(fields, want) {
			return true
		}
	}
	return false
}

var (
	start = wire.Fields{"cmd": "start", "config": "{}"}
	stop  = wire.Fields{"cmd": "stop"}
)

func TestAStartAndAStopReportEachStep(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))

	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})

	if starts, stops := engine.counts(); starts != 1 || stops != 1 {
		t.Fatalf("engine saw %d starts and %d stops, want one of each", starts, stops)
	}
}

func TestAFailedStartSaysWhy(t *testing.T) {
	engine := newEngine()
	engine.err = errors.New("no route to the exit")
	s := serve(t, engine)

	s.send(wire.Fields{"cmd": "start", "config": "{}", "id": "4"})
	s.expect(
		status("connecting"),
		wire.Fields{"event": "error", "id": "4", "message": "no route to the exit"},
		status("disconnected"),
	)
}

func TestAStartWithoutAConfigNeverReachesTheEngine(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(wire.Fields{"cmd": "start"})
	s.expect(wire.Fields{"event": "error", "message": "no config"}, status("disconnected"))

	if starts, _ := engine.counts(); starts != 0 {
		t.Fatalf("engine saw %d starts, want none", starts)
	}
}

// Saying disconnected here would leave the UI claiming so while the first
// tunnel is still carrying traffic.
func TestASecondStartIsRefusedWithoutTouchingTheFirst(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))

	s.send(start)
	s.expect(wire.Fields{"event": "error", "message": "a tunnel is already running"})

	// The next thing said is about the stop, so nothing was said in between.
	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})

	if starts, _ := engine.counts(); starts != 1 {
		t.Fatalf("engine saw %d starts, want 1", starts)
	}
}

// The reason the loop reads on one goroutine and runs commands on another: a
// start is seconds long, and a disconnect used to wait all of them out.
func TestAStopCallsOffAStartInFlight(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	s.send(stop)
	// No error event: whoever called it off knows why, and the app would
	// show one as a failed connect.
	s.expect(status("disconnected"), wire.Fields{"event": "stopped"})

	if _, stops := engine.counts(); stops == 0 {
		t.Fatal("nothing unwound what the interrupted start may have left up")
	}
}

func TestClosingStdinCallsOffAStartInFlight(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	s.stdin.Close()
	events := s.rest()

	if has(events, status("connected")) {
		t.Fatalf("a start that was called off reported connected: %v", events)
	}
	if _, stops := engine.counts(); stops == 0 {
		t.Fatal("the loop returned without tearing down")
	}
}

func TestAnInterruptCallsOffAStartInFlight(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	close(s.interrupt)
	events := s.rest()

	if has(events, status("connected")) {
		t.Fatalf("a start that was called off reported connected: %v", events)
	}
	if _, stops := engine.counts(); stops == 0 {
		t.Fatal("the loop returned without tearing down")
	}
}

// A logoff or a shutdown with a tunnel up. stdin is still open: the plugin
// has not gone anywhere yet, and the core has seconds to live.
func TestAnInterruptTakesARunningTunnelDown(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))

	close(s.interrupt)
	events := s.rest()

	if !has(events, status("disconnected")) {
		t.Fatalf("the tunnel was not reported down: %v", events)
	}
	if _, stops := engine.counts(); stops != 1 {
		t.Fatalf("engine saw %d stops, want 1", stops)
	}
}

// The steps before the probe cannot be interrupted, so a start can finish
// after it was called off. It must not be left up, or reported as up.
func TestAStartThatFinishesAfterItWasCalledOffIsTakenDown(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	engine.deaf = true
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	s.send(stop)
	// The stop has been read once this comes back, and with it the cancel.
	s.send(wire.Fields{"cmd": "version", "id": "1"})
	s.expect(wire.Fields{"event": "version", "id": "1", "version": "test"})

	close(engine.hold)
	s.expect(status("disconnected"), wire.Fields{"event": "stopped"})

	if _, stops := engine.counts(); stops != 1 {
		t.Fatalf("engine saw %d stops, want the one that takes it down", stops)
	}
}

// Two starts queued, then a stop: the second had not begun when the stop was
// read, so there was nothing to cancel then. It must still not run.
func TestAStopAlsoStopsAStartStillWaitingItsTurn(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	s.send(start)
	s.send(stop)
	s.expect(status("disconnected"), status("disconnected"), wire.Fields{"event": "stopped"})

	if starts, _ := engine.counts(); starts != 1 {
		t.Fatalf("engine saw %d starts, want only the first", starts)
	}
}

func TestAStartAfterAStopStillRuns(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(stop)
	s.expect(wire.Fields{"event": "stopped"})

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))
}

// The plugin polls these once a second and fails the call when nothing
// answers; behind a start they would all queue for the length of it.
func TestStatsAndVersionAreAnsweredDuringAStart(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	s.send(wire.Fields{"cmd": "stats", "id": "2"})
	s.expect(wire.Fields{"event": "stats", "id": "2", "uplink": "7", "downlink": "9"})
	s.send(wire.Fields{"cmd": "version", "id": "3"})
	s.expect(wire.Fields{"event": "version", "id": "3", "version": "test"})

	close(engine.hold)
	s.expect(wire.Fields{"event": "started"}, status("connected"))
}

func TestALostTunnelIsReportedAndTakenDown(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))

	engine.lose(0, errors.New("the tunnel adapter is gone"))
	s.expect(
		wire.Fields{"event": "error", "message": "the tunnel was lost: the tunnel adapter is gone"},
		status("disconnecting"),
		status("disconnected"),
	)

	if _, stops := engine.counts(); stops != 1 {
		t.Fatalf("engine saw %d stops, want 1", stops)
	}
}

// The watcher of a tunnel that was stopped can still be mid-report when the
// next one comes up. That one is not lost.
func TestALossFromAnEarlierTunnelIsIgnored(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))
	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})
	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))

	engine.lose(0, errors.New("stale"))

	// A refused start, to give the loop a turn: whichever of the two it
	// takes first, the loss has been looked at by the time the stop is.
	s.send(start)
	s.expect(wire.Fields{"event": "error", "message": "a tunnel is already running"})
	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})
}

// A start that fails has had a watcher for a moment too. Its report can land
// while the next start is still coming up, and must not be taken for that
// one's.
func TestALossFromAFailedStartIsNotTheNextTunnels(t *testing.T) {
	engine := newEngine()
	engine.err = errors.New("the exit refused us")
	s := serve(t, engine)

	s.send(start)
	s.expect(
		status("connecting"),
		wire.Fields{"event": "error", "message": "the exit refused us"},
		status("disconnected"),
	)
	s.enteredStart()

	hold := make(chan struct{})
	engine.set(func(e *fakeEngine) { e.err, e.hold = nil, hold })
	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	engine.lose(0, errors.New("from the attempt that failed"))
	close(hold)
	s.expect(wire.Fields{"event": "started"}, status("connected"))

	s.send(start)
	s.expect(wire.Fields{"event": "error", "message": "a tunnel is already running"})
	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})
}

// Reported while its own start is still finishing, which is before there is
// a tunnel to lose. It is one all the same, a moment later.
func TestALossDuringItsOwnStartIsActedOnOnceTheStartIsDone(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	engine.deaf = true
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	engine.lose(0, errors.New("the tunnel adapter is gone"))
	close(engine.hold)

	s.expect(
		wire.Fields{"event": "started"},
		status("connected"),
		wire.Fields{"event": "error", "message": "the tunnel was lost: the tunnel adapter is gone"},
		status("disconnecting"),
		status("disconnected"),
	)
}

// Two reports while the loop is busy, the first of them stale. The second
// is the one that matters and must not be crowded out.
func TestALossIsNotDroppedBehindAStaleOne(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))
	s.enteredStart()
	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})

	hold := make(chan struct{})
	engine.set(func(e *fakeEngine) { e.hold, e.deaf = hold, true })
	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	engine.lose(0, errors.New("stale"))
	engine.lose(1, errors.New("the tunnel adapter is gone"))
	close(hold)

	s.expect(
		wire.Fields{"event": "started"},
		status("connected"),
		wire.Fields{"event": "error", "message": "the tunnel was lost: the tunnel adapter is gone"},
		status("disconnecting"),
		status("disconnected"),
	)
}

func TestALossAfterTheTunnelWasStoppedIsIgnored(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"), wire.Fields{"event": "started"}, status("connected"))
	s.send(stop)
	s.expect(status("disconnecting"), status("disconnected"), wire.Fields{"event": "stopped"})

	engine.lose(0, errors.New("late"))

	// Twice, so the loss has had a turn whichever the loop takes first.
	s.send(stop)
	s.expect(wire.Fields{"event": "stopped"})
	s.send(stop)
	s.expect(wire.Fields{"event": "stopped"})
}

// A start still queued when the plugin goes away has nobody left to stop it.
func TestNothingStartsOnceStdinHasClosed(t *testing.T) {
	engine := newEngine()
	engine.hold = make(chan struct{})
	s := serve(t, engine)

	s.send(start)
	s.expect(status("connecting"))
	s.enteredStart()

	s.send(start)
	s.stdin.Close()
	events := s.rest()

	if starts, _ := engine.counts(); starts != 1 {
		t.Fatalf("engine saw %d starts, want only the one in flight", starts)
	}
	if has(events, status("connected")) {
		t.Fatalf("reported connected with nobody listening: %v", events)
	}
}

func TestBadInputIsAnErrorNotAnExit(t *testing.T) {
	engine := newEngine()
	s := serve(t, engine)

	s.send(wire.Fields{"cmd": "dance", "id": "9"})
	s.expect(wire.Fields{"event": "error", "id": "9", "message": "unknown command dance"})

	if _, err := io.WriteString(s.stdin, "config=%zz\n\n"); err != nil {
		t.Fatal(err)
	}
	if got := s.next(); got["event"] != "error" || got["message"] == "" {
		t.Fatalf("got %v, want a parse error", got)
	}

	s.send(wire.Fields{"cmd": "version", "id": "1"})
	s.expect(wire.Fields{"event": "version", "id": "1", "version": "test"})
}
