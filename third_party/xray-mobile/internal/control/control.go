// Package control is the core's end of the line protocol: it reads commands,
// runs them against an [Engine], and writes the replies and status events.
//
// Kept apart from the command that hosts it so that it builds and is tested
// on every platform. What it has to get right is ordering under concurrency,
// and none of that is Windows's business; the engine that is lives in
// cmd/vless_core.
package control

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mysteriumnetwork/vless-core/xray-mobile/internal/wire"
)

// Engine is the tunnel, as far as the protocol is concerned.
//
// Start and Stop are only ever called one at a time. Stats and Version can
// arrive during either.
type Engine interface {
	// Start brings a tunnel up and returns once it carries traffic, or with
	// an error once it has undone whatever it did. It gives up early when ctx
	// is cancelled.
	//
	// onLost is how a tunnel that later goes away on its own is reported. It
	// may be called from any goroutine and does not block.
	Start(ctx context.Context, config string, onLost func(error)) error
	// Stop tears everything down. Safe to call when nothing is up.
	Stop()
	Stats() (uplink, downlink int64)
	Version() string
}

const (
	// Configs run to a few KB, and percent-encoding inflates them further.
	// bufio's default 64 KB cap would truncate one into a parse error that
	// looks like a malformed request.
	maxLineBytes = 4 * 1024 * 1024

	// Only starts and stops wait here, and the plugin sends one at a time.
	queueDepth = 16
)

type request struct {
	// Position among the starts and stops, in the order they were read.
	seq    uint64
	fields wire.Fields
}

type lostTunnel struct {
	generation uint64
	err        error
}

type loop struct {
	engine Engine

	outMu sync.Mutex
	out   *bufio.Writer

	// Touched only by the goroutine that runs commands, which is what
	// serialises start and stop: Xray keeps one package-wide instance, and a
	// stop landing inside a start would leave it set.
	running    bool
	generation uint64

	// The reader's way in to a start the worker is inside of.
	cancelMu sync.Mutex
	cancel   context.CancelFunc
	// Every start numbered below this was followed by a stop.
	stopSeq atomic.Uint64
	// Set once nothing more will be asked for.
	closing atomic.Bool

	// Losses reported by the engine, for the worker to take in its own time.
	// A list and a wake rather than a channel of them: a report must neither
	// block its caller nor be dropped, and the worker can be inside a start
	// for seconds while they arrive.
	lostMu   sync.Mutex
	losses   []lostTunnel
	lostWake chan struct{}
}

// Run serves commands from in until it is closed or interrupt fires, then
// takes down whatever is up and returns.
//
// A closed stdin means the plugin is gone, and an interrupt that the session
// is ending. Either way nothing is left to drive the tunnel, and the machine
// must not stay routed into it.
func Run(in io.Reader, out io.Writer, engine Engine, interrupt <-chan struct{}) {
	l := &loop{
		engine:   engine,
		out:      bufio.NewWriter(out),
		lostWake: make(chan struct{}, 1),
	}

	l.emit(wire.Fields{"event": "ready", "version": engine.Version()})

	queue := make(chan request, queueDepth)
	go l.read(in, queue)

	// Its own goroutine, because the loop below is inside the start for as
	// long as a start takes, and that is exactly when an interrupt has to
	// get through.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupt:
			l.close()
		case <-done:
		}
	}()

serve:
	for {
		select {
		case req, ok := <-queue:
			if !ok {
				break serve
			}
			l.handle(req)
		case <-l.lostWake:
			for _, lost := range l.takeLosses() {
				l.tunnelLost(lost)
			}
		case <-interrupt:
			break serve
		}
	}

	l.stop()
}

// read turns stdin into requests. It never waits on a start: that is the
// point of it being separate from the goroutine that runs one.
func (l *loop) read(in io.Reader, queue chan<- request) {
	// In this order: whatever is in flight is called off before the worker
	// is told there is nothing more.
	defer close(queue)
	defer l.close()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var seq uint64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields, err := wire.Decode(line)
		if err != nil {
			l.emit(wire.Fields{"event": "error", "message": fmt.Sprintf("parse request: %v", err)})
			continue
		}

		id := fields["id"]
		switch fields["cmd"] {
		case "start":
			seq++
			queue <- request{seq: seq, fields: fields}

		case "stop":
			seq++
			// Before it is queued. The worker may be inside the start this
			// is meant to end, and would not look at the queue until that
			// start had run its course.
			l.stopSeq.Store(seq)
			l.cancelStart()
			queue <- request{seq: seq, fields: fields}

		// Answered here rather than queued: they change nothing, and behind
		// a start they would wait out the whole of it.
		case "stats":
			up, down := l.engine.Stats()
			l.reply(id, wire.Fields{
				"event":    "stats",
				"uplink":   strconv.FormatInt(up, 10),
				"downlink": strconv.FormatInt(down, 10),
			})

		case "version":
			l.reply(id, wire.Fields{"event": "version", "version": l.engine.Version()})

		default:
			l.reply(id, wire.Fields{"event": "error", "message": "unknown command " + fields["cmd"]})
		}
	}
}

// close calls off a start in flight and refuses any that follow.
func (l *loop) close() {
	l.closing.Store(true)
	l.cancelStart()
}

func (l *loop) cancelStart() {
	l.cancelMu.Lock()
	defer l.cancelMu.Unlock()
	if l.cancel != nil {
		l.cancel()
	}
}

func (l *loop) handle(req request) {
	id := req.fields["id"]
	switch req.fields["cmd"] {
	case "start":
		l.start(req, id)
	case "stop":
		l.stop()
		l.reply(id, wire.Fields{"event": "stopped"})
	}
}

func (l *loop) start(req request, id string) {
	// Reported without a status: a start refused because a tunnel is already
	// running tears nothing down, and saying disconnected would leave the UI
	// claiming so while traffic is still flowing.
	if l.running {
		l.reply(id, wire.Fields{"event": "error", "message": "a tunnel is already running"})
		return
	}
	config := req.fields["config"]
	if config == "" {
		l.reply(id, wire.Fields{"event": "error", "message": "no config"})
		l.emit(wire.Fields{"event": "status", "status": "disconnected"})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.cancelMu.Lock()
	l.cancel = cancel
	l.cancelMu.Unlock()
	defer func() {
		l.cancelMu.Lock()
		l.cancel = nil
		l.cancelMu.Unlock()
	}()

	// A stop read while this start was still queued found nothing to cancel.
	// Checked after the cancel is published, so one arriving now finds it.
	if l.closing.Load() || req.seq < l.stopSeq.Load() {
		cancel()
	}
	if ctx.Err() != nil {
		l.emit(wire.Fields{"event": "status", "status": "disconnected"})
		return
	}

	l.emit(wire.Fields{"event": "status", "status": "connecting"})

	// Counted per attempt, not per tunnel. A start that fails has had a
	// watcher too, and its loss must not be taken for the next one's.
	l.generation++
	generation := l.generation
	err := l.engine.Start(ctx, config, func(err error) {
		l.reportLoss(lostTunnel{generation: generation, err: err})
	})

	if ctx.Err() != nil {
		// Called off, whatever Start returned: it can come up in the instant
		// it is told not to. Not an error either way. Whoever called it off
		// knows why, and an error event would reach the app as a failed
		// connect. What it left up goes with the stop that called it off,
		// which is the next thing this goroutine does.
		l.emit(wire.Fields{"event": "status", "status": "disconnected"})
		return
	}
	if err != nil {
		l.reply(id, wire.Fields{"event": "error", "message": err.Error()})
		l.emit(wire.Fields{"event": "status", "status": "disconnected"})
		return
	}

	l.running = true
	l.reply(id, wire.Fields{"event": "started"})
	l.emit(wire.Fields{"event": "status", "status": "connected"})
}

func (l *loop) stop() {
	if !l.running {
		// Still unwind: a failed start can leave pieces up, and this is the
		// only thing that runs when stdin closes.
		l.engine.Stop()
		return
	}

	l.emit(wire.Fields{"event": "status", "status": "disconnecting"})
	l.engine.Stop()
	l.running = false
	l.emit(wire.Fields{"event": "status", "status": "disconnected"})
}

// reportLoss is what the engine calls, from wherever it is.
func (l *loop) reportLoss(lost lostTunnel) {
	l.lostMu.Lock()
	l.losses = append(l.losses, lost)
	l.lostMu.Unlock()

	select {
	case l.lostWake <- struct{}{}:
	default:
	}
}

func (l *loop) takeLosses() []lostTunnel {
	l.lostMu.Lock()
	defer l.lostMu.Unlock()
	losses := l.losses
	l.losses = nil
	return losses
}

func (l *loop) tunnelLost(lost lostTunnel) {
	// A loss can arrive after its tunnel was stopped and another started.
	// That one is not lost.
	if !l.running || lost.generation != l.generation {
		return
	}
	// No id: nobody asked. The plugin passes these on as they come.
	l.emit(wire.Fields{"event": "error", "message": fmt.Sprintf("the tunnel was lost: %v", lost.err)})
	l.stop()
}

// reply emits a response, tagging it with the request's id so the plugin can
// match it. Commands sent without one (connect, disconnect) get no id field
// rather than an empty one.
func (l *loop) reply(id string, fields wire.Fields) {
	if id != "" {
		fields["id"] = id
	}
	l.emit(fields)
}

// emit writes one message and flushes it. Flushed every time on purpose: the
// plugin is waiting on these, and a buffered status change would arrive only
// once something else happened to push it out.
func (l *loop) emit(fields wire.Fields) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	_, _ = l.out.WriteString(wire.Encode(fields) + "\n")
	_ = l.out.Flush()
}
