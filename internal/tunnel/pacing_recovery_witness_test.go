package tunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlog"
)

// Installed only after preceding writers have joined. It witnesses exactly
// the first following raw Write, not a later call or the whole phase worker.
type feedbackWriteWitness struct {
	started chan struct{}
	done    chan struct{}
	once    sync.Once
}

type feedbackBackpressureGate struct {
	raw          *feedbackRawStream
	trace        *feedbackBlockedTrace
	first        *feedbackWriteWitness
	warmupOffset int64
}

func newFeedbackBackpressureGate(raw *feedbackRawStream, trace *feedbackBlockedTrace, warmupOffset int64) *feedbackBackpressureGate {
	first := &feedbackWriteWitness{started: make(chan struct{}), done: make(chan struct{})}
	raw.writeWitness = first
	return &feedbackBackpressureGate{raw: raw, trace: trace, first: first, warmupOffset: warmupOffset}
}

func (g *feedbackBackpressureGate) completed(finished <-chan struct{}) error {
	select {
	case <-g.first.done:
		return errors.New("first raw Write completed before receiver backpressure was witnessed")
	default:
	}
	select {
	case <-finished:
		return errors.New("phase writer completed before receiver backpressure was witnessed")
	default:
	}
	return nil
}

func (g *feedbackBackpressureGate) await(ctx context.Context, finished <-chan struct{}) (int64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-g.first.started:
	case <-finished:
		return 0, errors.New("phase writer never established a pending raw Write")
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := g.completed(finished); err != nil {
			return 0, err
		}
		if offset := g.trace.highest(); offset > g.warmupOffset {
			// Check completion after reading the received-frame evidence too.
			// A pending later call must not mask completion of the first call.
			if err := g.completed(finished); err != nil {
				return 0, err
			}
			if !g.raw.pending.Load() {
				return 0, errors.New("first raw Write is not pending at the received blocked-frame witness")
			}
			return offset, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-g.first.done:
			return 0, errors.New("first raw Write completed before receiver backpressure was witnessed")
		case <-finished:
			return 0, errors.New("phase writer completed before receiver backpressure was witnessed")
		case <-g.trace.changed:
		}
	}
}

func TestFeedbackBackpressureGateRequiresPendingFirstWrite(t *testing.T) {
	for _, mode := range []string{"pending", "first-completed", "phase-completed", "raw-not-pending", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			trace := newFeedbackBlockedTrace()
			trace.selectStream(0)
			raw := &feedbackRawStream{}
			gate := newFeedbackBackpressureGate(raw, trace, 1<<20)
			finished := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			raw.pending.Store(mode != "raw-not-pending")
			close(gate.first.started)
			trace.RecordEvent(qlog.PacketReceived{Frames: []qlog.Frame{{Frame: &qlog.StreamDataBlockedFrame{
				StreamID: 0, MaximumStreamData: (1 << 20) + (16 << 10),
			}}}})
			switch mode {
			case "first-completed":
				// A later raw call may be pending, but cannot replace the first.
				close(gate.first.done)
			case "phase-completed":
				close(finished)
			case "canceled":
				cancel()
			}
			offset, err := gate.await(ctx, finished)
			if mode == "pending" {
				if err != nil || offset <= gate.warmupOffset {
					t.Fatalf("pending fresh blocked write: offset=%d err=%v", offset, err)
				}
			} else if err == nil {
				t.Fatalf("%s unexpectedly established backpressure at offset %d", mode, offset)
			}
		})
	}
}

func TestFeedbackBackpressureGateBoundsMissingEvidence(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	trace.selectStream(0)
	gate := newFeedbackBackpressureGate(&feedbackRawStream{}, trace, 1<<20)
	gate.raw.pending.Store(true)
	close(gate.first.started)
	// Boundary and stale warmup evidence cannot release the slow-phase gate.
	trace.RecordEvent(qlog.PacketReceived{Frames: []qlog.Frame{{Frame: &qlog.StreamDataBlockedFrame{
		StreamID: 0, MaximumStreamData: 1 << 20,
	}}}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	offset, err := gate.await(ctx, make(chan struct{}))
	if !errors.Is(err, context.DeadlineExceeded) || offset != 0 {
		t.Fatalf("stale/equal-boundary evidence must wait until its deadline: offset=%d err=%v", offset, err)
	}
}

func TestQUICPacingBackpressureWitnessRequiresReceiveLimit(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	// More than the entire warmup and slow phase can fit without a read.
	// Retain the same controller, payload, deadlines and actual QUIC path.
	f := newFeedbackQUICFixtureWithTrace(t, 1, 2<<20, trace)
	trace.selectStream(f.clientStreams[0].StreamID())
	const warmupBytes = 1 << 20
	runPacingRecoveryPhase(t, f, "wide-window warmup", warmupBytes, 0, nil)
	gate := newFeedbackBackpressureGate(f.rawStreams[0], trace, warmupBytes)
	finished := make(chan struct{})
	writer := f.run(func() error {
		defer close(finished)
		return writeFeedbackPayload(f.serverStreams[0], 16*feedbackChunkSize)
	})
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	offset, err := gate.await(ctx, finished)
	if err == nil {
		t.Fatalf("unrestricted receive window established backpressure: stream=%d offset=%d", f.clientStreams[0].StreamID(), offset)
	}
	if ctx.Err() != nil {
		t.Fatalf("wide-window control did not reject a completed first Write before its deadline: %v", err)
	}
	select {
	case <-gate.first.done:
	default:
		t.Fatalf("wide-window control did not complete its first raw Write: %v", err)
	}
	if got := trace.highest(); got > warmupBytes {
		t.Fatalf("wide-window control received new blocking offset %d beyond warmup %d", got, warmupBytes)
	}
	// Drain every original slow byte and join the actual writer independently
	// even though the setup gate was rejected. Fixture cleanup joins on failure.
	if err := readFeedbackPayload(f.clientStreams[0], 16*feedbackChunkSize); err != nil {
		t.Fatal(err)
	}
	f.await(t, writer)
	f.checkReverse(t)
	t.Logf("wide-window negative control rejected without timeout: %v; verified %d slow bytes", err, 16*feedbackChunkSize)
}
