package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlogwriter"
)

// Each stream keeps its own copied blocked offset. Forwarding is synchronous,
// so neither observer retains library packet or frame pointers.
type feedbackSharedTrace struct{ streams [2]*feedbackBlockedTrace }

var _ qlogwriter.Trace = (*feedbackSharedTrace)(nil)
var _ qlogwriter.Recorder = (*feedbackSharedRecorder)(nil)

func newFeedbackSharedTrace() *feedbackSharedTrace {
	return &feedbackSharedTrace{streams: [2]*feedbackBlockedTrace{newFeedbackBlockedTrace(), newFeedbackBlockedTrace()}}
}

func (t *feedbackSharedTrace) SupportsSchemas(schema string) bool {
	return t.streams[0].SupportsSchemas(schema) && t.streams[1].SupportsSchemas(schema)
}

func (t *feedbackSharedTrace) AddProducer() qlogwriter.Recorder {
	return &feedbackSharedRecorder{trace: t}
}

func (t *feedbackSharedTrace) RecordEvent(event qlogwriter.Event) {
	for _, stream := range t.streams {
		stream.RecordEvent(event)
	}
}

func (*feedbackSharedTrace) Close() error { return nil }

type feedbackSharedRecorder struct{ trace *feedbackSharedTrace }

func (r *feedbackSharedRecorder) RecordEvent(event qlogwriter.Event) { r.trace.RecordEvent(event) }
func (*feedbackSharedRecorder) Close() error                         { return nil }

type feedbackSharedRawCall struct {
	owner     *feedbackSharedWitness
	ordinal   int
	done      chan struct{}
	completed bool // protected by owner.mu
}

type feedbackSharedWaitToken struct {
	owner   *feedbackSharedWitness
	ordinal int
}

type feedbackSharedReceipt struct {
	owner          *feedbackSharedWitness
	waitOrdinal    int
	rawCompleted   int
	completedBytes int
	target         int64
}

// The pointer and phase configuration are installed only after this stream's
// preceding writer joined, and never replaced while subsequent writers run.
// It observes calls; it never sleeps, gates I/O, or adds controller samples.
type feedbackSharedWitness struct {
	raw          *feedbackRawStream
	trace        *feedbackBlockedTrace
	warmupOffset int64
	checkpoint   int
	receipts     chan feedbackSharedReceipt // shared capacity-two FIFO, one value per stream
	changed      chan struct{}              // coalesced hints; never closed

	mu             sync.Mutex
	waits          int
	started        int
	completed      int
	completedBytes int
	current        *feedbackSharedRawCall
	receiptSent    bool
}

func newFeedbackSharedWitness(raw *feedbackRawStream, trace *feedbackBlockedTrace, warmup int64, checkpoint int, receipts chan feedbackSharedReceipt) *feedbackSharedWitness {
	return &feedbackSharedWitness{raw: raw, trace: trace, warmupOffset: warmup, checkpoint: checkpoint,
		receipts: receipts, changed: make(chan struct{}, 1)}
}

func (w *feedbackSharedWitness) notify() {
	select {
	case w.changed <- struct{}{}:
	default:
	}
}

func (w *feedbackSharedWitness) rawStarted() *feedbackSharedRawCall {
	w.mu.Lock()
	w.started++
	call := &feedbackSharedRawCall{owner: w, ordinal: w.started, done: make(chan struct{})}
	w.current = call
	w.mu.Unlock()
	w.notify()
	return call
}

func (w *feedbackSharedWitness) rawFinished(call *feedbackSharedRawCall, n int, _ error) {
	w.mu.Lock()
	if call.owner == w && !call.completed {
		call.completed = true
		w.completed++
		w.completedBytes += n
		close(call.done)
	}
	w.mu.Unlock()
	w.notify()
}

func (w *feedbackSharedWitness) waitStarted() feedbackSharedWaitToken {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.waits++
	return feedbackSharedWaitToken{owner: w, ordinal: w.waits}
}

// Called only after the underlying production wait returned. Target is a live
// read after Observe/Wait, not an atomic result of that individual Observe.
func (w *feedbackSharedWitness) waitReturned(token feedbackSharedWaitToken, err error, target int64) {
	w.mu.Lock()
	if token.owner != w || token.ordinal != w.checkpoint+1 || err != nil || w.receiptSent {
		w.mu.Unlock()
		return
	}
	w.receiptSent = true
	receipt := feedbackSharedReceipt{owner: w, waitOrdinal: token.ordinal, rawCompleted: w.completed,
		completedBytes: w.completedBytes, target: target}
	w.mu.Unlock()
	// Capacity two holds exactly the two selected successful returns. FIFO
	// arrival order, not a lower target or select between buffered queues,
	// determines the final prescribed receipt.
	select {
	case w.receipts <- receipt:
	default:
	}
}

func (w *feedbackSharedWitness) pendingCall(ordinal int) (*feedbackSharedRawCall, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started < ordinal {
		return nil, nil
	}
	if w.started != ordinal || w.completed != ordinal-1 || w.completedBytes != (ordinal-1)*feedbackChunkSize {
		return nil, fmt.Errorf("raw call %d replaced or completed: started=%d completed=%d bytes=%d", ordinal, w.started, w.completed, w.completedBytes)
	}
	call := w.current
	if call == nil || call.ordinal != ordinal || call.completed || !w.raw.pending.Load() {
		return nil, fmt.Errorf("raw call %d is not pending", ordinal)
	}
	return call, nil
}

func (w *feedbackSharedWitness) awaitRaw(ctx context.Context, finished <-chan struct{}, ordinal int, offsetAfter int64) (int64, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		select {
		case <-finished:
			return 0, errors.New("phase writer finished before prescribed pending Write")
		default:
		}
		call, err := w.pendingCall(ordinal)
		if err != nil {
			return 0, err
		}
		var done <-chan struct{}
		if call != nil {
			done = call.done
			if offset := w.trace.highest(); offset > offsetAfter {
				// Recheck after the actual received-frame evidence. A later raw
				// call cannot stand in for the prescribed call's completion.
				if current, err := w.pendingCall(ordinal); err != nil || current != call {
					return 0, fmt.Errorf("raw call changed while checking blocked frame: %v", err)
				}
				select {
				case <-done:
					return 0, errors.New("prescribed raw Write completed at blocked-frame witness")
				case <-finished:
					return 0, errors.New("phase writer completed at blocked-frame witness")
				default:
					return offset, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-finished:
			return 0, errors.New("phase writer finished before prescribed pending Write")
		case <-done:
			return 0, errors.New("prescribed raw Write completed before fresh blocked frame")
		case <-w.changed:
		case <-w.trace.changed:
		}
	}
}

func awaitFeedbackSharedReceipts(ctx context.Context, witnesses [2]*feedbackSharedWitness, finished [2]<-chan struct{}) ([2]feedbackSharedReceipt, error) {
	var result [2]feedbackSharedReceipt
	if witnesses[0].receipts != witnesses[1].receipts {
		return result, errors.New("stream receipts do not share an arrival-order queue")
	}
	seen := make(map[*feedbackSharedWitness]bool, 2)
	for index := range result {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-finished[0]:
			return result, errors.New("primary phase finished before feedback checkpoint")
		case <-finished[1]:
			return result, errors.New("sibling phase finished before feedback checkpoint")
		case receipt := <-witnesses[0].receipts:
			owner := receipt.owner
			if (owner != witnesses[0] && owner != witnesses[1]) || seen[owner] {
				return result, errors.New("foreign or duplicate phase receipt")
			}
			if receipt.waitOrdinal != owner.checkpoint+1 || receipt.rawCompleted != owner.checkpoint || receipt.completedBytes != owner.checkpoint*feedbackChunkSize {
				return result, fmt.Errorf("invalid feedback checkpoint receipt: wait=%d raw_completed=%d bytes=%d", receipt.waitOrdinal, receipt.rawCompleted, receipt.completedBytes)
			}
			seen[owner] = true
			result[index] = receipt
		}
	}
	return result, nil
}

func feedbackSharedReceiptFor(receipts [2]feedbackSharedReceipt, witness *feedbackSharedWitness) feedbackSharedReceipt {
	for _, receipt := range receipts {
		if receipt.owner == witness {
			return receipt
		}
	}
	return feedbackSharedReceipt{}
}

func feedbackSharedUnitWitness(checkpoint int, receipts chan feedbackSharedReceipt) *feedbackSharedWitness {
	trace := newFeedbackBlockedTrace()
	trace.selectStream(0)
	return newFeedbackSharedWitness(&feedbackRawStream{}, trace, 1<<20, checkpoint, receipts)
}

func feedbackSharedCompleteRaw(w *feedbackSharedWitness, count int) {
	for range count {
		call := w.rawStarted()
		w.rawFinished(call, feedbackChunkSize, nil)
	}
}

func TestFeedbackSharedReceiptRequiresSuccessfulPrescribedReturn(t *testing.T) {
	for _, mode := range []string{"entry-only", "earlier-ordinal", "old-phase", "failed-return", "selected-return", "duplicate-return"} {
		t.Run(mode, func(t *testing.T) {
			w := feedbackSharedUnitWitness(10, make(chan feedbackSharedReceipt, 2))
			feedbackSharedCompleteRaw(w, 10)
			var token feedbackSharedWaitToken
			for range 11 {
				token = w.waitStarted()
			}
			switch mode {
			case "entry-only":
			case "earlier-ordinal":
				token.ordinal = 10
				w.waitReturned(token, nil, 101)
			case "old-phase":
				token.owner = feedbackSharedUnitWitness(10, make(chan feedbackSharedReceipt, 2))
				w.waitReturned(token, nil, 101)
			case "failed-return":
				w.waitReturned(token, context.Canceled, 101)
			default:
				w.waitReturned(token, nil, 101)
				if mode == "duplicate-return" {
					w.waitReturned(token, nil, 1)
				}
			}
			select {
			case receipt := <-w.receipts:
				if mode != "selected-return" && mode != "duplicate-return" {
					t.Fatalf("%s produced a checkpoint receipt", mode)
				}
				if receipt.target != 101 || receipt.rawCompleted != 10 || receipt.completedBytes != 10*feedbackChunkSize {
					t.Fatalf("wrong selected receipt: %+v", receipt)
				}
			default:
				if mode == "selected-return" || mode == "duplicate-return" {
					t.Fatal("successful prescribed return did not publish")
				}
			}
			select {
			case <-w.receipts:
				t.Fatal("observer published more than one receipt")
			default:
			}
		})
	}
}

func TestFeedbackSharedCheckpointValidatesReceiptAndArrivalOrder(t *testing.T) {
	for _, mode := range []string{"valid", "old-phase", "duplicate-phase", "wrong-ordinal", "prior-incomplete", "wrong-bytes", "missing"} {
		t.Run(mode, func(t *testing.T) {
			queue := make(chan feedbackSharedReceipt, 2)
			first, second := feedbackSharedUnitWitness(10, queue), feedbackSharedUnitWitness(10, queue)
			one := feedbackSharedReceipt{owner: first, waitOrdinal: 11, rawCompleted: 10, completedBytes: 10 * feedbackChunkSize, target: 1}
			two := one
			two.owner, two.target = second, 100 // Last arrival must win, not the minimum.
			switch mode {
			case "old-phase":
				one.owner = feedbackSharedUnitWitness(10, queue)
			case "duplicate-phase":
				two.owner = first
			case "wrong-ordinal":
				one.waitOrdinal = 10
			case "prior-incomplete":
				one.rawCompleted = 9
			case "wrong-bytes":
				one.completedBytes--
			}
			queue <- one
			if mode != "missing" {
				queue <- two
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			receipts, err := awaitFeedbackSharedReceipts(ctx, [2]*feedbackSharedWitness{first, second}, [2]<-chan struct{}{make(chan struct{}), make(chan struct{})})
			if mode == "valid" {
				if err != nil || receipts[1].target != 100 || receipts[1].owner != second {
					t.Fatalf("fixed arrival-order checkpoint: receipts=%+v err=%v", receipts, err)
				}
			} else if err == nil {
				t.Fatalf("%s receipt was accepted", mode)
			} else if mode == "missing" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("missing receipt did not wait to its bounded deadline: %v", err)
			}
		})
	}
}

func TestFeedbackSharedRawGateRequiresExactPendingCall(t *testing.T) {
	for _, mode := range []string{"first", "checkpoint", "later-call", "earlier-call", "equal-offset", "not-pending", "short-prior-write", "missing-call", "phase-finished"} {
		t.Run(mode, func(t *testing.T) {
			w := feedbackSharedUnitWitness(10, make(chan feedbackSharedReceipt, 2))
			ordinal := 11
			if mode == "first" {
				ordinal = 1
			}
			if mode != "missing-call" {
				feedbackSharedCompleteRaw(w, ordinal-1)
				if mode == "short-prior-write" {
					w.completedBytes--
				}
				call := w.rawStarted()
				if mode == "later-call" {
					w.rawFinished(call, feedbackChunkSize, nil)
					w.rawStarted() // This pending later Write must not substitute.
				} else if mode == "earlier-call" {
					ordinal++
				}
				w.raw.pending.Store(mode != "not-pending")
			}
			threshold := w.warmupOffset + int64((ordinal-1)*feedbackChunkSize)
			maximum := threshold + (16 << 10)
			if mode == "equal-offset" {
				maximum = threshold
			}
			w.trace.RecordEvent(feedbackBlockedPacket(0, maximum))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			finished := make(chan struct{})
			if mode == "phase-finished" {
				close(finished)
			}
			offset, err := w.awaitRaw(ctx, finished, ordinal, threshold)
			if mode == "first" || mode == "checkpoint" {
				if err != nil || offset != maximum {
					t.Fatalf("fresh prescribed pending call: offset=%d err=%v", offset, err)
				}
			} else if err == nil {
				t.Fatalf("%s established a prescribed raw-call witness", mode)
			} else if (mode == "equal-offset" || mode == "missing-call" || mode == "earlier-call") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s missing evidence did not remain bounded: %v", mode, err)
			}
		})
	}
}

func TestFeedbackSharedTraceSeparatesStreamsAndProducerLifetimes(t *testing.T) {
	trace := newFeedbackSharedTrace()
	trace.streams[0].selectStream(0)
	trace.streams[1].selectStream(4)
	first, second := trace.AddProducer(), trace.AddProducer()
	first.RecordEvent(feedbackBlockedPacket(0, 1024))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second.RecordEvent(feedbackBlockedPacket(4, 2048))
	second.RecordEvent(feedbackBlockedPacket(8, 1<<20))
	if got := trace.streams[0].highest(); got != 1024 {
		t.Fatalf("primary stream maximum = %d", got)
	}
	if got := trace.streams[1].highest(); got != 2048 {
		t.Fatalf("sibling stream maximum = %d", got)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := trace.Close(); err != nil {
		t.Fatal(err)
	}
}
