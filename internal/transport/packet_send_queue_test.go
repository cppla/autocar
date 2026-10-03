package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const packetQueueTestTargetBytes = 128 << 10

type packetQueueTestEvent struct {
	address string
	payload string
	ctx     context.Context
}

type packetQueueTestGate struct {
	done chan struct{}
	once sync.Once
}

func (g *packetQueueTestGate) release() { g.once.Do(func() { close(g.done) }) }

type packetQueueTestFixture struct {
	t          *testing.T
	ctx        context.Context
	cancel     context.CancelFunc
	gates      []*packetQueueTestGate
	queues     []*PacketSendQueue
	auxJoined  []<-chan struct{}
	unexpected atomic.Int32
}

func newPacketQueueTestFixture(t *testing.T) *packetQueueTestFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	f := &packetQueueTestFixture{t: t, ctx: ctx, cancel: cancel}
	t.Cleanup(func() {
		f.cancel()
		for _, gate := range f.gates {
			gate.release()
		}
		for _, q := range f.queues {
			joined := make(chan struct{})
			go func(q *PacketSendQueue) {
				q.Stop()
				q.Wait()
				close(joined)
			}(q)
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Error("packet queue cleanup did not join its callbacks")
			}
		}
		for _, joined := range f.auxJoined {
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Error("packet queue fixture caller did not join")
			}
		}
		if got := f.unexpected.Load(); got != 0 {
			t.Errorf("unexpected callback event/error count=%d", got)
		}
	})
	return f
}

func (f *packetQueueTestFixture) gate() *packetQueueTestGate {
	g := &packetQueueTestGate{done: make(chan struct{})}
	f.gates = append(f.gates, g)
	return g
}

func (f *packetQueueTestFixture) queue(maxPackets, maxTargets int, send func(context.Context, []byte, string) error) *PacketSendQueue {
	q := NewPacketSendQueue(f.ctx, maxPackets, maxTargets, send)
	f.queues = append(f.queues, q)
	return q
}

func (f *packetQueueTestFixture) publish(ch chan<- packetQueueTestEvent, event packetQueueTestEvent) {
	select {
	case ch <- event:
	default:
		f.unexpected.Add(1)
	}
}

func (f *packetQueueTestFixture) next(ch <-chan packetQueueTestEvent, label string) packetQueueTestEvent {
	f.t.Helper()
	select {
	case event := <-ch:
		return event
	case <-time.After(2 * time.Second):
		f.t.Fatalf("missing %s callback witness", label)
	case <-f.ctx.Done():
		f.t.Fatalf("fixture ended waiting for %s: %v", label, context.Cause(f.ctx))
	}
	return packetQueueTestEvent{}
}

func (f *packetQueueTestFixture) enqueue(q *PacketSendQueue, payload []byte, address string) {
	f.t.Helper()
	if err := q.Enqueue(payload, address); err != nil {
		f.t.Fatalf("Enqueue(payloadBytes=%d, addressBytes=%d): %v", len(payload), len(address), err)
	}
}

func (f *packetQueueTestFixture) wantFull(q *PacketSendQueue, payload []byte, address string) {
	f.t.Helper()
	if err := q.Enqueue(payload, address); !errors.Is(err, ErrPacketQueueFull) {
		f.t.Errorf("Enqueue rejected budget with %v, want ErrPacketQueueFull", err)
	}
}

func (f *packetQueueTestFixture) stopJoin(q *PacketSendQueue) {
	f.t.Helper()
	joined := make(chan struct{})
	f.auxJoined = append(f.auxJoined, joined)
	go func() { q.Stop(); q.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		f.t.Fatal("Stop/Wait did not join packet callbacks")
	}
}

func (f *packetQueueTestFixture) stop(q *PacketSendQueue) {
	f.t.Helper()
	joined := make(chan struct{})
	f.auxJoined = append(f.auxJoined, joined)
	go func() { q.Stop(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		f.t.Fatal("Stop waited for a controlled active callback instead of returning")
	}
}

// A callback's completion notification precedes its return. Observe idle-lane
// pruning through public admission, not a private map or a scheduling sleep.
// Only rejected Enqueues are retried; an accepted packet is never retried.
func (f *packetQueueTestFixture) enqueueAfterRetirement(q *PacketSendQueue, payload []byte, address string) {
	f.t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		err := q.Enqueue(payload, address)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrPacketQueueFull) {
			f.t.Fatalf("admission after completed callback: %v", err)
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			f.t.Fatal("completed target lane retained capacity")
		case <-f.ctx.Done():
			f.t.Fatalf("fixture ended before lane retirement: %v", context.Cause(f.ctx))
		}
	}
}

func packetQueueTestNoError(t *testing.T, q *PacketSendQueue) {
	t.Helper()
	select {
	case err, ok := <-q.Errors():
		t.Errorf("Errors received value=%v open=%t, want open empty channel", err, ok)
	default:
	}
}

func TestPacketSendQueueIsolatesTargetsAndPreservesFIFO(t *testing.T) {
	f := newPacketQueueTestFixture(t)
	first, other := f.gate(), f.gate()
	started := make(chan packetQueueTestEvent, 8)
	q := f.queue(8, 3, func(ctx context.Context, payload []byte, address string) error {
		f.publish(started, packetQueueTestEvent{address: address, payload: string(payload), ctx: ctx})
		var gate *packetQueueTestGate
		if address == "a:1" && string(payload) == "a1" {
			gate = first
		} else if address == "b:2" {
			gate = other
		}
		if gate != nil {
			select {
			case <-gate.done:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		return nil
	})
	f.enqueue(q, []byte("a1"), "a:1")
	if event := f.next(started, "blocked a1"); event.address != "a:1" || event.payload != "a1" {
		t.Fatalf("first callback=%+v", event)
	}
	f.enqueue(q, []byte("a2"), "a:1")
	f.enqueue(q, []byte("a3"), "a:1")
	f.enqueue(q, []byte("b1"), "b:2")
	if event := f.next(started, "independent b1"); event.address != "b:2" || event.payload != "b1" {
		t.Fatalf("callback while a1 blocked=%+v, want b1", event)
	}
	select {
	case event := <-started:
		t.Errorf("same-target callback overlapped blocked a1: %+v", event)
	case <-time.After(50 * time.Millisecond):
	}
	first.release()
	for _, want := range []string{"a2", "a3"} {
		if event := f.next(started, want); event.address != "a:1" || event.payload != want {
			t.Errorf("same-target FIFO callback=%+v, want %s", event, want)
		}
	}
	other.release()
	f.stopJoin(q)
	packetQueueTestNoError(t, q)
	select {
	case event := <-started:
		t.Errorf("unexpected retry/extra callback=%+v", event)
	default:
	}
}

func TestPacketSendQueueBudgetsIncludeActivePackets(t *testing.T) {
	t.Run("nonpositive-packet-normalization", func(t *testing.T) {
		for _, maxPackets := range []int{0, -1} {
			t.Run(fmt.Sprintf("packets-%d", maxPackets), func(t *testing.T) {
				f := newPacketQueueTestFixture(t)
				seen := make(chan packetQueueTestEvent, 2)
				q := f.queue(maxPackets, 0, func(ctx context.Context, _ []byte, address string) error {
					f.publish(seen, packetQueueTestEvent{address: address})
					<-ctx.Done()
					return context.Cause(ctx)
				})
				f.enqueue(q, nil, "a:1")
				f.next(seen, "normalized single active packet")
				f.wantFull(q, nil, "a:1")
				f.wantFull(q, nil, "b:2")
				f.stopJoin(q)
				packetQueueTestNoError(t, q)
			})
		}
	})
	t.Run("target-ceiling-and-default", func(t *testing.T) {
		for _, maxTargets := range []int{0, -1, 9} {
			t.Run(fmt.Sprintf("targets-%d", maxTargets), func(t *testing.T) {
				f := newPacketQueueTestFixture(t)
				seen := make(chan packetQueueTestEvent, 16)
				q := f.queue(32, maxTargets, func(ctx context.Context, _ []byte, address string) error {
					f.publish(seen, packetQueueTestEvent{address: address})
					<-ctx.Done()
					return context.Cause(ctx)
				})
				for index := 0; index < 8; index++ {
					f.enqueue(q, nil, fmt.Sprintf("active-%d:1", index))
					f.next(seen, "eight-target callback ceiling")
				}
				f.wantFull(q, nil, "ninth:1")
				f.stopJoin(q)
				packetQueueTestNoError(t, q)
			})
		}
	})
	t.Run("packets", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		started := make(chan packetQueueTestEvent, 8)
		q := f.queue(4, 3, func(ctx context.Context, payload []byte, address string) error {
			f.publish(started, packetQueueTestEvent{address: address, payload: string(payload)})
			select {
			case <-gate.done:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
		f.enqueue(q, []byte("a1"), "a:1")
		f.next(started, "active a1")
		f.enqueue(q, []byte("a2"), "a:1")
		f.wantFull(q, []byte("a3"), "a:1") // ceil(4/2), though global space remains.
		f.enqueue(q, []byte("b1"), "b:2")
		f.next(started, "active b1")
		f.enqueue(q, []byte("b2"), "b:2")
		f.wantFull(q, []byte("c1"), "c:3") // Four total, including both active callbacks.
		f.stopJoin(q)
		packetQueueTestNoError(t, q)
	})
	t.Run("target-bytes", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		started := make(chan packetQueueTestEvent, 8)
		q := f.queue(8, 3, func(ctx context.Context, _ []byte, address string) error {
			f.publish(started, packetQueueTestEvent{address: address})
			select {
			case <-gate.done:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
		f.enqueue(q, make([]byte, packetQueueTestTargetBytes-len("a:1")), "a:1")
		f.next(started, "active full-byte a")
		f.wantFull(q, nil, "a:1")
		f.enqueue(q, []byte("other target still fits"), "b:2")
		f.next(started, "independent byte budget")
		f.stopJoin(q)
		packetQueueTestNoError(t, q)
	})
	t.Run("global-bytes", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		started := make(chan packetQueueTestEvent, 8)
		q := f.queue(8, 3, func(ctx context.Context, _ []byte, address string) error {
			f.publish(started, packetQueueTestEvent{address: address})
			select {
			case <-gate.done:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
		for _, address := range []string{"a:1", "b:2"} {
			f.enqueue(q, make([]byte, packetQueueTestTargetBytes-len(address)), address)
			f.next(started, "active global-byte charge")
		}
		f.wantFull(q, nil, "c:3") // 256 KiB is charged while callbacks remain active.
		f.stopJoin(q)
		packetQueueTestNoError(t, q)
	})
}

func TestPacketSendQueueOwnsPayloadAndRetiresTargets(t *testing.T) {
	f := newPacketQueueTestFixture(t)
	gate := f.gate()
	started, observed := make(chan packetQueueTestEvent, 32), make(chan packetQueueTestEvent, 32)
	q := f.queue(4, 1, func(ctx context.Context, payload []byte, address string) error {
		f.publish(started, packetQueueTestEvent{address: address})
		if address == "a:1" {
			select {
			case <-gate.done:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		f.publish(observed, packetQueueTestEvent{address: address, payload: string(payload)})
		return nil
	})
	payload := []byte("owned-original")
	f.enqueue(q, payload, "a:1")
	f.next(started, "copy callback admission")
	copy(payload, "caller-mutated")
	f.wantFull(q, []byte("b"), "b:2") // A live target occupies the only target slot.
	gate.release()
	if event := f.next(observed, "owned payload"); event.payload != "owned-original" {
		t.Errorf("callback payload=%q, want the Enqueue-owned copy", event.payload)
	}
	for index := 0; index < 12; index++ {
		address := fmt.Sprintf("retired-%d:2", index)
		f.enqueueAfterRetirement(q, []byte("next"), address)
		if event := f.next(started, "replacement target"); event.address != address {
			t.Errorf("replacement callback address=%q, want %q", event.address, address)
		}
		if event := f.next(observed, "replacement completion"); event.address != address || event.payload != "next" {
			t.Errorf("replacement callback=%+v", event)
		}
	}
	f.stopJoin(q)
	packetQueueTestNoError(t, q)
}

func TestPacketSendQueueErrorsDoNotRetry(t *testing.T) {
	t.Run("recoverable", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		seen := make(chan packetQueueTestEvent, 8)
		q := f.queue(8, 1, func(_ context.Context, payload []byte, address string) error {
			f.publish(seen, packetQueueTestEvent{address: address, payload: string(payload)})
			switch string(payload) {
			case "queue-full":
				return fmt.Errorf("owned send: %w", ErrPacketQueueFull)
			case "target-unavailable":
				return fmt.Errorf("owned send: %w", ErrPacketTargetUnavailable)
			default:
				return nil
			}
		})
		for _, payload := range []string{"queue-full", "target-unavailable", "healthy"} {
			f.enqueue(q, []byte(payload), "a:1")
		}
		for _, want := range []string{"queue-full", "target-unavailable", "healthy"} {
			if event := f.next(seen, want); event.payload != want {
				t.Errorf("callback=%+v, want %s once in FIFO order", event, want)
			}
		}
		f.stopJoin(q)
		packetQueueTestNoError(t, q)
		select {
		case event := <-seen:
			t.Errorf("recoverable send was retried: %+v", event)
		default:
		}
	})
	t.Run("terminal", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		seen := make(chan packetQueueTestEvent, 8)
		want := errors.New("owned terminal send failure")
		q := f.queue(8, 1, func(_ context.Context, payload []byte, address string) error {
			f.publish(seen, packetQueueTestEvent{address: address, payload: string(payload)})
			<-gate.done
			return want
		})
		f.enqueue(q, []byte("active"), "a:1")
		f.next(seen, "terminal callback")
		f.enqueue(q, []byte("must-drop"), "a:1")
		gate.release()
		select {
		case err, ok := <-q.Errors():
			if !ok || err != want {
				t.Errorf("terminal Errors value=%v open=%t, want exact original error", err, ok)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("terminal callback did not publish its error")
		}
		if err := q.Enqueue(nil, "b:2"); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Enqueue after terminal error=%v, want automatic Stop/net.ErrClosed", err)
		}
		f.stopJoin(q)
		packetQueueTestNoError(t, q)
		select {
		case event := <-seen:
			t.Errorf("terminal/queued packet callback repeated: %+v", event)
		default:
		}
	})
}

func TestPacketSendQueueStopJoinsAndRejectsEnqueue(t *testing.T) {
	t.Run("active-join", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		seen := make(chan packetQueueTestEvent, 8)
		q := f.queue(4, 2, func(ctx context.Context, payload []byte, address string) error {
			f.publish(seen, packetQueueTestEvent{address: address, payload: string(payload), ctx: ctx})
			<-gate.done // Deliberately return only when independently released.
			return errors.New("controlled callback returned after Stop")
		})
		var active []packetQueueTestEvent
		for _, address := range []string{"a:1", "b:2"} {
			f.enqueue(q, []byte("active"), address)
			active = append(active, f.next(seen, "active callback"))
			f.enqueue(q, []byte("must-drop"), address)
		}
		f.stop(q)
		for _, event := range active {
			if event.ctx.Err() == nil {
				t.Error("Stop did not cancel an active callback's context")
			}
		}
		if err := q.Enqueue(nil, "new:3"); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Enqueue after Stop=%v, want net.ErrClosed", err)
		}
		waiting, joined := make(chan struct{}, 2), make(chan struct{}, 2)
		for index := 0; index < 2; index++ {
			callerJoined := make(chan struct{})
			f.auxJoined = append(f.auxJoined, callerJoined)
			go func() {
				defer close(callerJoined)
				waiting <- struct{}{}
				q.Wait()
				joined <- struct{}{}
			}()
		}
		for index := 0; index < 2; index++ {
			select {
			case <-waiting:
			case <-time.After(2 * time.Second):
				t.Fatal("concurrent Wait worker did not start")
			}
		}
		alreadyJoined := 0
		select {
		case <-joined:
			alreadyJoined++
			t.Error("Wait returned while active callbacks remained gated")
		case <-time.After(50 * time.Millisecond):
		}
		gate.release()
		for index := alreadyJoined; index < 2; index++ {
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Fatal("concurrent Wait did not join released callbacks")
			}
		}
		packetQueueTestNoError(t, q) // Shutdown callback errors are suppressed.
		select {
		case event := <-seen:
			t.Errorf("Stop ran a queued packet: %+v", event)
		default:
		}
	})
	t.Run("parent-cancellation", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		parent, cancel := context.WithCancelCause(f.ctx)
		defer cancel(nil)
		seen := make(chan packetQueueTestEvent, 2)
		q := NewPacketSendQueue(parent, 4, 2, func(ctx context.Context, _ []byte, address string) error {
			f.publish(seen, packetQueueTestEvent{address: address, ctx: ctx})
			<-ctx.Done()
			return context.Cause(ctx)
		})
		f.queues = append(f.queues, q)
		f.enqueue(q, []byte("active"), "a:1")
		event := f.next(seen, "parent-owned callback")
		want := errors.New("private parent cancellation")
		cancel(want)
		<-parent.Done()
		f.stopJoin(q)
		if got := context.Cause(event.ctx); got != want {
			t.Errorf("callback context cause=%v, want exact parent cause", got)
		}
		if err := q.Enqueue(nil, "b:2"); !errors.Is(err, net.ErrClosed) {
			t.Errorf("canceled queue Enqueue=%v, want net.ErrClosed", err)
		}
		packetQueueTestNoError(t, q)
	})
	t.Run("stop-versus-enqueue", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		seen := make(chan packetQueueTestEvent, 8)
		q := f.queue(16, 4, func(ctx context.Context, _ []byte, address string) error {
			f.publish(seen, packetQueueTestEvent{address: address})
			<-ctx.Done()
			return context.Cause(ctx)
		})
		f.enqueue(q, []byte("already-active"), "lane-0:1")
		f.next(seen, "active callback before concurrent Stop/Enqueue")
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(5)
		for index := 0; index < 4; index++ {
			go func(index int) {
				defer workers.Done()
				<-start
				for packet := 0; packet < 64; packet++ {
					err := q.Enqueue([]byte{byte(packet)}, fmt.Sprintf("lane-%d:1", index))
					if err != nil && !errors.Is(err, ErrPacketQueueFull) && !errors.Is(err, net.ErrClosed) {
						f.unexpected.Add(1)
					}
				}
			}(index)
		}
		go func() { defer workers.Done(); <-start; q.Stop() }()
		close(start)
		joined := make(chan struct{})
		f.auxJoined = append(f.auxJoined, joined)
		go func() { workers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Stop/Enqueue callers did not join")
		}
		f.stopJoin(q)
		if err := q.Enqueue(nil, "later:1"); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Enqueue after joined Stop=%v, want net.ErrClosed", err)
		}
		packetQueueTestNoError(t, q)
	})
}

func TestPacketSendQueueAddressAndZeroPayloadAreCharged(t *testing.T) {
	t.Run("address-bytes", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		seen := make(chan packetQueueTestEvent, 4)
		q := f.queue(8, 3, func(ctx context.Context, _ []byte, address string) error {
			f.publish(seen, packetQueueTestEvent{address: address})
			select {
			case <-gate.done:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
		first, second := strings.Repeat("a", packetQueueTestTargetBytes), strings.Repeat("b", packetQueueTestTargetBytes)
		f.enqueue(q, nil, first)
		f.next(seen, "empty-payload address charge")
		f.wantFull(q, nil, first)
		f.enqueue(q, nil, second)
		f.next(seen, "second address charge")
		f.wantFull(q, nil, "c")
		f.stopJoin(q)
		packetQueueTestNoError(t, q)
	})
	t.Run("minimum-one-byte", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		gate := f.gate()
		var callbacks atomic.Int32
		seen := make(chan packetQueueTestEvent, 2)
		// The packet quota deliberately leaves one spare slot after 128 KiB
		// zero-byte packets; only minimum-one-byte accounting can reject next.
		q := f.queue(2*(packetQueueTestTargetBytes+1), 1, func(ctx context.Context, _ []byte, _ string) error {
			callbacks.Add(1)
			f.publish(seen, packetQueueTestEvent{ctx: ctx})
			select {
			case <-gate.done:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
		f.enqueue(q, nil, "")
		f.next(seen, "one active zero-byte packet")
		for index := 1; index < packetQueueTestTargetBytes; index++ {
			f.enqueue(q, nil, "")
		}
		f.wantFull(q, nil, "")
		f.stopJoin(q)
		if got := callbacks.Load(); got != 1 {
			t.Errorf("Stop processed queued zero-byte packets: callbacks=%d, want 1", got)
		}
		packetQueueTestNoError(t, q)
	})
	t.Run("oversized-and-combined", func(t *testing.T) {
		f := newPacketQueueTestFixture(t)
		var callbacks atomic.Int32
		q := f.queue(8, 2, func(context.Context, []byte, string) error { callbacks.Add(1); return nil })
		f.wantFull(q, make([]byte, packetQueueTestTargetBytes+1), "a")
		f.wantFull(q, nil, strings.Repeat("a", packetQueueTestTargetBytes+1))
		f.wantFull(q, make([]byte, packetQueueTestTargetBytes), "a")
		f.stopJoin(q)
		if got := callbacks.Load(); got != 0 {
			t.Errorf("oversized packet started callbacks=%d", got)
		}
		packetQueueTestNoError(t, q)
	})
}
