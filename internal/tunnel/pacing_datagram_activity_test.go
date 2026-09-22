package tunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/accel"
)

func TestQUICDatagramActivityCoversPacingWaitAndCancellation(t *testing.T) {
	clock := &datagramActivityClock{started: make(chan struct{})}
	controller, err := accel.New(accel.Config{
		Mode: accel.ModeFixedRate, FixedRateBytesPerSecond: 1, BurstBytes: 1, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Consume the initial burst. The next admission must enter the controlled
	// sleep and cannot reach SendDatagram before cancellation.
	if err := controller.Wait(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	pacer := &connectionPacer{controller: controller}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sendQUICDatagram(nil, pacer, queuedDatagram{ctx: ctx, frames: [][]byte{{1}, {2}}})
	}()
	select {
	case <-clock.started:
	case <-time.After(2 * time.Second):
		t.Fatal("datagram pacing wait did not start")
	}
	pacer.mu.Lock()
	active := pacer.activity.activeWrites
	before := pacer.activity.idleTime(time.Now())
	after := pacer.activity.idleTime(time.Now().Add(time.Second))
	pacer.mu.Unlock()
	if active != 1 || before != after {
		t.Fatalf("blocked datagram activity = %d, idle = %s -> %s; want one active sender and no idle accumulation", active, before, after)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("sendQUICDatagram error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not end datagram pacing wait")
	}
	pacer.mu.Lock()
	active = pacer.activity.activeWrites
	idleSince := pacer.activity.idleSince
	idleDelta := pacer.activity.idleTime(idleSince.Add(time.Second)) - pacer.activity.idle
	pacer.mu.Unlock()
	if active != 0 || idleSince.IsZero() || idleDelta != time.Second {
		t.Fatalf("finished datagram activity = %d, idleSince=%s, idleDelta=%s; want resumed idle accounting", active, idleSince, idleDelta)
	}
}

func TestQUICDatagramActivitySkipsCanceledAndEmptyBatches(t *testing.T) {
	cause := errors.New("canceled before send")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	for _, test := range []struct {
		name   string
		queued queuedDatagram
		want   error
	}{
		{name: "pre-canceled", queued: queuedDatagram{ctx: ctx, frames: [][]byte{{1}}}, want: cause},
		{name: "empty", queued: queuedDatagram{ctx: context.Background()}},
		{name: "empty pre-canceled", queued: queuedDatagram{ctx: ctx}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Seed an existing idle epoch: even a balanced begin/end would mutate
			// these timestamps and must be detected, not just an active-count leak.
			initial := pacingWriteActivity{idleSince: time.Unix(1, 0), idle: time.Millisecond}
			pacer := &connectionPacer{activity: initial}
			if err := sendQUICDatagram(nil, pacer, test.queued); !errors.Is(err, test.want) {
				t.Fatalf("sendQUICDatagram error = %v, want %v", err, test.want)
			}
			if pacer.activity != initial {
				t.Fatalf("skipped batch changed activity: got %+v, want %+v", pacer.activity, initial)
			}
		})
	}
}

// A fixed clock prevents real-time token refills. Sleep is cancellation-aware
// and announces admission without polling timing-dependent controller state.
type datagramActivityClock struct {
	started chan struct{}
	once    sync.Once
}

func (*datagramActivityClock) Now() time.Time { return time.Unix(1, 0) }

func (c *datagramActivityClock) Sleep(ctx context.Context, _ time.Duration) error {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return context.Cause(ctx)
}
