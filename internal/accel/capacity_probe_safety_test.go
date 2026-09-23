package accel

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestCapacityProbeSafetyAdmissionBounds(t *testing.T) {
	for _, test := range []struct {
		name     string
		capacity int64
		burst    int64
		maximum  int64
		rtt      time.Duration
		want     bool
	}{
		{name: "ordinary", capacity: 1_000_000, burst: 64 << 10, want: true},
		{name: "window_scaled_budget", capacity: 20_000_000, burst: 64 << 10, want: true},
		{name: "exact_budget_limit", capacity: 41_943_040, burst: 64 << 10, want: true},
		{name: "over_budget_limit", capacity: 41_943_041, burst: 64 << 10},
		{name: "exact_burst_limit", capacity: 1_000_000, burst: 512 << 10, want: true},
		{name: "over_burst_limit", capacity: 1_000_000, burst: 512<<10 + 1},
		{name: "chunk_too_slow", capacity: 100_000, burst: 512 << 10},
		{name: "maximum_prevents_uplift", capacity: 1_000_000, burst: 64 << 10, maximum: 1_000_000},
		{name: "duration_does_not_overflow", capacity: 1_000_000, burst: 64 << 10, rtt: time.Duration(math.MaxInt64), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock()
			controller := newProbeSafetyController(t, clock, test.capacity, test.burst, test.maximum)
			rtt := test.rtt
			if rtt == 0 {
				rtt = 4 * time.Millisecond
			}
			qualifyProbeSafety(t, controller, clock, []time.Duration{rtt, rtt, rtt})
			probe := controller.probe
			if probe.active != test.want {
				t.Fatalf("probe active=%t, want %t: %+v", probe.active, test.want, probe)
			}
			if !test.want {
				return
			}
			if probe.remaining > maximumProbeBytes || probe.remaining < 2*controller.burst {
				t.Fatalf("probe budget=%g, burst=%g", probe.remaining, controller.burst)
			}
			if probe.rate <= test.capacity || probe.rate > controller.maximumRate || probe.rate > 2*controller.targetRate {
				t.Fatalf("probe rate=%d capacity=%d steady=%d maximum=%d", probe.rate, test.capacity, controller.targetRate, controller.maximumRate)
			}
			if duration := probe.deadline.Sub(clock.Now()); duration < 100*time.Millisecond || duration > maximumProbeDuration {
				t.Fatalf("probe duration=%s", duration)
			}
			if probe.gap < minimumProbeGap || probe.gap > maximumProbeBackoff {
				t.Fatalf("probe gap=%s", probe.gap)
			}
			if controller.TargetBytesPerSecond() != int64(float64(test.capacity)*.648) {
				t.Fatal("probe changed the reported steady target")
			}
		})
	}
}

func TestCapacityProbeSafetyQualificationRejectsRisingRTT(t *testing.T) {
	clock := newFakeClock()
	controller := newProbeSafetyController(t, clock, 1_000_000, 64<<10, 0)
	qualifyProbeSafety(t, controller, clock, []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond})
	if controller.probe.active {
		t.Fatal("probe started while qualifying observations showed a growing queue")
	}
}

func TestCapacityProbeSafetySubwindowRTTResetsQualification(t *testing.T) {
	clock := newFakeClock()
	controller := newProbeSafetyController(t, clock, 1000, 100, 0)
	qualifyProbeSafety(t, controller, clock, []time.Duration{4 * time.Millisecond, 4 * time.Millisecond})
	baseline := Snapshot{At: clock.Now(), MinRTT: time.Millisecond, SmoothedRTT: 4 * time.Millisecond}
	mustObserveIdleSnapshot(t, controller, baseline)
	if err := clock.Sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	snapshot := baseline
	snapshot.At, snapshot.SmoothedRTT = clock.Now(), 6*time.Millisecond
	mustObserveIdleSnapshot(t, controller, snapshot)
	if controller.probe.active || controller.probe.eligibleSamples != 0 || controller.previous != baseline {
		t.Fatalf("early RTT rise did not clear qualification without consuming baseline: %+v", controller.probe)
	}
}

func TestCapacityProbeSafetySharedAdmissionBudget(t *testing.T) {
	for _, test := range []struct {
		name        string
		budget      float64
		probeChunks int
	}{
		{name: "exact_chunks", budget: 200, probeChunks: 2},
		{name: "no_partial_chunk_overshoot", budget: 150, probeChunks: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock()
			controller := newProbeSafetyController(t, clock, 1000, 100, 0)
			startProbeSafety(controller, test.budget)
			started := clock.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var writers sync.WaitGroup
			errors := make(chan error, 3)
			for range 3 {
				writers.Add(1)
				go func() {
					defer writers.Done()
					errors <- controller.Wait(ctx, 100)
				}()
			}
			writers.Wait()
			close(errors)
			for err := range errors {
				if err != nil {
					t.Fatal(err)
				}
			}
			want := time.Duration(test.probeChunks)*durationForBytes(100, 1250) + time.Duration(3-test.probeChunks)*durationForBytes(100, 648)
			if elapsed := clock.Now().Sub(started); elapsed != want {
				t.Fatalf("shared admission elapsed=%s, want %s (only %d chunks may use probe rate)", elapsed, want, test.probeChunks)
			}
			if controller.probe.active || controller.probe.remaining != test.budget-float64(100*test.probeChunks) {
				t.Fatalf("shared budget not exhausted exactly once: %+v", controller.probe)
			}
		})
	}
}

func TestCapacityProbeSafetyEntryDoesNotMintTokensOrCapacity(t *testing.T) {
	clock := newFakeClock()
	controller := newProbeSafetyController(t, clock, 1000, 100, 0)
	qualifyProbeSafety(t, controller, clock, []time.Duration{4 * time.Millisecond, 4 * time.Millisecond})
	if err := clock.Sleep(context.Background(), 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	controller.refillLocked(clock.Now())
	controller.tokens = 17
	controller.observeProbeLocked(Snapshot{MinRTT: time.Millisecond, SmoothedRTT: 4 * time.Millisecond}, clock.Now(), true, false)
	controller.mu.Unlock()
	if !controller.probe.active || controller.tokens != 17 || controller.estimator.bandwidthEstimate() != 1000 || controller.TargetBytesPerSecond() != 648 {
		t.Fatalf("entry changed steady state: probe=%+v tokens=%g capacity=%g steady=%d", controller.probe, controller.tokens, controller.estimator.bandwidthEstimate(), controller.TargetBytesPerSecond())
	}
}

func TestCapacityProbeSafetyOversleepSplitsRefillWithoutObserve(t *testing.T) {
	clock := newPacingSleepClock()
	controller := newProbeSafetyController(t, clock, 1000, 1000, 0)
	controller.targetRate = 1000
	startProbeSafety(controller, 2000)
	controller.probe.rate = 2000
	controller.probe.deadline = clock.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Wait(ctx, 1000) }()
	first := clock.nextSleep(t)
	if first.duration != 100*time.Millisecond {
		t.Fatalf("first sleep=%s, want probe deadline in 100ms", first.duration)
	}
	clock.advance(250 * time.Millisecond)
	close(first.release)
	second := clock.nextSleep(t)
	// 200 probe tokens plus 150 steady tokens are available after oversleep.
	// Refilling all 250ms at the probe rate would incorrectly leave only 500ms.
	if second.duration != 650*time.Millisecond {
		t.Fatalf("steady remainder=%s, want 650ms", second.duration)
	}
	controller.mu.Lock()
	active := controller.probe.active
	controller.mu.Unlock()
	if active {
		t.Fatal("probe survived its deadline without Observe")
	}
	clock.advance(second.duration)
	close(second.release)
	if err := awaitPacingSleepWait(t, done); err != nil {
		t.Fatal(err)
	}
	assertPacingSleep(t, controller, clock.Now(), 900*time.Millisecond, false)
}

func TestCapacityProbeSafetyCancelRefundDoesNotReplenishBudget(t *testing.T) {
	clock := newPacingSleepClock()
	controller := newProbeSafetyController(t, clock, 1000, 100, 0)
	startProbeSafety(controller, 200)
	controller.tokens = 100
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Wait(ctx, 200) }()
	clock.nextSleep(t)
	clock.advance(20 * time.Millisecond)
	cancel()
	if err := awaitPacingSleepWait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Wait=%v", err)
	}
	if controller.probe.remaining != 100 || controller.tokens != 100 {
		t.Fatalf("cancel budget/tokens=%g/%g, want 100/100", controller.probe.remaining, controller.tokens)
	}
	if err := controller.Wait(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	if controller.probe.active || controller.probe.remaining != 0 {
		t.Fatalf("refunded tokens replenished probe allowance: %+v", controller.probe)
	}
	assertPacingSleep(t, controller, clock.Now(), 20*time.Millisecond, false)
}

func TestCapacityProbeSafetySubwindowCongestionAborts(t *testing.T) {
	for _, test := range []struct {
		name string
		loss uint64
		rtt  time.Duration
		want bool
	}{
		{name: "new_loss", loss: 1, rtt: 4 * time.Millisecond, want: true},
		{name: "exact_rtt_tolerance", rtt: 5 * time.Millisecond},
		{name: "above_rtt_tolerance", rtt: 5*time.Millisecond + time.Nanosecond, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock()
			controller := newProbeSafetyController(t, clock, 1000, 100, 0)
			baseline := Snapshot{At: clock.Now(), SentBytes: 100, MinRTT: time.Millisecond, SmoothedRTT: 4 * time.Millisecond}
			mustObserveIdleSnapshot(t, controller, baseline)
			startProbeSafety(controller, 200)
			if err := clock.Sleep(context.Background(), time.Millisecond); err != nil {
				t.Fatal(err)
			}
			snapshot := baseline
			snapshot.At, snapshot.LostBytes, snapshot.SmoothedRTT = clock.Now(), test.loss, test.rtt
			mustObserveIdleSnapshot(t, controller, snapshot)
			if got := !controller.probe.active; got != test.want {
				t.Fatalf("probe aborted=%t, want %t", got, test.want)
			}
			if controller.previous != baseline || controller.estimator.count != 1 {
				t.Fatal("subwindow abort consumed the delivery baseline")
			}
		})
	}
}

func TestCapacityProbeSafetyFinalAdmissionFeedbackIsLearned(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "higher_sample"
		if delayed {
			name = "transport_bound_sample"
		}
		t.Run(name, func(t *testing.T) {
			clock := newFakeClock()
			controller := newProbeSafetyController(t, clock, 1000, 100, 0)
			snapshot := Snapshot{At: clock.Now(), MinRTT: time.Millisecond, SmoothedRTT: 4 * time.Millisecond}
			mustObserveIdleSnapshot(t, controller, snapshot)
			startProbeSafety(controller, 100)
			if err := controller.Wait(context.Background(), 100); err != nil {
				t.Fatal(err)
			}
			if controller.probe.active || !controller.probe.pending {
				t.Fatal("last admission did not enter feedback-only phase")
			}
			if delayed {
				if err := clock.Sleep(context.Background(), 100*time.Millisecond); err != nil {
					t.Fatal(err)
				}
			}
			snapshot.At, snapshot.SentBytes = clock.Now(), 100
			mustObserveIdleSnapshot(t, controller, snapshot)
			if controller.estimator.count != 2 || controller.probe.active || controller.probe.pending {
				t.Fatalf("final delivery was discarded or outcome unresolved: count=%d probe=%+v", controller.estimator.count, controller.probe)
			}
			if delayed {
				if controller.estimator.rates[1] >= 1000 || controller.probe.backoff != 2*time.Second {
					t.Fatal("ending probe discarded genuine backpressure or failed to back off")
				}
			} else if controller.estimator.bandwidthEstimate() != 1250 || controller.TargetBytesPerSecond() != 810 || controller.probe.backoff != 0 {
				t.Fatalf("post-budget higher sample was not learned: capacity=%g steady=%d backoff=%s", controller.estimator.bandwidthEstimate(), controller.TargetBytesPerSecond(), controller.probe.backoff)
			}
		})
	}
}

func TestCapacityProbeSafetyMissingFeedbackBackoffIsBounded(t *testing.T) {
	clock := newFakeClock()
	controller := newProbeSafetyController(t, clock, 1000, 100, 0)
	for _, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 16 * time.Second} {
		controller.mu.Lock()
		controller.probe.active = true
		controller.probe.gap = time.Second
		controller.finishProbeLocked(clock.Now())
		deadline := controller.probe.outcomeDeadline
		controller.mu.Unlock()
		if err := clock.Sleep(context.Background(), deadline.Sub(clock.Now())); err != nil {
			t.Fatal(err)
		}
		// No Observe is needed to leave the feedback grace period.
		if err := controller.Wait(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		if controller.probe.active || controller.probe.pending || controller.probe.backoff != want || !controller.probe.nextAt.Equal(clock.Now().Add(want)) {
			t.Fatalf("missing-feedback outcome=%+v, want %s backoff", controller.probe, want)
		}
	}
}

func TestCapacityProbeSafetyIdleUnknownFeedbackAndEpochEndProbe(t *testing.T) {
	for _, condition := range []string{"no_bytes", "no_rtt", "idle", "sent_reset", "idle_reset"} {
		t.Run(condition, func(t *testing.T) {
			clock := newFakeClock()
			controller := newProbeSafetyController(t, clock, 1000, 100, 0)
			snapshot := Snapshot{At: clock.Now(), SentBytes: 100, MinRTT: time.Millisecond, SmoothedRTT: 4 * time.Millisecond, ApplicationIdleTime: 100 * time.Millisecond}
			mustObserveIdleSnapshot(t, controller, snapshot)
			startProbeSafety(controller, 200)
			if err := clock.Sleep(context.Background(), 20*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			snapshot.At, snapshot.SentBytes = clock.Now(), 120
			switch condition {
			case "no_bytes":
				snapshot.SentBytes = 100
			case "no_rtt":
				snapshot.SmoothedRTT = 0
			case "idle":
				snapshot.ApplicationIdleTime += 20 * time.Millisecond
			case "sent_reset":
				snapshot.SentBytes = 0
			case "idle_reset":
				snapshot.ApplicationIdleTime = 0
			}
			mustObserveIdleSnapshot(t, controller, snapshot)
			if controller.probe.active || controller.probe.pending || controller.probe.eligibleSamples != 0 {
				t.Fatalf("%s retained a probe: %+v", condition, controller.probe)
			}
			if condition == "sent_reset" || condition == "idle_reset" {
				if controller.estimator.count != 0 || controller.TargetBytesPerSecond() != 1000 || controller.probe.backoff != 0 {
					t.Fatal("new epoch retained old capacity or probe backoff")
				}
			} else if controller.estimator.count != 1 || controller.TargetBytesPerSecond() != 648 {
				t.Fatal("non-capacity observation changed steady state")
			}
		})
	}
}

// Seed existing capacity evidence and a steady RTT penalty. Individual tests
// exercise real admission/observation paths; qualification tests isolate only
// the eligibility policy. End-to-end discovery is covered by the closed loop.
func newProbeSafetyController(t *testing.T, clock Clock, capacity, burst, maximum int64) *Controller {
	t.Helper()
	if maximum == 0 {
		maximum = max(defaultMaximumRate, capacity)
	}
	controller, err := New(Config{Clock: clock, InitialRateBytesPerSecond: capacity, MinRateBytesPerSecond: 1, MaxRateBytesPerSecond: maximum, BurstBytes: burst})
	if err != nil {
		t.Fatal(err)
	}
	controller.estimator.rates[0] = float64(capacity)
	controller.estimator.count = 1
	controller.estimator.next = 1
	controller.targetRate = int64(float64(capacity) * .648)
	controller.tokens = 0
	return controller
}

func qualifyProbeSafety(t *testing.T, controller *Controller, clock *fakeClock, rtts []time.Duration) {
	t.Helper()
	for index, rtt := range rtts {
		if index > 0 {
			if err := clock.Sleep(context.Background(), 500*time.Millisecond); err != nil {
				t.Fatal(err)
			}
		}
		controller.mu.Lock()
		controller.refillLocked(clock.Now())
		controller.observeProbeLocked(Snapshot{MinRTT: time.Millisecond, SmoothedRTT: rtt}, clock.Now(), true, false)
		controller.mu.Unlock()
	}
}

func startProbeSafety(controller *Controller, budget float64) {
	controller.probe = capacityProbe{
		active: true, rate: 1250, remaining: budget,
		deadline:      controller.clock.Now().Add(time.Second),
		entryCapacity: controller.estimator.bandwidthEstimate(),
		entryRTT:      4 * time.Millisecond, window: 10 * time.Millisecond, gap: time.Second,
	}
}
