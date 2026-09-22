package accel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPacingSleepOngoingAndSubWindowObservation(t *testing.T) {
	clock := newPacingSleepClock()
	controller := newPacingSleepController(t, clock)
	// The transport timestamp deliberately has a different epoch. Pacing time
	// must be compared with the controller's clock, not with Snapshot.At.
	base := Snapshot{At: time.Unix(100, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
	mustObserveIdleSnapshot(t, controller, base)
	started := clock.Now()
	if err := controller.Wait(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Wait(ctx, 1000) }()
	clock.nextSleep(t)
	for _, elapsed := range []time.Duration{4 * time.Millisecond, 8 * time.Millisecond} {
		clock.advance(4 * time.Millisecond)
		sample := base
		sample.At = base.At.Add(elapsed)
		sample.SentBytes = uint64(elapsed / time.Millisecond)
		mustObserveIdleSnapshot(t, controller, sample)
		controller.mu.Lock()
		previous, observation, previousSleep := controller.previous, controller.previousObservationTime, controller.previousPacingSleep
		ongoing := controller.pacingTimeLocked(clock.Now())
		controller.mu.Unlock()
		if previous != base || observation != started || previousSleep != 0 || ongoing != elapsed {
			t.Fatalf("sub-window consumed or lost sleep: previous=%+v own=%v baseline=%s ongoing=%s", previous, observation, previousSleep, ongoing)
		}
	}
	clock.advance(2 * time.Millisecond)
	sample := base
	sample.At = base.At.Add(10 * time.Millisecond)
	sample.SentBytes = 10
	mustObserveIdleSnapshot(t, controller, sample)
	controller.mu.Lock()
	previous, observation, previousSleep := controller.previous, controller.previousObservationTime, controller.previousPacingSleep
	controller.mu.Unlock()
	if previous != sample || observation != clock.Now() || previousSleep != 10*time.Millisecond {
		t.Fatalf("accepted observation did not retain partial sleep: previous=%+v own=%v sleep=%s", previous, observation, previousSleep)
	}
	cancel()
	if err := awaitPacingSleepWait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want cancellation", err)
	}
	assertPacingSleep(t, controller, clock.Now(), 10*time.Millisecond, false)
}

func TestPacingSleepConcurrentWaitersAreNotDoubleCounted(t *testing.T) {
	clock := newPacingSleepClock()
	controller := newPacingSleepController(t, clock)
	if err := controller.Wait(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const writers = 16
	done := make(chan error, writers)
	entered := make(chan struct{}, writers)
	for range writers {
		go func() {
			entered <- struct{}{}
			done <- controller.Wait(ctx, 1000)
		}()
	}
	for range writers {
		<-entered
	}
	clock.nextSleep(t)
	clock.advance(40 * time.Millisecond)
	assertPacingSleep(t, controller, clock.Now(), 40*time.Millisecond, true)
	select {
	case <-clock.requests:
		t.Fatal("more than one admission holder entered token sleep")
	default:
	}
	cancel()
	for range writers {
		if err := awaitPacingSleepWait(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait error = %v, want cancellation", err)
		}
	}
	assertPacingSleep(t, controller, clock.Now(), 40*time.Millisecond, false)
	clock.advance(time.Second)
	assertPacingSleep(t, controller, clock.Now(), 40*time.Millisecond, false)
}

func TestPacingSleepRecordsActualElapsedAndStopsAtReturn(t *testing.T) {
	clock := newPacingSleepClock()
	controller := newPacingSleepController(t, clock)
	if err := controller.Wait(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Wait(ctx, 1000) }()
	sleep := clock.nextSleep(t)
	if sleep.duration != time.Second {
		t.Fatalf("requested sleep = %s, want 1s", sleep.duration)
	}
	clock.advance(1250 * time.Millisecond)
	close(sleep.release)
	if err := awaitPacingSleepWait(t, done); err != nil {
		t.Fatal(err)
	}
	assertPacingSleep(t, controller, clock.Now(), 1250*time.Millisecond, false)
	clock.advance(time.Second)
	assertPacingSleep(t, controller, clock.Now(), 1250*time.Millisecond, false)
}

func TestPacingSleepZeroEpochTracksFirstSleep(t *testing.T) {
	clock := newPacingSleepClock()
	clock.now = time.Time{}
	controller := newPacingSleepController(t, clock)
	if err := controller.Wait(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Wait(ctx, 1000) }()
	sleep := clock.nextSleep(t)
	if sleep.duration != time.Second {
		t.Fatalf("requested sleep = %s, want 1s", sleep.duration)
	}
	// The active sleep timestamp is legitimately zero. Its activity must not
	// be inferred from IsZero(), either during observation or at completion.
	assertPacingSleep(t, controller, clock.Now(), 0, true)
	clock.advance(250 * time.Millisecond)
	assertPacingSleep(t, controller, clock.Now(), 250*time.Millisecond, true)
	clock.advance(750 * time.Millisecond)
	close(sleep.release)
	if err := awaitPacingSleepWait(t, done); err != nil {
		t.Fatal(err)
	}
	assertPacingSleep(t, controller, clock.Now(), time.Second, false)
	clock.advance(time.Second)
	assertPacingSleep(t, controller, clock.Now(), time.Second, false)
}

func TestPacingSleepRefundAndRateChangeFinishAccounting(t *testing.T) {
	for _, action := range []string{"refund", "rate_change"} {
		t.Run(action, func(t *testing.T) {
			clock := newPacingSleepClock()
			controller := newPacingSleepController(t, clock)
			if err := controller.Wait(context.Background(), 1000); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- controller.Wait(ctx, 1000) }()
			clock.nextSleep(t)
			clock.advance(200 * time.Millisecond)
			wantSleep := 200 * time.Millisecond
			if action == "refund" {
				controller.refund(1000)
			} else {
				controller.mu.Lock()
				controller.setTargetRateLocked(2000)
				controller.mu.Unlock()
				recalculated := clock.nextSleep(t)
				if recalculated.duration != 400*time.Millisecond {
					t.Fatalf("recalculated sleep = %s, want 400ms", recalculated.duration)
				}
				assertPacingSleep(t, controller, clock.Now(), 200*time.Millisecond, true)
				clock.advance(400 * time.Millisecond)
				close(recalculated.release)
				wantSleep += 400 * time.Millisecond
			}
			if err := awaitPacingSleepWait(t, done); err != nil {
				t.Fatal(err)
			}
			assertPacingSleep(t, controller, clock.Now(), wantSleep, false)
		})
	}
}

func TestPacingSleepCanceledMultiChunkWaitRefundsWithoutLeakingTime(t *testing.T) {
	clock := newPacingSleepClock()
	controller := newPacingSleepController(t, clock)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	// One chunk consumes the initial burst; the second sleeps and is canceled.
	go func() { done <- controller.Wait(ctx, 2000) }()
	clock.nextSleep(t)
	clock.advance(37 * time.Millisecond)
	cancel()
	if err := awaitPacingSleepWait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want cancellation", err)
	}
	assertPacingSleep(t, controller, clock.Now(), 37*time.Millisecond, false)
	refundedCtx, cancelRefunded := context.WithTimeout(context.Background(), time.Second)
	defer cancelRefunded()
	if err := controller.Wait(refundedCtx, 1000); err != nil {
		t.Fatal(err)
	}
	assertPacingSleep(t, controller, clock.Now(), 37*time.Millisecond, false)
}

func TestPacingSleepClassificationUsesOwnElapsedTime(t *testing.T) {
	for _, condition := range []string{"all_pacing", "mostly_transport", "exactly_half", "half_minus_1ns"} {
		t.Run(condition, func(t *testing.T) {
			clock := newFakeClock()
			controller := newPacingSleepController(t, clock)
			snapshot := Snapshot{At: time.Unix(100, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
			mustObserveIdleSnapshot(t, controller, snapshot)
			snapshot.At = snapshot.At.Add(time.Second)
			snapshot.SentBytes = 10_000
			mustObserveIdleSnapshot(t, controller, snapshot)
			beforeNext := controller.estimator.next
			beforeWait := clock.Now()
			if err := controller.Wait(context.Background(), 2000); err != nil {
				t.Fatal(err)
			}
			pacingTime := clock.Now().Sub(beforeWait)
			var externalWork time.Duration
			switch condition {
			case "mostly_transport":
				externalWork = time.Second
			case "exactly_half":
				externalWork = pacingTime
			case "half_minus_1ns":
				externalWork = pacingTime + 2*time.Nanosecond
			}
			if externalWork > 0 {
				// This is transport/application work, not the controller's sleep.
				if err := clock.Sleep(context.Background(), externalWork); err != nil {
					t.Fatal(err)
				}
			}
			// Transport observation time spans 10s while the own clock spans
			// about 93ms of pacing plus the independently specified work above.
			snapshot.At = snapshot.At.Add(10 * time.Second)
			snapshot.SentBytes += 1000
			mustObserveIdleSnapshot(t, controller, snapshot)
			wantNext := beforeNext
			if condition == "mostly_transport" || condition == "half_minus_1ns" {
				wantNext = (beforeNext + 1) % deliveryRateWindow
			}
			if controller.estimator.next != wantNext {
				t.Fatalf("external work=%s: history index=%d want %d; pacing must use own-clock elapsed", externalWork, controller.estimator.next, wantNext)
			}
		})
	}
}

func TestPacingSleepEpochResetRebaselinesOwnClock(t *testing.T) {
	for _, counter := range []string{"sent", "application_idle"} {
		t.Run(counter, func(t *testing.T) {
			clock := newFakeClock()
			controller := newPacingSleepController(t, clock)
			base := Snapshot{At: time.Unix(100, 0), SentBytes: 10, ApplicationIdleTime: time.Second, MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
			mustObserveIdleSnapshot(t, controller, base)
			if err := controller.Wait(context.Background(), 2000); err != nil {
				t.Fatal(err)
			}
			reset := base
			reset.At = base.At.Add(time.Millisecond)
			if counter == "sent" {
				reset.SentBytes = 0
			} else {
				reset.ApplicationIdleTime = 0
			}
			mustObserveIdleSnapshot(t, controller, reset)
			controller.mu.Lock()
			observation, previousSleep := controller.previousObservationTime, controller.previousPacingSleep
			controller.mu.Unlock()
			if observation != clock.Now() || previousSleep != time.Second {
				t.Fatalf("epoch reset retained old pacing baseline: own=%v sleep=%s", observation, previousSleep)
			}
		})
	}
}

func TestPacingSleepNonAdaptiveModesKeepAccountingInactive(t *testing.T) {
	for _, mode := range []Mode{ModeFixedRate, ModeReno} {
		t.Run(mode.String(), func(t *testing.T) {
			clock := newFakeClock()
			controller, err := New(Config{Mode: mode, FixedRateBytesPerSecond: 1000, BurstBytes: 1000, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			if err := controller.Wait(context.Background(), 2000); err != nil {
				t.Fatal(err)
			}
			assertPacingSleep(t, controller, clock.Now(), 0, false)
			wantSleep := time.Duration(0)
			if mode == ModeFixedRate {
				wantSleep = time.Second
			}
			if clock.totalSleep() != wantSleep {
				t.Fatalf("mode %s sleep=%s want %s", mode, clock.totalSleep(), wantSleep)
			}
		})
	}
}

func TestPacingSleepClosedLoopPersistentRTTDoesNotCompound(t *testing.T) {
	for _, profile := range []Profile{ProfileConservative, ProfileBalanced, ProfileAggressive} {
		t.Run(profile.String(), func(t *testing.T) {
			clock := newFakeClock()
			controller, err := New(Config{Profile: profile, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			const chunk, total = 32 << 10, 8 << 20
			snapshot := Snapshot{MinRTT: time.Millisecond, SmoothedRTT: 2 * time.Millisecond}
			var halfwayTarget int64
			for sent := 0; sent < total; sent += chunk {
				snapshot.At = clock.Now()
				mustObserveIdleSnapshot(t, controller, snapshot)
				if err := controller.Wait(context.Background(), chunk); err != nil {
					t.Fatal(err)
				}
				// This separate fixed-capacity wire delay is not token waiting.
				if err := clock.Sleep(context.Background(), time.Millisecond); err != nil {
					t.Fatal(err)
				}
				snapshot.SentBytes += chunk
				if sent+chunk == total/2 {
					halfwayTarget = controller.TargetBytesPerSecond()
				}
			}
			finalTarget := controller.TargetBytesPerSecond()
			if halfwayTarget <= defaultMinimumRate || finalTarget < halfwayTarget {
				t.Fatalf("unchanged path kept compounding its penalty: halfway=%d final=%d", halfwayTarget, finalTarget)
			}
			wantSleep := clock.totalSleep() - time.Duration(total/chunk)*time.Millisecond
			if wantSleep <= 0 {
				t.Fatal("fixture did not exercise pacing sleep")
			}
			assertPacingSleep(t, controller, clock.Now(), wantSleep, false)
		})
	}
}

func TestPacingSleepClosedLoopPathDropAndRecovery(t *testing.T) {
	for _, profile := range []Profile{ProfileConservative, ProfileBalanced, ProfileAggressive} {
		t.Run(profile.String(), func(t *testing.T) {
			clock := newFakeClock()
			controller, err := New(Config{Profile: profile, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			const chunk = 32 << 10
			snapshot := Snapshot{At: clock.Now(), MinRTT: time.Millisecond, SmoothedRTT: 2 * time.Millisecond}
			mustObserveIdleSnapshot(t, controller, snapshot)
			type phaseResult struct {
				target       int64
				lowerSamples int
				censored     int
			}
			phase := func(name string, chunks int, wireDelay, smoothedRTT time.Duration) phaseResult {
				t.Helper()
				result := phaseResult{}
				started := clock.Now()
				snapshot.SmoothedRTT = smoothedRTT
				for range chunks {
					// Every chunk uses production Wait. Independent wire work is
					// never declared pacing-limited by this fixture. Observing each
					// completed chunk supplies the next Observe-before-Wait cycle.
					if err := controller.Wait(context.Background(), chunk); err != nil {
						t.Fatal(err)
					}
					if err := clock.Sleep(context.Background(), wireDelay); err != nil {
						t.Fatal(err)
					}
					snapshot.At = clock.Now()
					snapshot.SentBytes += chunk
					beforeNext := controller.estimator.next
					beforeCapacity := controller.estimator.bandwidthEstimate()
					beforeObservation := controller.previous.At
					mustObserveIdleSnapshot(t, controller, snapshot)
					if controller.estimator.next != beforeNext {
						// A newly inserted lower rate proves the real Controller
						// classifier allowed transport-bound capacity learning.
						if controller.estimator.rates[beforeNext] < beforeCapacity {
							result.lowerSamples++
						}
					} else if controller.previous.At != beforeObservation {
						result.censored++
					}
				}
				result.target = controller.TargetBytesPerSecond()
				t.Logf("phase=%s virtual_elapsed=%s target=%d lower_samples=%d censored=%d", name, clock.Now().Sub(started), result.target, result.lowerSamples, result.censored)
				return result
			}
			stable := phase("fast path with 2x RTT", 32*deliveryRateWindow, time.Millisecond, 2*time.Millisecond)
			if stable.target <= defaultMinimumRate || stable.censored < deliveryRateWindow {
				t.Fatalf("initial phase did not establish stable pacing-limited samples: %+v", stable)
			}
			// 32KiB/32ms is 1,024,000 B/s. Keep the RTT penalty unchanged,
			// so capacity learning (not removal of the penalty) must lower rate.
			slow := phase("path step-down", 16*deliveryRateWindow, 32*time.Millisecond, 2*time.Millisecond)
			if slow.target >= stable.target/2 || slow.target <= defaultMinimumRate || slow.lowerSamples < deliveryRateWindow {
				t.Fatalf("transport-bound step-down was not learned: initial=%+v slow=%+v", stable, slow)
			}
			recoveredRTT := phase("RTT recovery on slow path", 16*deliveryRateWindow, 32*time.Millisecond, time.Millisecond)
			if recoveredRTT.target <= slow.target {
				t.Fatalf("RTT recovery failed: slow=%d recovered=%d", slow.target, recoveredRTT.target)
			}
			recoveredPath := phase("fourfold path recovery", 32*deliveryRateWindow, 8*time.Millisecond, time.Millisecond)
			if recoveredPath.target < recoveredRTT.target {
				t.Fatalf("improved path reduced target: before=%d after=%d", recoveredRTT.target, recoveredPath.target)
			}
			// Gain 1.0 cannot actively probe an unobserved fourfold increase.
			// Conservative must preserve its recovered rate; the other profiles
			// have explicit positive probe gains and can rediscover this model's
			// fixed wire ceiling. These are synthetic, not real-network gates.
			if profile != ProfileConservative && recoveredPath.target < 4_096_000 {
				t.Fatalf("profile %s failed to probe recovered capacity: %d", profile, recoveredPath.target)
			}
		})
	}
}

func newPacingSleepController(t *testing.T, clock Clock) *Controller {
	t.Helper()
	controller, err := New(Config{InitialRateBytesPerSecond: 1000, MinRateBytesPerSecond: 1, MaxRateBytesPerSecond: 1_000_000, BurstBytes: 1000, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func assertPacingSleep(t *testing.T, controller *Controller, now time.Time, want time.Duration, active bool) {
	t.Helper()
	controller.mu.Lock()
	total, started, sleeping := controller.pacingTimeLocked(now), controller.pacingSleepStarted, controller.pacingSleeping
	controller.mu.Unlock()
	if total != want || sleeping != active || (!active && !started.IsZero()) {
		t.Fatalf("pacing sleep total/active/started = %s/%t/%v, want %s/%t with cleared inactive timestamp", total, sleeping, started, want, active)
	}
}

func awaitPacingSleepWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("pacing Wait did not finish")
		return nil
	}
}

// Unlike blockingClock, this clock advances independently of releasing a
// sleep. It can model partial waits, interruptions and scheduler oversleep.
type pacingSleepClock struct {
	mu       sync.Mutex
	now      time.Time
	requests chan blockingSleep
}

func newPacingSleepClock() *pacingSleepClock {
	return &pacingSleepClock{now: time.Unix(1, 0), requests: make(chan blockingSleep, 32)}
}

func (c *pacingSleepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *pacingSleepClock) advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func (c *pacingSleepClock) Sleep(ctx context.Context, duration time.Duration) error {
	request := blockingSleep{duration: duration, release: make(chan struct{})}
	select {
	case c.requests <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-request.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *pacingSleepClock) nextSleep(t *testing.T) blockingSleep {
	t.Helper()
	select {
	case request := <-c.requests:
		return request
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pacing sleep")
		return blockingSleep{}
	}
}
