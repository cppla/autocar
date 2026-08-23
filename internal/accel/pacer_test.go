package accel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDefaultsAndLabels(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if got := controller.Mode(); got != ModeAdaptive || got.String() != "adaptive" {
		t.Fatalf("mode = %q, want adaptive", got)
	}
	if got := controller.Profile(); got != ProfileBalanced || got.String() != "balanced" {
		t.Fatalf("profile = %q, want balanced", got)
	}
	if got := controller.TargetBytesPerSecond(); got != defaultInitialRate {
		t.Fatalf("initial target = %d, want %d", got, defaultInitialRate)
	}
}

func TestValidateRejectsInvalidConfigurations(t *testing.T) {
	tests := []Config{
		{Mode: "unknown"},
		{Profile: "unknown"},
		{BurstBytes: -1},
		{MinRateBytesPerSecond: 200, InitialRateBytesPerSecond: 100},
		{InitialRateBytesPerSecond: 200, MaxRateBytesPerSecond: 100},
		{Mode: ModeFixedRate},
		{Mode: ModeFixedRate, FixedRateBytesPerSecond: -1},
	}
	for _, config := range tests {
		if err := Validate(config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate(%+v) error = %v, want ErrInvalidConfig", config, err)
		}
	}
}

func TestRenoModeBypassesApplicationPacing(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{Mode: ModeReno, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Wait(context.Background(), 1<<20); err != nil {
		t.Fatal(err)
	}
	if got := clock.totalSleep(); got != 0 {
		t.Fatalf("bypass mode slept for %s", got)
	}
	if got := controller.TargetBytesPerSecond(); got != 0 {
		t.Fatalf("bypass target = %d, want 0", got)
	}
	if err := controller.SetFixedRate(1); !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("SetFixedRate error = %v, want ErrModeMismatch", err)
	}
}

func TestFixedRateUsesBoundedTokenBucket(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{
		Mode:                    ModeFixedRate,
		FixedRateBytesPerSecond: 1_000,
		BurstBytes:              100,
		Clock:                   clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.Wait(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	if got := clock.totalSleep(); got != 0 {
		t.Fatalf("initial burst slept for %s", got)
	}
	if err := controller.Wait(context.Background(), 50); err != nil {
		t.Fatal(err)
	}
	if got := clock.totalSleep(); got != 50*time.Millisecond {
		t.Fatalf("sleep = %s, want 50ms", got)
	}

	if err := controller.SetFixedRate(2_000); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got != 2_000 {
		t.Fatalf("updated target = %d, want 2000", got)
	}
	if err := controller.Wait(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	if got := clock.totalSleep(); got != 100*time.Millisecond {
		t.Fatalf("total sleep = %s, want 100ms", got)
	}
}

func TestWaitChunksRequestLargerThanBurst(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{
		Mode:                    ModeFixedRate,
		FixedRateBytesPerSecond: 1_000,
		BurstBytes:              100,
		Clock:                   clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Wait(context.Background(), 250); err != nil {
		t.Fatal(err)
	}
	if got := clock.totalSleep(); got != 150*time.Millisecond {
		t.Fatalf("sleep = %s, want 150ms after one free 100-byte burst", got)
	}
}

func TestWaitHonorsContext(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{
		Mode:                    ModeFixedRate,
		FixedRateBytesPerSecond: 1,
		BurstBytes:              1,
		Clock:                   clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Wait(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.Wait(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want context.Canceled", err)
	}
	if err := controller.Wait(context.Background(), -1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative Wait error = %v, want ErrInvalidConfig", err)
	}
}

func TestAdaptiveProfilesUseDifferentProbeGains(t *testing.T) {
	targets := make(map[Profile]int64)
	for _, profile := range []Profile{ProfileConservative, ProfileBalanced, ProfileAggressive} {
		controller := newTestAdaptive(t, profile)
		observePair(t, controller, 1_000_000, 0, 100*time.Millisecond, 100*time.Millisecond)
		targets[profile] = controller.TargetBytesPerSecond()
	}
	if !(targets[ProfileConservative] < targets[ProfileBalanced] &&
		targets[ProfileBalanced] < targets[ProfileAggressive]) {
		t.Fatalf("profile targets are not ordered: %+v", targets)
	}
}

func TestAdaptiveDampsRTTInflationAndLossIndependently(t *testing.T) {
	tests := []struct {
		name        string
		lostBytes   uint64
		smoothedRTT time.Duration
	}{
		{name: "RTT inflation", smoothedRTT: 200 * time.Millisecond},
		{name: "loss", lostBytes: 200_000, smoothedRTT: 100 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := newTestAdaptive(t, ProfileBalanced)
			t0 := time.Unix(1, 0)
			if err := controller.Observe(Snapshot{
				At: t0, MinRTT: 100 * time.Millisecond, SmoothedRTT: 100 * time.Millisecond,
			}); err != nil {
				t.Fatal(err)
			}
			if err := controller.Observe(Snapshot{
				At: t0.Add(time.Second), SentBytes: 1_000_000,
				MinRTT: 100 * time.Millisecond, SmoothedRTT: 100 * time.Millisecond,
			}); err != nil {
				t.Fatal(err)
			}
			cleanTarget := controller.TargetBytesPerSecond()

			if err := controller.Observe(Snapshot{
				At: t0.Add(2 * time.Second), SentBytes: 2_000_000, LostBytes: test.lostBytes,
				MinRTT: 100 * time.Millisecond, SmoothedRTT: test.smoothedRTT,
			}); err != nil {
				t.Fatal(err)
			}
			dampedTarget := controller.TargetBytesPerSecond()
			if dampedTarget >= cleanTarget {
				t.Fatalf("damped target = %d, want less than clean target %d", dampedTarget, cleanTarget)
			}
		})
	}
}

func TestAdaptiveClampsRateAndHandlesCounterCorrection(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{
		Mode:                      ModeAdaptive,
		Profile:                   ProfileBalanced,
		InitialRateBytesPerSecond: 100_000,
		MinRateBytesPerSecond:     50_000,
		MaxRateBytesPerSecond:     200_000,
		BurstBytes:                100,
		Clock:                     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1, 0)
	if err := controller.Observe(Snapshot{At: t0, MinRTT: time.Second, SmoothedRTT: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(Snapshot{
		At: t0.Add(time.Second), SentBytes: 10, LostBytes: 10,
		MinRTT: time.Second, SmoothedRTT: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got != 50_000 {
		t.Fatalf("minimum-clamped target = %d, want 50000", got)
	}

	if err := controller.Observe(Snapshot{
		At: t0.Add(2 * time.Second), SentBytes: 1_000_010, LostBytes: 5,
		MinRTT: time.Second, SmoothedRTT: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got != 200_000 {
		t.Fatalf("maximum-clamped target = %d, want 200000", got)
	}
}

func TestAdaptiveRejectsNonIncreasingTime(t *testing.T) {
	controller := newTestAdaptive(t, ProfileBalanced)
	t0 := time.Unix(1, 0)
	if err := controller.Observe(Snapshot{At: t0}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(Snapshot{At: t0}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Observe error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestAdaptiveIgnoresUnstableSubWindowSamples(t *testing.T) {
	controller := newTestAdaptive(t, ProfileBalanced)
	t0 := time.Unix(1, 0)
	base := Snapshot{At: t0, MinRTT: 40 * time.Millisecond, SmoothedRTT: 40 * time.Millisecond}
	if err := controller.Observe(base); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(Snapshot{
		At: t0.Add(time.Microsecond), SentBytes: 64 << 10,
		MinRTT: base.MinRTT, SmoothedRTT: base.SmoothedRTT,
	}); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got != 1_000_000 {
		t.Fatalf("sub-window sample changed target to %d", got)
	}
	if err := controller.Observe(Snapshot{
		At: t0.Add(20 * time.Millisecond), SentBytes: 20_000,
		MinRTT: base.MinRTT, SmoothedRTT: base.SmoothedRTT,
	}); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got != 1_080_000 {
		t.Fatalf("stable-window target = %d, want 1080000", got)
	}
}

func TestAdaptiveRebaselinesOnSentCounterReset(t *testing.T) {
	controller := newTestAdaptive(t, ProfileBalanced)
	t0 := time.Unix(1, 0)
	if err := controller.Observe(Snapshot{
		At: t0, SentBytes: 1_000_000,
		MinRTT: time.Second, SmoothedRTT: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(Snapshot{
		At: t0.Add(time.Second), SentBytes: 2_000_000,
		MinRTT: time.Second, SmoothedRTT: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got == 1_000_000 {
		t.Fatal("adaptive sample did not change the initial target")
	}
	if err := controller.Observe(Snapshot{
		At: t0.Add(2 * time.Second), SentBytes: 1,
		MinRTT: time.Second, SmoothedRTT: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if got := controller.TargetBytesPerSecond(); got != 1_000_000 {
		t.Fatalf("reset target = %d, want initial target 1000000", got)
	}
}

func TestFixedRateConcurrentWaits(t *testing.T) {
	clock := newFakeClock()
	controller, err := New(Config{
		Mode:                    ModeFixedRate,
		FixedRateBytesPerSecond: 10_000,
		BurstBytes:              10,
		Clock:                   clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 16
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer waitGroup.Done()
			if err := controller.Wait(context.Background(), 10); err != nil {
				t.Errorf("Wait error: %v", err)
			}
		}()
	}
	waitGroup.Wait()
	if elapsed := clock.Now().Sub(time.Unix(1, 0)); elapsed < 15*time.Millisecond {
		t.Fatalf("elapsed = %s, want at least 15ms for 160 bytes with a 10-byte burst", elapsed)
	}
}

func TestRateReductionRecalculatesQueuedAdmissions(t *testing.T) {
	clock := newBlockingClock()
	controller, err := New(Config{
		Mode:                    ModeFixedRate,
		FixedRateBytesPerSecond: 10_000,
		BurstBytes:              10,
		Clock:                   clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Wait(context.Background(), 10); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- controller.Wait(ctx, 10) }()

	oldRateSleep := clock.nextSleep(t)
	if oldRateSleep.duration != time.Millisecond {
		t.Fatalf("old-rate delay = %s, want 1ms", oldRateSleep.duration)
	}
	go func() { secondDone <- controller.Wait(ctx, 10) }()

	if err := controller.SetFixedRate(100); err != nil {
		t.Fatal(err)
	}
	recalculatedSleep := clock.nextSleep(t)
	if recalculatedSleep.duration != 100*time.Millisecond {
		t.Fatalf("recalculated delay = %s, want 100ms", recalculatedSleep.duration)
	}
	close(recalculatedSleep.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Wait error: %v", err)
	}

	queuedSleep := clock.nextSleep(t)
	if queuedSleep.duration != 100*time.Millisecond {
		t.Fatalf("queued delay = %s, want 100ms", queuedSleep.duration)
	}
	close(queuedSleep.release)
	if err := <-secondDone; err != nil {
		t.Fatalf("second Wait error: %v", err)
	}
}

func TestRefundWakesCapacityWaiter(t *testing.T) {
	clock := newBlockingClock()
	controller, err := New(Config{
		Mode:                    ModeFixedRate,
		FixedRateBytesPerSecond: 1,
		BurstBytes:              10,
		Clock:                   clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Wait(context.Background(), 10); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Wait(ctx, 10) }()
	sleep := clock.nextSleep(t)
	if sleep.duration != 10*time.Second {
		t.Fatalf("capacity delay = %s, want 10s", sleep.duration)
	}

	controller.refund(10)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait error after refund: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("refunded capacity did not wake the queued waiter")
	}
}

func newTestAdaptive(t *testing.T, profile Profile) *Controller {
	t.Helper()
	controller, err := New(Config{
		Mode:                      ModeAdaptive,
		Profile:                   profile,
		InitialRateBytesPerSecond: 1_000_000,
		MinRateBytesPerSecond:     1,
		MaxRateBytesPerSecond:     10_000_000,
		BurstBytes:                100,
		Clock:                     newFakeClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func observePair(
	t *testing.T,
	controller *Controller,
	sentBytes uint64,
	lostBytes uint64,
	minimumRTT time.Duration,
	smoothedRTT time.Duration,
) {
	t.Helper()
	t0 := time.Unix(1, 0)
	if err := controller.Observe(Snapshot{At: t0, MinRTT: minimumRTT, SmoothedRTT: smoothedRTT}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(Snapshot{
		At: t0.Add(time.Second), SentBytes: sentBytes, LostBytes: lostBytes,
		MinRTT: minimumRTT, SmoothedRTT: smoothedRTT,
	}); err != nil {
		t.Fatal(err)
	}
}

type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept time.Duration
}

type blockingSleep struct {
	duration time.Duration
	release  chan struct{}
}

type blockingClock struct {
	mu       sync.Mutex
	now      time.Time
	requests chan blockingSleep
}

func newBlockingClock() *blockingClock {
	return &blockingClock{
		now:      time.Unix(1, 0),
		requests: make(chan blockingSleep, 4),
	}
}

func (c *blockingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *blockingClock) Sleep(ctx context.Context, duration time.Duration) error {
	request := blockingSleep{duration: duration, release: make(chan struct{})}
	select {
	case c.requests <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-request.release:
		c.mu.Lock()
		c.now = c.now.Add(duration)
		c.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *blockingClock) nextSleep(t *testing.T) blockingSleep {
	t.Helper()
	select {
	case request := <-c.requests:
		return request
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pacing sleep")
		return blockingSleep{}
	}
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.slept += duration
	c.mu.Unlock()
	return nil
}

func (c *fakeClock) totalSleep() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slept
}
