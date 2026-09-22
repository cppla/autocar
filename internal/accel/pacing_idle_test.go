package accel

import (
	"errors"
	"testing"
	"time"
)

func TestAdaptiveApplicationIdleACKWindowPreservesTarget(t *testing.T) {
	controller, err := New(Config{Clock: newFakeClock()})
	if err != nil {
		t.Fatal(err)
	}
	base := Snapshot{
		At: time.Unix(1, 0), SentBytes: 1000,
		MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond,
	}
	mustObserveIdleSnapshot(t, controller, base)
	beforeEstimator := controller.estimator
	idle := base
	idle.At = idle.At.Add(2500 * time.Millisecond)
	idle.SentBytes += 20_000 // ACK/control traffic while receiving an upload.
	idle.ApplicationIdleTime = 2500 * time.Millisecond
	mustObserveIdleSnapshot(t, controller, idle)
	if got := controller.TargetBytesPerSecond(); got != defaultInitialRate {
		t.Fatalf("ACK-only application-idle window changed target to %d, want %d", got, defaultInitialRate)
	}
	if controller.estimator != beforeEstimator {
		t.Fatal("application-idle window changed bandwidth history")
	}
	if controller.previous != idle {
		t.Fatal("application-idle window did not rebaseline cumulative counters")
	}
}

func TestAdaptiveApplicationIdleAccumulatesAcrossSubWindowSamples(t *testing.T) {
	controller := newTestAdaptive(t, ProfileBalanced)
	base := Snapshot{At: time.Unix(1, 0), MinRTT: 40 * time.Millisecond, SmoothedRTT: 40 * time.Millisecond}
	mustObserveIdleSnapshot(t, controller, base)
	for _, elapsed := range []time.Duration{4 * time.Millisecond, 8 * time.Millisecond} {
		snapshot := base
		snapshot.At = base.At.Add(elapsed)
		snapshot.SentBytes = uint64(elapsed / time.Microsecond)
		snapshot.ApplicationIdleTime = elapsed
		mustObserveIdleSnapshot(t, controller, snapshot)
		if controller.previous != base {
			t.Fatal("sub-window observation consumed accumulated idle time")
		}
	}
	threshold := base
	threshold.At = base.At.Add(10 * time.Millisecond)
	threshold.SentBytes = 10_000
	threshold.ApplicationIdleTime = 10 * time.Millisecond
	mustObserveIdleSnapshot(t, controller, threshold)
	if got := controller.TargetBytesPerSecond(); got != 1_000_000 || controller.estimator.count != 0 {
		t.Fatalf("accumulated idle window changed target/history: %d/%d", got, controller.estimator.count)
	}
	if controller.previous != threshold {
		t.Fatal("full idle window was not rebaselined")
	}
	active := threshold
	active.At = active.At.Add(20 * time.Millisecond)
	active.SentBytes += 20_000
	mustObserveIdleSnapshot(t, controller, active)
	if got := controller.TargetBytesPerSecond(); got != 1_080_000 {
		t.Fatalf("clean active interval reused old idle time: target=%d want 1080000", got)
	}
}

func TestAdaptiveApplicationShortIdleGapsStillUpdateRate(t *testing.T) {
	controller, err := New(Config{Clock: newFakeClock()})
	if err != nil {
		t.Fatal(err)
	}
	base := Snapshot{At: time.Unix(1, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
	mustObserveIdleSnapshot(t, controller, base)
	sample := base
	sample.At = base.At.Add(50 * time.Millisecond)
	sample.SentBytes = 50_000
	sample.ApplicationIdleTime = 9 * time.Millisecond
	mustObserveIdleSnapshot(t, controller, sample)
	if got := controller.TargetBytesPerSecond(); got != 1_080_000 {
		t.Fatalf("short application gaps suppressed an active sample: target=%d want 1080000", got)
	}
}

func TestAdaptiveMostlyActiveSamplesStillRespondToPath(t *testing.T) {
	for _, condition := range []string{"slower_delivery", "loss", "rtt"} {
		t.Run(condition, func(t *testing.T) {
			controller := newTestAdaptive(t, ProfileBalanced)
			snapshot := Snapshot{At: time.Unix(1, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
			mustObserveIdleSnapshot(t, controller, snapshot)
			snapshot.At = snapshot.At.Add(time.Second)
			snapshot.SentBytes = 1_000_000
			mustObserveIdleSnapshot(t, controller, snapshot)
			learned := controller.TargetBytesPerSecond()
			for range deliveryRateWindow {
				// A one-second paced or transport-blocked write is active demand.
				// Its 20ms source-read gap exceeds the 10ms sample window, but
				// must not discard the much longer active congestion observation.
				snapshot.At = snapshot.At.Add(time.Second + 20*time.Millisecond)
				snapshot.ApplicationIdleTime += 20 * time.Millisecond
				delivered := uint64(1_000_000)
				switch condition {
				case "slower_delivery":
					delivered = 100_000
				case "loss":
					snapshot.LostBytes += 200_000
				case "rtt":
					snapshot.SmoothedRTT = 2 * time.Millisecond
				}
				snapshot.SentBytes += delivered
				beforeNext := controller.estimator.next
				mustObserveIdleSnapshot(t, controller, snapshot)
				if controller.estimator.next != (beforeNext+1)%deliveryRateWindow {
					t.Fatal("mostly active interval did not update bandwidth history")
				}
			}
			if got := controller.TargetBytesPerSecond(); got >= learned {
				t.Fatalf("mostly active %s did not reduce target: %d >= %d", condition, got, learned)
			}
		})
	}
}

func TestAdaptiveApplicationIdleHalfIntervalBoundary(t *testing.T) {
	for _, test := range []struct {
		name     string
		idle     time.Duration
		filtered bool
	}{
		{name: "just below half", idle: 12*time.Millisecond - time.Nanosecond},
		{name: "exactly half", idle: 12 * time.Millisecond, filtered: true},
		{name: "above half", idle: 13 * time.Millisecond, filtered: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := newTestAdaptive(t, ProfileBalanced)
			base := Snapshot{At: time.Unix(1, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
			mustObserveIdleSnapshot(t, controller, base)
			sample := base
			sample.At = base.At.Add(24 * time.Millisecond)
			sample.SentBytes = 24_000
			sample.ApplicationIdleTime = test.idle
			mustObserveIdleSnapshot(t, controller, sample)
			wantRate, wantCount := int64(1_080_000), 1
			if test.filtered {
				wantRate, wantCount = 1_000_000, 0
			}
			if controller.TargetBytesPerSecond() != wantRate || controller.estimator.count != wantCount {
				t.Fatalf("idle=%s: target/history = %d/%d, want %d/%d", test.idle,
					controller.TargetBytesPerSecond(), controller.estimator.count, wantRate, wantCount)
			}
			if controller.previous != sample {
				t.Fatal("stable sample did not rebaseline counters")
			}
		})
	}
}

func TestAdaptiveApplicationIdleRejectsNegativeTime(t *testing.T) {
	for _, established := range []bool{false, true} {
		controller := newTestAdaptive(t, ProfileBalanced)
		base := Snapshot{At: time.Unix(1, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
		if established {
			mustObserveIdleSnapshot(t, controller, base)
		}
		before := controller.previous
		invalid := base
		invalid.At = base.At.Add(time.Second)
		invalid.ApplicationIdleTime = -time.Nanosecond
		if err := controller.Observe(invalid); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("negative idle time error=%v want ErrInvalidSnapshot", err)
		}
		if controller.previous != before || controller.haveSnapshot != established || controller.TargetBytesPerSecond() != 1_000_000 {
			t.Fatal("invalid idle time changed controller state")
		}
	}
}

func TestAdaptiveApplicationIdleCounterResetStartsNewEpoch(t *testing.T) {
	for _, reset := range []string{"idle", "sent"} {
		t.Run(reset, func(t *testing.T) {
			controller := newTestAdaptive(t, ProfileBalanced)
			base := Snapshot{
				At: time.Unix(1, 0), SentBytes: 1000, ApplicationIdleTime: time.Second,
				MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond,
			}
			mustObserveIdleSnapshot(t, controller, base)
			active := base
			active.At = active.At.Add(time.Second)
			active.SentBytes += 2_000_000
			mustObserveIdleSnapshot(t, controller, active)
			if controller.TargetBytesPerSecond() == 1_000_000 || controller.estimator.count == 0 {
				t.Fatal("test did not establish a learned rate")
			}
			resetSample := active
			resetSample.At = resetSample.At.Add(time.Millisecond) // Reset is recognized even below the sample window.
			if reset == "idle" {
				resetSample.ApplicationIdleTime = 0
			} else {
				resetSample.SentBytes = 0
			}
			mustObserveIdleSnapshot(t, controller, resetSample)
			if controller.TargetBytesPerSecond() != 1_000_000 || controller.estimator.count != 0 || controller.previous != resetSample {
				t.Fatal("counter reset did not restore the initial rate and rebaseline")
			}
		})
	}
}

func TestAdaptiveApplicationIdleRecoveryStillRespondsToActivePath(t *testing.T) {
	for _, condition := range []string{"slower_delivery", "loss", "rtt"} {
		t.Run(condition, func(t *testing.T) {
			controller := newTestAdaptive(t, ProfileBalanced)
			snapshot := Snapshot{At: time.Unix(1, 0), MinRTT: time.Millisecond, SmoothedRTT: time.Millisecond}
			mustObserveIdleSnapshot(t, controller, snapshot)
			snapshot.At = snapshot.At.Add(time.Second)
			snapshot.SentBytes = 1_000_000
			mustObserveIdleSnapshot(t, controller, snapshot)
			learned := controller.TargetBytesPerSecond()
			beforeEstimator := controller.estimator
			snapshot.At = snapshot.At.Add(2500 * time.Millisecond)
			snapshot.SentBytes += 20_000
			snapshot.ApplicationIdleTime = 2500 * time.Millisecond
			mustObserveIdleSnapshot(t, controller, snapshot)
			if controller.TargetBytesPerSecond() != learned || controller.estimator != beforeEstimator {
				t.Fatal("idle window discarded learned capacity")
			}
			for range deliveryRateWindow {
				snapshot.At = snapshot.At.Add(time.Second)
				delivered := uint64(1_000_000)
				switch condition {
				case "slower_delivery":
					delivered = 100_000
				case "loss":
					snapshot.LostBytes += 200_000
				case "rtt":
					snapshot.SmoothedRTT = 2 * time.Millisecond
				}
				snapshot.SentBytes += delivered
				mustObserveIdleSnapshot(t, controller, snapshot)
			}
			if got := controller.TargetBytesPerSecond(); got >= learned {
				t.Fatalf("resumed active %s did not reduce target: %d >= %d", condition, got, learned)
			}
		})
	}
}

func TestApplicationIdleSnapshotsDoNotChangeFixedOrRenoModes(t *testing.T) {
	for _, mode := range []Mode{ModeFixedRate, ModeReno} {
		t.Run(mode.String(), func(t *testing.T) {
			controller, err := New(Config{Mode: mode, FixedRateBytesPerSecond: 123_456, Clock: newFakeClock()})
			if err != nil {
				t.Fatal(err)
			}
			before := controller.TargetBytesPerSecond()
			for _, idle := range []time.Duration{time.Second, 0, -time.Second} {
				// Observe has always been an unconditional no-op outside adaptive
				// mode, even for otherwise invalid adaptive-only observations.
				mustObserveIdleSnapshot(t, controller, Snapshot{At: time.Unix(1, 0), ApplicationIdleTime: idle})
			}
			if controller.TargetBytesPerSecond() != before || controller.haveSnapshot {
				t.Fatal("idle snapshots changed a non-adaptive controller")
			}
		})
	}
}

func mustObserveIdleSnapshot(t *testing.T, controller *Controller, snapshot Snapshot) {
	t.Helper()
	if err := controller.Observe(snapshot); err != nil {
		t.Fatal(err)
	}
}
