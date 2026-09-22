package accel

import (
	"math"
	"testing"
	"time"
)

func TestAdaptiveEstimatorLimitedSamplesPreserveCapacityHistory(t *testing.T) {
	for _, profile := range []Profile{ProfileConservative, ProfileBalanced, ProfileAggressive} {
		t.Run(profile.String(), func(t *testing.T) {
			estimator := newAdaptiveEstimator(profile, 2_000_000)
			estimator.observe(8_000_000, 0, time.Millisecond, time.Millisecond, false)
			learned := estimator
			for range 4 * deliveryRateWindow {
				estimator.observe(100_000, 0, time.Millisecond, time.Millisecond, true)
				if estimator != learned {
					t.Fatal("low pacing-limited sample aged or changed capacity history")
				}
			}
			estimator.observe(8_000_000, 0, time.Millisecond, time.Millisecond, true)
			if estimator != learned {
				t.Fatal("equal pacing-limited sample aged capacity history")
			}
			got := estimator.observe(9_000_000, 0, time.Millisecond, time.Millisecond, true)
			assertEstimatorRate(t, got, 9_000_000*estimator.settings.pacingGain)
			if estimator.count != learned.count+1 || estimator.bandwidthEstimate() != 9_000_000 {
				t.Fatal("higher pacing-limited sample was not learned")
			}
		})
	}
}

func TestAdaptiveEstimatorUnconstrainedCapacityCanFallAndRecover(t *testing.T) {
	for _, profile := range []Profile{ProfileConservative, ProfileBalanced, ProfileAggressive} {
		t.Run(profile.String(), func(t *testing.T) {
			estimator := newAdaptiveEstimator(profile, 8_000_000)
			estimator.observe(8_000_000, 0, time.Millisecond, time.Millisecond, false)
			for index := 0; index < deliveryRateWindow; index++ {
				got := estimator.observe(1_000_000, 0, time.Millisecond, time.Millisecond, false)
				wantCapacity := float64(8_000_000)
				if index == deliveryRateWindow-1 {
					wantCapacity = 1_000_000
				}
				assertEstimatorRate(t, got, wantCapacity*estimator.settings.pacingGain)
			}
			got := estimator.observe(4_000_000, 0, time.Millisecond, time.Millisecond, false)
			assertEstimatorRate(t, got, 4_000_000*estimator.settings.pacingGain)
		})
	}
}

func TestAdaptiveEstimatorLimitedCongestionDoesNotCompound(t *testing.T) {
	for _, test := range []struct {
		profile   Profile
		gain      float64
		rttFactor float64
		loss      float64
	}{
		{ProfileConservative, 1.00, 0.575, 0.62},
		{ProfileBalanced, 1.08, 0.65, 0.745},
		{ProfileAggressive, 1.18, 0.75, 0.86},
	} {
		t.Run(test.profile.String(), func(t *testing.T) {
			const capacity = 8_000_000
			estimator := newAdaptiveEstimator(test.profile, capacity)
			current := estimator.observe(capacity, 0, time.Millisecond, 2*time.Millisecond, false)
			assertEstimatorRate(t, current, capacity*test.gain*test.rttFactor)
			learned := estimator
			for range 4 * deliveryRateWindow {
				current = estimator.observe(current, 0, time.Millisecond, 2*time.Millisecond, true)
				assertEstimatorRate(t, current, capacity*test.gain*test.rttFactor)
			}
			for range 4 * deliveryRateWindow {
				current = estimator.observe(current, 0.2, time.Millisecond, 2*time.Millisecond, true)
				assertEstimatorRate(t, current, capacity*test.gain*test.rttFactor*test.loss)
			}
			worseLoss := estimator.observe(current, 0.4, time.Millisecond, 2*time.Millisecond, true)
			if worseLoss >= current {
				t.Fatalf("worsening loss did not lower target: %g >= %g", worseLoss, current)
			}
			worseRTT := estimator.observe(current, 0.2, time.Millisecond, 4*time.Millisecond, true)
			if worseRTT >= current {
				t.Fatalf("worsening RTT did not lower target: %g >= %g", worseRTT, current)
			}
			recovered := estimator.observe(worseRTT, 0, time.Millisecond, time.Millisecond, true)
			assertEstimatorRate(t, recovered, capacity*test.gain)
			if estimator != learned {
				t.Fatal("RTT/loss changes changed retained bandwidth evidence")
			}
		})
	}
}

func TestAdaptiveEstimatorEmptyHistoryUsesPriorOnlyWhenLimited(t *testing.T) {
	for _, profile := range []Profile{ProfileConservative, ProfileBalanced, ProfileAggressive} {
		t.Run(profile.String(), func(t *testing.T) {
			const initial = 8_000_000
			estimator := newAdaptiveEstimator(profile, initial)
			prior := estimator
			// The comparison estimator has actual capacity evidence, so its
			// penalties should match the empty-history prior under the same RTT
			// and loss without inserting sparse ACK traffic into history.
			reference := newAdaptiveEstimator(profile, initial)
			want := reference.observe(initial, 0.2, time.Millisecond, 2*time.Millisecond, false)
			for range 4 * deliveryRateWindow {
				got := estimator.observe(100, 0.2, time.Millisecond, 2*time.Millisecond, true)
				assertEstimatorRate(t, got, want)
				if estimator != prior {
					t.Fatal("sparse limited sample initialized bandwidth history")
				}
			}
			got := estimator.observe(10_000_000, 0, time.Millisecond, time.Millisecond, true)
			assertEstimatorRate(t, got, 10_000_000*estimator.settings.pacingGain)
			if estimator.count != 1 || estimator.bandwidthEstimate() != 10_000_000 {
				t.Fatal("higher-than-prior limited observation was not learned")
			}
			estimator.reset()
			if estimator != prior {
				t.Fatal("reset did not restore empty history while retaining the initial prior")
			}
			got = estimator.observe(100_000, 0, time.Millisecond, time.Millisecond, false)
			assertEstimatorRate(t, got, 100_000*estimator.settings.pacingGain)
			if estimator.count != 1 || estimator.bandwidthEstimate() != 100_000 {
				t.Fatal("initial prior prevented learning a truly low capacity")
			}
		})
	}
}

func assertEstimatorRate(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.000001 {
		t.Fatalf("estimator target = %g, want %g", got, want)
	}
}
