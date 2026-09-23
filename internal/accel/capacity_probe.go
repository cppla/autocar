package accel

import (
	"math"
	"time"
)

const (
	maximumProbeBytes    = 1 << 20
	maximumProbeDuration = 2 * time.Second
	minimumProbeGap      = time.Second
	maximumProbeBackoff  = 16 * time.Second
)

// capacityProbe is a temporary, connection-wide admission excursion. It never
// writes into the estimator: only ordinary transport observations can establish
// higher capacity. All fields are protected by Controller.mu.
type capacityProbe struct {
	active        bool
	rate          int64
	remaining     float64
	deadline      time.Time
	entryCapacity float64
	entryRTT      time.Duration
	window        time.Duration
	gap           time.Duration

	// The last admitted bytes may not yet appear in wire counters. Allow a
	// bounded feedback grace period after admission ends, without more probes.
	pending         bool
	outcomeDeadline time.Time
	backoff         time.Duration
	nextAt          time.Time
	eligibleSamples int
	eligibleSince   time.Time
	eligibleRTT     time.Duration
}

func (c *Controller) pacingRateLocked() int64 {
	if c.probe.active {
		return c.probe.rate
	}
	return c.targetRate
}

func (c *Controller) probeRTTRoseLocked(rtt time.Duration) bool {
	baseline := c.probe.entryRTT
	if !c.probe.active && !c.probe.pending && c.probe.eligibleSamples > 0 {
		baseline = c.probe.eligibleRTT
	} else if !c.probe.active && !c.probe.pending {
		return false
	}
	// An absolute 1ms tolerance avoids treating microsecond scheduler noise on
	// loopback as a newly growing queue. Sustained RTT penalties still apply to
	// the steady target, independently of this relative abort signal.
	return rtt > baseline && rtt-baseline > max(time.Millisecond, baseline/4)
}

func (c *Controller) resetProbeLocked() {
	c.refillLocked(c.clock.Now())
	wasActive := c.probe.active
	c.probe = capacityProbe{}
	if wasActive {
		c.signalStateChangeLocked()
	}
}

func (c *Controller) abortProbeLocked(now time.Time) {
	if c.probe.active || c.probe.pending {
		c.resolveProbeLocked(now, false)
	}
	c.probe.eligibleSamples = 0
}

func (c *Controller) resolveProbeLocked(now time.Time, success bool) {
	wasActive := c.probe.active
	c.probe.active = false
	c.probe.pending = false
	c.probe.eligibleSamples = 0
	if success {
		c.probe.backoff = 0
	} else {
		c.probe.backoff = min(maximumProbeBackoff, max(2*minimumProbeGap, 2*c.probe.backoff))
	}
	c.probe.nextAt = now.Add(max(c.probe.gap, c.probe.backoff))
	if wasActive {
		c.signalStateChangeLocked()
	}
}

// Caller has already refilled through now at the old rate. The grace period is
// only for learning the result; no more high-rate admission is allowed.
func (c *Controller) finishProbeLocked(now time.Time) {
	c.probe.active = false
	c.probe.pending = true
	c.probe.outcomeDeadline = now.Add(max(250*time.Millisecond, 2*c.probe.window))
	c.probe.eligibleSamples = 0
	c.signalStateChangeLocked()
}

func (c *Controller) observeProbeLocked(snapshot Snapshot, now time.Time, limited, loss bool) {
	if c.profile == ProfileConservative {
		return
	}
	capacity := c.estimator.bandwidthEstimate()
	if c.probe.active || c.probe.pending {
		// The normal estimator has consumed this sample first, including real
		// backpressure and any higher delivery. Never discard evidence on abort.
		if loss || c.probeRTTRoseLocked(snapshot.SmoothedRTT) {
			c.abortProbeLocked(now)
		} else if capacity > c.probe.entryCapacity*1.02 {
			c.resolveProbeLocked(now, true)
		} else if !limited {
			c.abortProbeLocked(now)
		}
		return
	}
	if loss || !limited || c.estimator.count == 0 || float64(c.targetRate) >= capacity*.95 {
		c.probe.eligibleSamples = 0
		return
	}
	if c.probeRTTRoseLocked(snapshot.SmoothedRTT) {
		c.probe.eligibleSamples = 0
	}
	if c.probe.eligibleSamples == 0 {
		c.probe.eligibleSince = now
		c.probe.eligibleRTT = snapshot.SmoothedRTT
	}
	if c.probe.eligibleSamples < 3 {
		c.probe.eligibleSamples++
	}
	if c.probe.eligibleSamples < 3 || now.Sub(c.probe.eligibleSince) < time.Second || now.Before(c.probe.nextAt) {
		return
	}

	gain := 1.25
	if c.profile == ProfileAggressive {
		gain = 1.50
	}
	rate := int64(math.Min(float64(c.maximumRate), math.Min(capacity*gain, 2*float64(c.targetRate))))
	if float64(rate) <= capacity || rate <= c.targetRate {
		return
	}
	window := stableSampleWindow(snapshot.MinRTT)
	budget := math.Ceil(math.Max(2*c.burst, 2*float64(rate)*window.Seconds()))
	// Do not repeatedly run probes too small/short to produce even a complete
	// sample. Extremely large custom bursts or bandwidth-delay products are
	// outside this deliberately bounded application-level recovery mechanism.
	if budget > maximumProbeBytes {
		return
	}
	service := durationForBytes(budget, rate)
	if service > maximumProbeDuration-window {
		return
	}
	duration := max(100*time.Millisecond, service+window)
	// Clamp before multiplying potentially untrusted positive RTT durations.
	duration = max(duration, 2*min(snapshot.SmoothedRTT, maximumProbeDuration/2))
	gap := max(minimumProbeGap, 8*min(snapshot.SmoothedRTT, maximumProbeBackoff/8))
	c.probe.active = true
	c.probe.rate = rate
	c.probe.remaining = budget
	c.probe.deadline = now.Add(duration)
	c.probe.entryCapacity = capacity
	c.probe.entryRTT = snapshot.SmoothedRTT
	c.probe.window = window
	c.probe.gap = gap
	c.probe.eligibleSamples = 0
	c.signalStateChangeLocked()
}
