// Package accel provides optional application-layer write pacing.
//
// The controller sits above a transport. It never replaces, disables, or
// modifies the transport's own congestion control and loss recovery.
package accel

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	// Start at 64 Mbit/s. QUIC's own controller remains the hard safety bound;
	// the adaptive layer then converges from observed path statistics instead of
	// trapping itself behind an unrealistically low initial application cap.
	defaultInitialRate  = int64(8_000_000)
	defaultMinimumRate  = int64(64 << 10)
	defaultMaximumRate  = int64(1 << 30)
	defaultBurstBytes   = int64(64 << 10)
	maxExactInteger     = int64(1 << 52)
	minimumSampleWindow = 10 * time.Millisecond
	maximumSampleWindow = 250 * time.Millisecond
)

// Mode selects the application-layer pacing policy.
type Mode string

const (
	// ModeAdaptive uses delivery-rate and RTT observations to pace writes. It is
	// the default when Config.Mode is empty.
	ModeAdaptive Mode = "adaptive"
	// ModeReno bypasses application-layer pacing. The pinned quic-go transport
	// uses Reno by default; this package does not implement or replace that
	// transport policy.
	ModeReno Mode = "reno"
	// ModeFixedRate paces writes at an explicitly configured byte rate.
	ModeFixedRate Mode = "fixed-rate"
)

// String returns the stable configuration and telemetry label for the mode.
func (m Mode) String() string { return string(m) }

// Profile controls how readily adaptive pacing probes above its estimated
// delivery rate and how strongly it responds to queue and loss signals.
type Profile string

const (
	ProfileConservative Profile = "conservative"
	ProfileBalanced     Profile = "balanced"
	ProfileAggressive   Profile = "aggressive"
)

// String returns the stable configuration and telemetry label for the profile.
func (p Profile) String() string { return string(p) }

// Snapshot is a transport-neutral view of cumulative connection statistics.
// An adapter outside this package can populate it from any transport exposing
// equivalent counters. SentBytes includes retransmitted bytes. LostBytes is
// allowed to decrease when a transport corrects an earlier loss declaration.
//
// At may be zero, in which case Observe uses the controller's clock. MinRTT and
// SmoothedRTT may be zero before the transport has an RTT sample; such a
// snapshot establishes a counter baseline but does not change the target rate.
type Snapshot struct {
	At          time.Time
	SentBytes   uint64
	LostBytes   uint64
	MinRTT      time.Duration
	SmoothedRTT time.Duration
}

// Clock provides the time operations used by pacing. Implementations must be
// safe for concurrent use. Sleep must return promptly when ctx is canceled.
// Supplying a Clock is primarily useful for deterministic tests.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, duration time.Duration) error
}

// Config describes an application-layer controller. Byte rates are decimal
// bytes per second. Zero values select documented defaults except that a fixed
// rate must always be explicit.
type Config struct {
	Mode    Mode
	Profile Profile

	InitialRateBytesPerSecond int64
	MinRateBytesPerSecond     int64
	MaxRateBytesPerSecond     int64
	FixedRateBytesPerSecond   int64
	BurstBytes                int64

	Clock Clock
}

// Controller is a concurrency-safe application-layer pacer. A typical writer
// calls Observe with a fresh transport Snapshot, then calls Wait before writing
// the corresponding number of application bytes.
type Controller struct {
	mu sync.Mutex
	// admission serializes token admission without tying cancellation to a
	// mutex acquisition. Only the holder sleeps for capacity, so concurrent
	// streams neither reserve stale capacity nor wake as a herd.
	admission chan struct{}

	mode    Mode
	profile Profile
	clock   Clock

	initialRate int64
	minimumRate int64
	maximumRate int64
	targetRate  int64

	burst       float64
	tokens      float64
	lastRefill  time.Time
	stateChange chan struct{}

	haveSnapshot bool
	previous     Snapshot
	estimator    adaptiveEstimator
}

type normalizedConfig struct {
	mode        Mode
	profile     Profile
	initialRate int64
	minimumRate int64
	maximumRate int64
	fixedRate   int64
	burstBytes  int64
	clock       Clock
}

var (
	// ErrInvalidConfig marks a rejected controller configuration.
	ErrInvalidConfig = errors.New("accel: invalid config")
	// ErrInvalidSnapshot marks an observation that cannot form a valid sample.
	ErrInvalidSnapshot = errors.New("accel: invalid snapshot")
	// ErrModeMismatch reports an operation that is unavailable in the selected
	// mode.
	ErrModeMismatch = errors.New("accel: mode mismatch")
)

// Validate checks config after applying zero-value defaults.
func Validate(config Config) error {
	_, err := normalizeConfig(config)
	return err
}

// New validates config and returns a controller with one full burst of initial
// tokens. ModeAdaptive and ProfileBalanced are the zero-value defaults.
func New(config Config) (*Controller, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}

	target := normalized.initialRate
	if normalized.mode == ModeFixedRate {
		target = normalized.fixedRate
	}
	if normalized.mode == ModeReno {
		target = 0
	}

	return &Controller{
		mode:        normalized.mode,
		profile:     normalized.profile,
		clock:       normalized.clock,
		initialRate: normalized.initialRate,
		minimumRate: normalized.minimumRate,
		maximumRate: normalized.maximumRate,
		targetRate:  target,
		burst:       float64(normalized.burstBytes),
		tokens:      float64(normalized.burstBytes),
		lastRefill:  normalized.clock.Now(),
		admission:   makeAdmissionToken(),
		stateChange: make(chan struct{}),
		estimator:   newAdaptiveEstimator(normalized.profile),
	}, nil
}

func makeAdmissionToken() chan struct{} {
	token := make(chan struct{}, 1)
	token <- struct{}{}
	return token
}

// Mode returns the controller's stable mode label.
func (c *Controller) Mode() Mode { return c.mode }

// Profile returns the adaptive profile label. It remains available in bypass
// and fixed-rate modes so shared configuration and telemetry stay consistent.
func (c *Controller) Profile() Profile { return c.profile }

// TargetBytesPerSecond reports the current application pacing target. It
// returns zero in bypass mode.
func (c *Controller) TargetBytesPerSecond() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.targetRate
}

// BurstBytes reports the largest application chunk the token bucket can admit
// at once. Transport adapters use it to split large writes physically instead
// of merely delaying one oversized write and releasing it as a single burst.
func (c *Controller) BurstBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(c.burst)
}

// SetFixedRate changes the pacing target of a fixed-rate controller. Existing
// tokens remain bounded by the configured burst.
func (c *Controller) SetFixedRate(bytesPerSecond int64) error {
	if c.mode != ModeFixedRate {
		return fmt.Errorf("%w: SetFixedRate requires mode %q", ErrModeMismatch, ModeFixedRate)
	}
	if err := validatePositive("fixed rate", bytesPerSecond); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTargetRateLocked(bytesPerSecond)
	return nil
}

// Observe adds one cumulative transport sample. Only adaptive mode consumes
// observations; other modes accept them as no-ops so a writer can use one
// instrumentation path for every controller mode.
func (c *Controller) Observe(snapshot Snapshot) error {
	if c.mode != ModeAdaptive {
		return nil
	}
	if snapshot.MinRTT < 0 || snapshot.SmoothedRTT < 0 {
		return fmt.Errorf("%w: RTT values cannot be negative", ErrInvalidSnapshot)
	}
	if snapshot.At.IsZero() {
		snapshot.At = c.clock.Now()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.haveSnapshot {
		c.previous = snapshot
		c.haveSnapshot = true
		return nil
	}
	if !snapshot.At.After(c.previous.At) {
		return fmt.Errorf("%w: sample time must increase", ErrInvalidSnapshot)
	}

	if snapshot.SentBytes < c.previous.SentBytes {
		// A cumulative sent-byte reset denotes a new transport epoch. Rebaseline
		// instead of interpreting wrapped counters as a huge delivery sample.
		c.previous = snapshot
		c.estimator.reset()
		c.setTargetRateLocked(c.initialRate)
		return nil
	}

	elapsed := snapshot.At.Sub(c.previous.At)
	// Connection counters are sampled by every writer. Ignore sub-window calls
	// without advancing the baseline so concurrent streams cannot turn one packet
	// observed a few microseconds later into a terabyte-per-second rate sample.
	if elapsed < stableSampleWindow(snapshot.MinRTT) {
		return nil
	}

	sentDelta := snapshot.SentBytes - c.previous.SentBytes
	lostDelta := uint64(0)
	if snapshot.LostBytes >= c.previous.LostBytes {
		lostDelta = snapshot.LostBytes - c.previous.LostBytes
	}
	c.previous = snapshot

	if sentDelta == 0 || snapshot.MinRTT == 0 || snapshot.SmoothedRTT == 0 {
		return nil
	}
	if lostDelta > sentDelta {
		// Loss declarations can lag the sends to which they refer. Cap the
		// interval ratio instead of allowing delayed accounting to underflow.
		lostDelta = sentDelta
	}
	deliveredDelta := sentDelta - lostDelta
	deliveredRate := float64(deliveredDelta) / elapsed.Seconds()
	lossRatio := float64(lostDelta) / float64(sentDelta)

	target := c.estimator.observe(deliveredRate, lossRatio, snapshot.MinRTT, snapshot.SmoothedRTT)
	target = math.Max(float64(c.minimumRate), math.Min(float64(c.maximumRate), target))
	c.setTargetRateLocked(int64(math.Round(target)))
	return nil
}

func stableSampleWindow(minimumRTT time.Duration) time.Duration {
	window := minimumRTT / 4
	if window < minimumSampleWindow {
		return minimumSampleWindow
	}
	if window > maximumSampleWindow {
		return maximumSampleWindow
	}
	return window
}

// Wait blocks until n application bytes are admitted by the selected pacing
// policy. Requests larger than the configured burst are admitted in bounded
// chunks. Bypass mode returns immediately, subject only to context cancellation.
func (c *Controller) Wait(ctx context.Context, n int) error {
	if n < 0 {
		return fmt.Errorf("%w: byte count cannot be negative", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if n == 0 || c.mode == ModeReno {
		return nil
	}

	remaining := int64(n)
	admitted := int64(0)
	for remaining > 0 {
		chunk := remaining
		if chunk > int64(c.burst) {
			chunk = int64(c.burst)
		}
		if err := c.admit(ctx, float64(chunk)); err != nil {
			c.refund(float64(admitted))
			return err
		}
		admitted += chunk
		remaining -= chunk
	}
	return nil
}

// admit waits for one bounded chunk. The channel token makes acquisition
// context-aware and ensures that only one stream sleeps for capacity. Target
// changes interrupt that sleep and force the delay to be recalculated against
// the new rate; no future capacity is pre-reserved at a stale rate.
func (c *Controller) admit(ctx context.Context, amount float64) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.admission:
	}
	defer func() { c.admission <- struct{}{} }()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		c.mu.Lock()
		c.refillLocked(c.clock.Now())
		if c.tokens >= amount {
			c.tokens -= amount
			c.mu.Unlock()
			return nil
		}
		missing := amount - c.tokens
		delay := durationForBytes(missing, c.targetRate)
		stateChange := c.stateChange
		c.mu.Unlock()

		if err := c.sleepUntilStateChange(ctx, delay, stateChange); err != nil {
			return err
		}
	}
}

func (c *Controller) sleepUntilStateChange(
	ctx context.Context,
	delay time.Duration,
	stateChange <-chan struct{},
) error {
	sleepCtx, cancelSleep := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	stopWatcher := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-stateChange:
			cancelSleep()
		case <-stopWatcher:
		}
	}()

	err := c.clock.Sleep(sleepCtx, delay)
	close(stopWatcher)
	<-watcherDone
	cancelSleep()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		// A rate update interrupted the sleep. The caller will refill and
		// recompute the outstanding delay with the new target.
		return nil
	}
	return err
}

func (c *Controller) refund(amount float64) {
	if amount == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refillLocked(c.clock.Now())
	c.tokens += amount
	if c.tokens > c.burst {
		c.tokens = c.burst
	}
	c.signalStateChangeLocked()
}

func normalizeConfig(config Config) (normalizedConfig, error) {
	mode := config.Mode
	if mode == "" {
		mode = ModeAdaptive
	}
	switch mode {
	case ModeAdaptive, ModeReno, ModeFixedRate:
	default:
		return normalizedConfig{}, fmt.Errorf("%w: unsupported mode %q", ErrInvalidConfig, config.Mode)
	}

	profile := config.Profile
	if profile == "" {
		profile = ProfileBalanced
	}
	switch profile {
	case ProfileConservative, ProfileBalanced, ProfileAggressive:
	default:
		return normalizedConfig{}, fmt.Errorf("%w: unsupported profile %q", ErrInvalidConfig, config.Profile)
	}

	initialRate := valueOrDefault(config.InitialRateBytesPerSecond, defaultInitialRate)
	minimumRate := valueOrDefault(config.MinRateBytesPerSecond, defaultMinimumRate)
	maximumRate := valueOrDefault(config.MaxRateBytesPerSecond, defaultMaximumRate)
	burstBytes := valueOrDefault(config.BurstBytes, defaultBurstBytes)
	for name, value := range map[string]int64{
		"initial rate": initialRate,
		"minimum rate": minimumRate,
		"maximum rate": maximumRate,
		"burst bytes":  burstBytes,
	} {
		if err := validatePositive(name, value); err != nil {
			return normalizedConfig{}, err
		}
	}
	if minimumRate > initialRate || initialRate > maximumRate {
		return normalizedConfig{}, fmt.Errorf(
			"%w: rates must satisfy minimum <= initial <= maximum",
			ErrInvalidConfig,
		)
	}

	fixedRate := config.FixedRateBytesPerSecond
	if mode == ModeFixedRate {
		if err := validatePositive("fixed rate", fixedRate); err != nil {
			return normalizedConfig{}, err
		}
	}

	clock := config.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return normalizedConfig{
		mode:        mode,
		profile:     profile,
		initialRate: initialRate,
		minimumRate: minimumRate,
		maximumRate: maximumRate,
		fixedRate:   fixedRate,
		burstBytes:  burstBytes,
		clock:       clock,
	}, nil
}

func validatePositive(name string, value int64) error {
	if value <= 0 {
		return fmt.Errorf("%w: %s must be positive", ErrInvalidConfig, name)
	}
	if value > maxExactInteger {
		return fmt.Errorf("%w: %s exceeds the supported range", ErrInvalidConfig, name)
	}
	return nil
}

func valueOrDefault(value, defaultValue int64) int64 {
	if value == 0 {
		return defaultValue
	}
	return value
}

func (c *Controller) setTargetRateLocked(rate int64) {
	c.refillLocked(c.clock.Now())
	if c.targetRate == rate {
		return
	}
	c.targetRate = rate
	c.signalStateChangeLocked()
}

func (c *Controller) signalStateChangeLocked() {
	close(c.stateChange)
	c.stateChange = make(chan struct{})
}

func durationForBytes(amount float64, rate int64) time.Duration {
	seconds := amount / float64(rate)
	nanoseconds := math.Ceil(seconds * float64(time.Second))
	if nanoseconds > float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	if nanoseconds < 1 {
		return time.Nanosecond
	}
	return time.Duration(nanoseconds)
}

func (c *Controller) refillLocked(now time.Time) {
	elapsed := now.Sub(c.lastRefill)
	if elapsed <= 0 {
		return
	}
	c.tokens += elapsed.Seconds() * float64(c.targetRate)
	if c.tokens > c.burst {
		c.tokens = c.burst
	}
	c.lastRefill = now
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
