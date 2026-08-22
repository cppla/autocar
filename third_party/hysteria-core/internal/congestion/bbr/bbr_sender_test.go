package bbr

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

type fixedClock struct{ now monotime.Time }

func (c fixedClock) Now() monotime.Time { return c.now }

type fixedRTTStats struct {
	min, latest, smoothed, deviation, maxAckDelay time.Duration
}

func (s *fixedRTTStats) MinRTT() time.Duration              { return s.min }
func (s *fixedRTTStats) LatestRTT() time.Duration           { return s.latest }
func (s *fixedRTTStats) SmoothedRTT() time.Duration         { return s.smoothed }
func (s *fixedRTTStats) MeanDeviation() time.Duration       { return s.deviation }
func (s *fixedRTTStats) MaxAckDelay() time.Duration         { return s.maxAckDelay }
func (s *fixedRTTStats) PTO(bool) time.Duration             { return s.smoothed + 4*s.deviation }
func (s *fixedRTTStats) UpdateRTT(send, _ time.Duration)    { s.latest, s.smoothed = send, send }
func (s *fixedRTTStats) SetMaxAckDelay(delay time.Duration) { s.maxAckDelay = delay }
func (s *fixedRTTStats) SetInitialRTT(rtt time.Duration)    { s.min, s.latest, s.smoothed = rtt, rtt, rtt }

func TestSetMaxDatagramSizeRescalesPacketSizedWindows(t *testing.T) {
	const oldMaxDatagramSize = congestion.ByteCount(1000)
	const newMaxDatagramSize = congestion.ByteCount(1400)
	const initialCongestionWindowPackets = congestion.ByteCount(20)
	const maxCongestionWindowPackets = congestion.ByteCount(80)

	b := newBbrSender(
		DefaultClock{},
		oldMaxDatagramSize,
		initialCongestionWindowPackets*oldMaxDatagramSize,
		maxCongestionWindowPackets*oldMaxDatagramSize,
		ProfileStandard,
	)
	b.congestionWindow = b.initialCongestionWindow

	b.SetMaxDatagramSize(newMaxDatagramSize)

	require.Equal(t, initialCongestionWindowPackets*newMaxDatagramSize, b.initialCongestionWindow)
	require.Equal(t, maxCongestionWindowPackets*newMaxDatagramSize, b.maxCongestionWindow)
	require.Equal(t, minCongestionWindowPackets*newMaxDatagramSize, b.minCongestionWindow)
	require.Equal(t, initialCongestionWindowPackets*newMaxDatagramSize, b.congestionWindow)
}

func TestSetMaxDatagramSizeClampsCongestionWindow(t *testing.T) {
	const oldMaxDatagramSize = congestion.ByteCount(1000)
	const newMaxDatagramSize = congestion.ByteCount(1400)

	b := NewBbrSender(DefaultClock{}, oldMaxDatagramSize, ProfileStandard)
	b.congestionWindow = b.minCongestionWindow + oldMaxDatagramSize
	b.recoveryWindow = b.minCongestionWindow + oldMaxDatagramSize

	b.SetMaxDatagramSize(newMaxDatagramSize)

	require.Equal(t, b.minCongestionWindow, b.congestionWindow)
	require.Equal(t, b.minCongestionWindow, b.recoveryWindow)
}

func TestNewBbrSenderAppliesProfiles(t *testing.T) {
	testCases := []struct {
		name                                string
		profile                             Profile
		highGain                            float64
		highCwndGain                        float64
		congestionWindowGainConstant        float64
		numStartupRtts                      int64
		drainToTarget                       bool
		detectOvershooting                  bool
		bytesLostMultiplier                 uint8
		enableAckAggregationDuringStartup   bool
		expireAckAggregationInStartup       bool
		enableOverestimateAvoidance         bool
		reduceExtraAckedOnBandwidthIncrease bool
	}{
		{
			name:                         "standard",
			profile:                      ProfileStandard,
			highGain:                     defaultHighGain,
			highCwndGain:                 derivedHighCWNDGain,
			congestionWindowGainConstant: 2.0,
			numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
			bytesLostMultiplier:          2,
		},
		{
			name:                                "conservative",
			profile:                             ProfileConservative,
			highGain:                            2.25,
			highCwndGain:                        1.75,
			congestionWindowGainConstant:        1.75,
			numStartupRtts:                      2,
			drainToTarget:                       true,
			detectOvershooting:                  true,
			bytesLostMultiplier:                 1,
			enableOverestimateAvoidance:         true,
			reduceExtraAckedOnBandwidthIncrease: true,
		},
		{
			name:                              "aggressive",
			profile:                           ProfileAggressive,
			highGain:                          3.0,
			highCwndGain:                      2.25,
			congestionWindowGainConstant:      2.5,
			numStartupRtts:                    4,
			bytesLostMultiplier:               2,
			enableAckAggregationDuringStartup: true,
			expireAckAggregationInStartup:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBbrSender(DefaultClock{}, congestion.InitialPacketSize, tc.profile)
			require.Equal(t, tc.profile, b.profile)
			require.Equal(t, tc.highGain, b.highGain)
			require.Equal(t, tc.highCwndGain, b.highCwndGain)
			require.Equal(t, tc.congestionWindowGainConstant, b.congestionWindowGainConstant)
			require.Equal(t, tc.numStartupRtts, b.numStartupRtts)
			require.Equal(t, tc.drainToTarget, b.drainToTarget)
			require.Equal(t, tc.detectOvershooting, b.detectOvershooting)
			require.Equal(t, tc.bytesLostMultiplier, b.bytesLostMultiplierWhileDetectingOvershooting)
			require.Equal(t, tc.enableAckAggregationDuringStartup, b.enableAckAggregationDuringStartup)
			require.Equal(t, tc.expireAckAggregationInStartup, b.expireAckAggregationInStartup)
			require.Equal(t, tc.enableOverestimateAvoidance, b.sampler.IsOverestimateAvoidanceEnabled())
			require.Equal(t, tc.reduceExtraAckedOnBandwidthIncrease, b.sampler.maxAckHeightTracker.reduceExtraAckedOnBandwidthIncrease)
			require.Equal(t, b.highGain, b.pacingGain)
			require.Equal(t, b.highCwndGain, b.congestionWindowGain)
		})
	}
}

func TestParseProfile(t *testing.T) {
	profile, err := ParseProfile("")
	require.NoError(t, err)
	require.Equal(t, ProfileStandard, profile)

	profile, err = ParseProfile("Aggressive")
	require.NoError(t, err)
	require.Equal(t, ProfileAggressive, profile)

	_, err = ParseProfile("turbo")
	require.EqualError(t, err, `unsupported BBR profile "turbo"`)
}

func TestCongestionEventUpdatesDeliveryRateAndMinimumRTT(t *testing.T) {
	now := monotime.Now()
	b := NewBbrSender(fixedClock{now: now}, 1200, ProfileStandard)
	b.SetRTTStatsProvider(&fixedRTTStats{min: 100 * time.Millisecond, smoothed: 100 * time.Millisecond})

	const packetSize = congestion.ByteCount(1200)
	b.OnPacketSent(now, 0, 1, packetSize, true)
	ackedAt := now.Add(100 * time.Millisecond)
	b.OnCongestionEventEx(packetSize, ackedAt, []congestion.AckedPacketInfo{{
		PacketNumber: 1,
		BytesAcked:   packetSize,
		ReceivedTime: ackedAt,
	}}, nil)

	require.Equal(t, 100*time.Millisecond, b.minRtt)
	require.Positive(t, b.bandwidthEstimate())
	require.Equal(t, packetSize, b.sampler.TotalBytesAcked())
	require.Positive(t, b.PacingRate())
}

func TestBBRStateMachineStartupDrainProbeBandwidthAndProbeRTT(t *testing.T) {
	now := monotime.Now()
	b := NewBbrSender(fixedClock{now: now}, 1200, ProfileStandard)
	b.SetRTTStatsProvider(&fixedRTTStats{min: 100 * time.Millisecond, smoothed: 100 * time.Millisecond})
	b.minRtt = 100 * time.Millisecond
	b.minRttTimestamp = now
	b.maxBandwidth.Update(BandwidthFromDelta(12000, 100*time.Millisecond), 1)
	b.isAtFullBandwidth = true

	target := b.getTargetCongestionWindow(1)
	b.bytesInFlight = target + b.maxDatagramSize
	b.maybeExitStartupOrDrain(now)
	require.EqualValues(t, bbrModeDrain, b.mode)
	require.Equal(t, b.drainGain, b.pacingGain)

	b.bytesInFlight = target
	b.maybeExitStartupOrDrain(now.Add(time.Millisecond))
	require.EqualValues(t, bbrModeProbeBw, b.mode)
	require.Equal(t, b.congestionWindowGainConstant, b.congestionWindowGain)

	b.exitingQuiescence = false
	b.bytesInFlight = 0
	probeStart := now.Add(minRttExpiry + time.Second)
	b.maybeEnterOrExitProbeRtt(probeStart, true, true)
	require.EqualValues(t, bbrModeProbeRtt, b.mode)
	require.Equal(t, b.minCongestionWindow, b.GetCongestionWindow())
	require.Equal(t, probeStart.Add(probeRttTime), b.exitProbeRttAt)

	probeEnd := probeStart.Add(probeRttTime + time.Millisecond)
	b.maybeEnterOrExitProbeRtt(probeEnd, true, false)
	require.EqualValues(t, bbrModeProbeBw, b.mode)
	require.Equal(t, probeEnd, b.minRttTimestamp)
}

func TestBBRLossRecoveryConservationGrowthAndExit(t *testing.T) {
	b := NewBbrSender(DefaultClock{}, 1200, ProfileStandard)
	b.isAtFullBandwidth = true
	b.lastSentPacket = 20
	b.bytesInFlight = 12000

	b.updateRecoveryState(10, true, false)
	require.EqualValues(t, bbrRecoveryStateConservation, b.recoveryState)
	require.Equal(t, congestion.PacketNumber(20), b.endRecoveryAt)
	b.calculateRecoveryWindow(1200, 1200)
	require.GreaterOrEqual(t, b.recoveryWindow, b.minCongestionWindow)

	b.updateRecoveryState(20, false, true)
	require.EqualValues(t, bbrRecoveryStateGrowth, b.recoveryState)
	before := b.recoveryWindow
	b.calculateRecoveryWindow(1200, 0)
	require.Greater(t, b.recoveryWindow, before)

	b.updateRecoveryState(21, false, false)
	require.EqualValues(t, bbrRecoveryStateNotInRecovery, b.recoveryState)
}
