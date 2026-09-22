package accel

import (
	"math"
	"time"
)

const deliveryRateWindow = 8

type adaptiveSettings struct {
	pacingGain        float64
	rttThreshold      float64
	minimumRTTFactor  float64
	lossThreshold     float64
	lossSensitivity   float64
	minimumLossFactor float64
}

// adaptiveEstimator is an application-layer model built from public
// BBR-inspired principles: a bounded recent maximum of delivered bandwidth, an
// RTT baseline, and pacing above the estimated bottleneck rate. It is
// deliberately smaller than a transport congestion controller and has no
// control over the transport's congestion window or retransmission behavior.
type adaptiveEstimator struct {
	settings    adaptiveSettings
	initialRate float64
	rates       [deliveryRateWindow]float64
	next        int
	count       int
}

func newAdaptiveEstimator(profile Profile, initialRate int64) adaptiveEstimator {
	settings := adaptiveSettings{}
	switch profile {
	case ProfileConservative:
		settings = adaptiveSettings{
			pacingGain:        1.00,
			rttThreshold:      1.15,
			minimumRTTFactor:  0.50,
			lossThreshold:     0.01,
			lossSensitivity:   2.00,
			minimumLossFactor: 0.50,
		}
	case ProfileAggressive:
		settings = adaptiveSettings{
			pacingGain:        1.18,
			rttThreshold:      1.50,
			minimumRTTFactor:  0.70,
			lossThreshold:     0.06,
			lossSensitivity:   1.00,
			minimumLossFactor: 0.70,
		}
	default:
		settings = adaptiveSettings{
			pacingGain:        1.08,
			rttThreshold:      1.30,
			minimumRTTFactor:  0.60,
			lossThreshold:     0.03,
			lossSensitivity:   1.50,
			minimumLossFactor: 0.60,
		}
	}
	return adaptiveEstimator{settings: settings, initialRate: float64(initialRate)}
}

func (e *adaptiveEstimator) reset() {
	e.rates = [deliveryRateWindow]float64{}
	e.next = 0
	e.count = 0
}

func (e *adaptiveEstimator) observe(
	deliveredRate float64,
	lossRatio float64,
	minimumRTT time.Duration,
	smoothedRTT time.Duration,
	pacingLimited bool,
) float64 {
	deliveredRate = math.Max(0, deliveredRate)
	bottleneckRate := e.bandwidthEstimate()
	if !pacingLimited || deliveredRate > bottleneckRate {
		// An application pacing limit censors lower capacity observations. Do
		// not let those samples replace the unpenalized bandwidth history with
		// the result of our own previous RTT/loss reduction. Higher observations
		// remain useful evidence, and unconstrained samples can age out an old
		// maximum when the path really becomes slower.
		e.rates[e.next] = deliveredRate
		e.next = (e.next + 1) % len(e.rates)
		if e.count < len(e.rates) {
			e.count++
		}
		bottleneckRate = e.bandwidthEstimate()
	}

	// Always apply current congestion signals to capacity evidence, even when
	// a pacing-limited sample was not allowed to change that evidence.
	target := bottleneckRate * e.settings.pacingGain

	rttRatio := float64(smoothedRTT) / float64(minimumRTT)
	if rttRatio > e.settings.rttThreshold {
		rttFactor := e.settings.rttThreshold / rttRatio
		target *= math.Max(e.settings.minimumRTTFactor, rttFactor)
	}
	if lossRatio > e.settings.lossThreshold {
		lossFactor := 1 - (lossRatio-e.settings.lossThreshold)*e.settings.lossSensitivity
		target *= math.Max(e.settings.minimumLossFactor, lossFactor)
	}
	return target
}

func (e *adaptiveEstimator) bandwidthEstimate() float64 {
	if e.count == 0 {
		// This is only a prior, not a permanent minimum or a history entry. The
		// first non-limited observation may establish a lower path capacity.
		return e.initialRate
	}
	maximum := float64(0)
	for index := 0; index < e.count; index++ {
		maximum = math.Max(maximum, e.rates[index])
	}
	return maximum
}
