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
	settings adaptiveSettings
	rates    [deliveryRateWindow]float64
	next     int
	count    int
}

func newAdaptiveEstimator(profile Profile) adaptiveEstimator {
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
	return adaptiveEstimator{settings: settings}
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
) float64 {
	e.rates[e.next] = math.Max(0, deliveredRate)
	e.next = (e.next + 1) % len(e.rates)
	if e.count < len(e.rates) {
		e.count++
	}

	bottleneckRate := float64(0)
	for index := 0; index < e.count; index++ {
		bottleneckRate = math.Max(bottleneckRate, e.rates[index])
	}
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
