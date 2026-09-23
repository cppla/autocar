package main

import (
	"math"
	"testing"
)

func TestPercentileMedian(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sorted []float64
		want   float64
	}{
		{"empty", nil, 0},
		{"single", []float64{3}, 3},
		{"two", []float64{2, 10}, 6},
		{"four", []float64{1, 2, 8, 100}, 5},
		{"odd", []float64{1, 3, 100}, 3},
		{"repeated", []float64{4, 4, 4, 4}, 4},
		{"large", []float64{math.MaxFloat64, math.MaxFloat64}, math.MaxFloat64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := percentile(tc.sorted, 0.5); got != tc.want {
				t.Fatalf("median(%v) = %v, want %v", tc.sorted, got, tc.want)
			}
		})
	}
}

func TestPercentileTailConventionUnchanged(t *testing.T) {
	values := []float64{2, 10}
	if got := percentile(values, 0.05); got != 2 {
		t.Fatalf("p05 = %v, want 2", got)
	}
	if got := percentile(values, 0.95); got != 10 {
		t.Fatalf("p95 = %v, want 10", got)
	}
}
