package tunnel

import (
	"testing"
	"time"
)

func TestPacingWriteActivityTracksConnectionIdleUnion(t *testing.T) {
	var activity pacingWriteActivity
	base := time.Unix(1, 0)
	check := func(at time.Duration, active int, idle time.Duration) {
		t.Helper()
		if activity.activeWrites != active {
			t.Fatalf("at %s: active = %d, want %d", at, activity.activeWrites, active)
		}
		if got := activity.idleTime(base.Add(at)); got != idle {
			t.Fatalf("at %s: idle = %s, want %s", at, got, idle)
		}
	}
	check(0, 0, 0) // A zero-value tracker has no pre-connection idle interval.
	activity.begin(base)
	check(time.Second, 1, 0)
	activity.begin(base.Add(time.Second))
	activity.end(base.Add(2 * time.Second))
	check(3*time.Second, 1, 0) // A sibling writer still has pending data.
	activity.end(base.Add(3 * time.Second))
	check(4*time.Second, 0, time.Second)
	check(5*time.Second, 0, 2*time.Second) // Sampling must not double-count.
	activity.begin(base.Add(5 * time.Second))
	check(8*time.Second, 1, 2*time.Second)
	activity.end(base.Add(9 * time.Second))
	activity.begin(base.Add(12 * time.Second))
	check(15*time.Second, 1, 5*time.Second)
}

func TestPacingWriteActivityAccumulatesShortSourceGaps(t *testing.T) {
	var activity pacingWriteActivity
	base := time.Unix(1, 0)
	for index := range 20 {
		started := base.Add(time.Duration(index) * time.Millisecond)
		activity.begin(started)
		activity.end(started.Add(400 * time.Microsecond))
	}
	// The cumulative counter retains gaps even when an observer's stable
	// sampling window spans many short writes.
	if got := activity.idleTime(base.Add(20 * time.Millisecond)); got != 12*time.Millisecond {
		t.Fatalf("cumulative idle = %s, want 12ms", got)
	}
}
