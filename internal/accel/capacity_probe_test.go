package accel

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestCapacityProbeRecoversWithPersistentRTTPenalty(t *testing.T) {
	for _, profile := range []Profile{ProfileBalanced, ProfileAggressive, ProfileConservative} {
		for _, chunk := range []int{32 << 10, 64 << 10} {
			t.Run(profile.String()+"/"+strconv.Itoa(chunk), func(t *testing.T) {
				clock := newFakeClock()
				controller, err := New(Config{Profile: profile, Clock: clock})
				if err != nil {
					t.Fatal(err)
				}
				// RTT never recovers: only real higher delivery can raise the
				// estimator. Transport work is independent of actual token Sleep.
				snapshot := Snapshot{At: clock.Now(), MinRTT: time.Millisecond, SmoothedRTT: 4 * time.Millisecond}
				mustObserveIdleSnapshot(t, controller, snapshot)
				type result struct {
					capacity float64
					target   int64
					higher   int
					lower    int
				}
				phase := func(name string, chunks int, wire time.Duration) result {
					t.Helper()
					started := clock.Now()
					r := result{}
					for range chunks {
						if err := controller.Wait(context.Background(), chunk); err != nil {
							t.Fatal(err)
						}
						if err := clock.Sleep(context.Background(), wire); err != nil {
							t.Fatal(err)
						}
						snapshot.At = clock.Now()
						snapshot.SentBytes += uint64(chunk)
						before := controller.estimator.bandwidthEstimate()
						next := controller.estimator.next
						mustObserveIdleSnapshot(t, controller, snapshot)
						if next != controller.estimator.next {
							if controller.estimator.rates[next] > before {
								r.higher++
							} else if controller.estimator.rates[next] < before {
								r.lower++
							}
						}
					}
					r.capacity = controller.estimator.bandwidthEstimate()
					r.target = controller.TargetBytesPerSecond()
					t.Logf("%s bytes=%d elapsed=%s capacity=%.0f steady=%d higher=%d lower=%d probe_active=%t", name, chunks*chunk, clock.Now().Sub(started), r.capacity, r.target, r.higher, r.lower, controller.probe.active)
					return r
				}
				fast := phase("fast", (1<<20)/chunk, time.Millisecond)
				slow := phase("slow", 24, 120*time.Millisecond)
				if slow.capacity >= fast.capacity/2 || slow.lower < deliveryRateWindow {
					t.Fatalf("fixture did not learn real lower capacity: fast=%+v slow=%+v", fast, slow)
				}
				// Empty-bucket recovery rules out relying on old initial tokens.
				controller.tokens = 0
				recoveryStart := clock.Now()
				recovery := phase("recovery", (4<<20)/chunk, time.Millisecond)
				if profile == ProfileConservative {
					if recovery.target < slow.target || recovery.higher != 0 || controller.probe.active {
						t.Fatalf("conservative behavior changed: slow=%+v recovered=%+v", slow, recovery)
					}
					return
				}
				if elapsed := clock.Now().Sub(recoveryStart); elapsed > 20*time.Second {
					t.Fatalf("recovery exceeded virtual-time bound: %s", elapsed)
				}
				if recovery.capacity < slow.capacity*1.5 || float64(recovery.target) < float64(slow.target)*1.5 || recovery.higher < 2 {
					t.Fatalf("failed real-sample recovery under unchanged RTT penalty: slow=%+v recovered=%+v", slow, recovery)
				}
				// A transient probe admission rate must never become the reported
				// steady target or estimator without a real observation.
				steady := controller.targetRate
				history := controller.estimator
				if err := controller.Wait(context.Background(), chunk); err != nil {
					t.Fatal(err)
				}
				if controller.targetRate != steady || controller.estimator != history {
					t.Fatal("admission manufactured capacity without a wire observation")
				}
				slowAgain := phase("slow again", 32, 120*time.Millisecond)
				if slowAgain.capacity >= recovery.capacity*.75 || slowAgain.lower < deliveryRateWindow {
					t.Fatalf("probes hid renewed transport backpressure: recovered=%+v slower=%+v", recovery, slowAgain)
				}
			})
		}
	}
}
