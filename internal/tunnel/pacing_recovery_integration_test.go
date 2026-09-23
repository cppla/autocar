package tunnel

import (
	"testing"
	"time"
)

// The adaptive defaults and QUIC path stay unchanged: only the real reader
// changes from fast to slow and back. The small, fixed receive window makes
// its backpressure observable instead of buffering the whole slow phase.
func TestQUICPacingRecoversAfterReceiverBackpressure(t *testing.T) {
	f := newFeedbackQUICFixture(t, 1, 16<<10)
	fast := runPacingRecoveryPhase(t, f, "fast before", 1<<20, 0)
	slow := runPacingRecoveryPhase(t, f, "receiver limited", 16*feedbackChunkSize, 120*time.Millisecond)
	if slow.write <= slow.wait {
		t.Fatalf("fixture did not establish transport backpressure: Write=%s, Wait=%s", slow.write, slow.wait)
	}
	// Even both worst-case balanced-profile penalties cannot reduce an
	// unchanged capacity target below 36%. Require an actual capacity decline,
	// not merely a transient RTT/loss penalty, before checking rediscovery.
	if slow.target >= fast.target*36/100 {
		t.Fatalf("fixture did not establish lower capacity: target %d -> %d", fast.target, slow.target)
	}

	var recovered [4]pacingRecoveryPhase
	for index := range recovered {
		recovered[index] = runPacingRecoveryPhase(t, f, "fast after", 512<<10, 0)
	}
	f.checkReverse(t)
	// The first two windows allow discovery. Require sustained useful progress
	// in both later windows instead of treating one target spike as recovery.
	// All bounds are relative to this connection's actual slow-reader phase,
	// not a machine-specific Mbps threshold or a race against another mode.
	for index := 2; index < len(recovered); index++ {
		phase := recovered[index]
		if phase.bytesPerSecond <= 1.25*float64(slow.target) {
			t.Errorf("recovery window %d did not provide useful progress: %.0f bytes/s, slow steady target %d bytes/s",
				index+1, phase.bytesPerSecond, slow.target)
		}
		// TargetBytesPerSecond excludes temporary probe rates, so this must
		// be a sustained target increase. Deterministic controller tests
		// separately isolate capacity discovery under persistent RTT penalties.
		if phase.target < slow.target*3/2 {
			t.Errorf("recovery window %d did not regain a meaningful target: %d, slow target %d",
				index+1, phase.target, slow.target)
		}
	}
}

type pacingRecoveryPhase struct {
	bytesPerSecond float64
	target         int64
	wait, write    time.Duration
}

func runPacingRecoveryPhase(t *testing.T, f *feedbackQUICFixture, name string, size int, readDelay time.Duration) pacingRecoveryPhase {
	t.Helper()
	started := time.Now()
	waitBefore := f.streamPacers[0].waitTime.Load()
	writeBefore := f.rawStreams[0].writeTime.Load()
	writer := f.run(func() error { return writeFeedbackPayload(f.serverStreams[0], size) })
	for read := 0; read < size; read += feedbackChunkSize {
		if readDelay > 0 {
			timer := time.NewTimer(readDelay)
			select {
			case <-timer.C:
			case <-f.ctx.Done():
				timer.Stop()
				t.Fatal(f.ctx.Err())
			}
		}
		if err := readFeedbackPayload(f.clientStreams[0], min(feedbackChunkSize, size-read)); err != nil {
			t.Fatalf("%s: %d/%d verified bytes: %v", name, read, size, err)
		}
	}
	f.await(t, writer)
	elapsed := time.Since(started)
	phase := pacingRecoveryPhase{
		bytesPerSecond: float64(size) / elapsed.Seconds(),
		target:         f.pacer.controller.TargetBytesPerSecond(),
		wait:           time.Duration(f.streamPacers[0].waitTime.Load() - waitBefore),
		write:          time.Duration(f.rawStreams[0].writeTime.Load() - writeBefore),
	}
	stats := f.serverStreams[0].conn.ConnectionStats()
	t.Logf("%s: bytes=%d duration=%s rate=%.0f bytes/s target=%d Wait=%s Write=%s lost=%d MinRTT=%s SRTT=%s",
		name, size, elapsed, phase.bytesPerSecond, phase.target, phase.wait, phase.write,
		stats.BytesLost, stats.MinRTT, stats.SmoothedRTT)
	return phase
}
