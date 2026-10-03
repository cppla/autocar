package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// This gate pauses the three context-watching session workers before their
// first cancellation select. It returns the real context's unchanged Done
// channel, and never fabricates an error, packet, stream, or authentication
// result. Holding a worker here models a scheduling pause, not blocked I/O.
type webUDPRemovedWorkerContext struct {
	context.Context
	budget  context.Context
	entered chan struct{}
	release <-chan struct{}
	calls   atomic.Int32
}

func (c *webUDPRemovedWorkerContext) Done() <-chan struct{} {
	if c.calls.Add(1) == 3 {
		close(c.entered)
	}
	select {
	case <-c.release:
	case <-c.budget.Done():
	}
	return c.Context.Done()
}

func webUDPRemovedWorkerClose(closeOwner func() error, started chan<- struct{}, result chan<- error, done chan struct{}) {
	defer close(done)
	started <- struct{}{}
	result <- closeOwner()
}

func TestWebUDPCloseJoinsRemovedSessionWorkers(t *testing.T) {
	t.Run("packet_close", func(t *testing.T) { testWebUDPCloseJoinsRemovedSessionWorkers(t, false) })
	t.Run("client_close", func(t *testing.T) { testWebUDPCloseJoinsRemovedSessionWorkers(t, true) })
}

func testWebUDPCloseJoinsRemovedSessionWorkers(t *testing.T, closeClient bool) {
	x := newWebUDPLateCloseJoinFixture(t, false)
	p := x.packet()
	// Open a real authenticated request, then install the scheduling context
	// before starting its workers. Registration/start is the same successful
	// handoff tail as session(), under p.mu; no concurrent context mutation.
	s, err := p.openSession(x.target.String())
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	ungate := sync.OnceFunc(func() { close(release) })
	ctx := &webUDPRemovedWorkerContext{Context: s.ctx, budget: x.f.ctx, entered: make(chan struct{}), release: release}
	s.ctx = ctx
	p.mu.Lock()
	p.sessions[s.target] = s
	s.start()
	p.mu.Unlock()
	workersDone := make(chan struct{})
	x.f.register(workersDone)
	go func() { defer close(workersDone); s.wg.Wait() }()
	// Always release workers before packet/client cleanup, including failure
	// against the original implementation. Their independent join is not Close.
	t.Cleanup(ungate)
	x.f.wait(ctx.entered, "three actual session workers at scheduling gate")
	// The fourth actual worker is reading Capsules on the real H3 stream.
	// Resetting that direction makes it call terminate and remove its target.
	s.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	x.f.wait(s.done, "actual Capsule worker terminated/removed session")
	p.mu.Lock()
	remaining := len(p.sessions)
	p.mu.Unlock()
	if remaining != 0 || len(x.c.udpSlots) != 0 {
		t.Fatalf("removed target/UDP slots=%d/%d, want 0/0", remaining, len(x.c.udpSlots))
	}
	x.requestJoin()
	x.zeroUsers()
	select {
	case <-workersDone:
		t.Fatal("scheduling gate did not retain actual session workers")
	default:
	}
	started := make(chan struct{}, 2)
	results := make(chan error, 2)
	first, second := make(chan struct{}), make(chan struct{})
	closeOwner := p.Close
	if closeClient {
		closeOwner = x.c.Close
	}
	x.f.register(first)
	x.f.register(second)
	go webUDPRemovedWorkerClose(closeOwner, started, results, first)
	x.f.wait(p.done, "Packet.Close cancellation/closed transition")
	go webUDPRemovedWorkerClose(closeOwner, started, results, second)
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-x.f.ctx.Done():
			t.Fatal("Close callers did not start")
		}
	}
	for _, closeDone := range []<-chan struct{}{first, second} {
		select {
		case <-closeDone:
			t.Error("owner Close returned while removed session workers were still owned")
		case <-time.After(100 * time.Millisecond):
		}
	}
	select {
	case <-workersDone:
		t.Error("workers exited before their scheduling gate was released")
	default:
	}
	ungate()
	x.f.wait(workersDone, "independent removed session worker join")
	x.f.wait(first, "first Close after worker completion")
	x.f.wait(second, "concurrent Close after worker completion")
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Errorf("Close=%v", err)
		}
	}
	if err := p.Send([]byte("after-close"), x.target.String()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Send after Close=%v, want net.ErrClosed", err)
	}
	t.Log("real TLS13/H3 request removed and admission released; all four session workers independently joined after gate release")
}
