package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
)

// A peer that has stopped reading leaves a real HTTP/2 SETTINGS ACK blocked
// while holding x/net's write mutex. State() must not be used for retirement:
// it takes that same mutex, unlike CanTakeNewRequest's memory-only state lock.
func TestWebH2RetirementAndCloseDoNotWaitForWireWrite(t *testing.T) {
	for _, active := range []int{0, 1} {
		t.Run(map[int]string{0: "drained", 1: "active"}[active], func(t *testing.T) {
			wire, h2 := newWebH2StalledWriter(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := &webH2ClientSession{raw: wire, h2: h2, opening: 1, active: active}
			client := &WebH2Client{
				ctx: ctx, cancel: cancel, dialGate: make(chan struct{}, 1),
				sessions: map[*webH2ClientSession]struct{}{session: {}},
			}
			// Leave the dial gate occupied so a second dial can only finish
			// through its deadline, without accessing the network.
			client.dialGate <- struct{}{}
			released := make(chan struct{})
			go func() { client.releaseSessionReservation(session); close(released) }()
			select {
			case <-released:
			case <-time.After(time.Second):
				_ = wire.Close()
				<-released
				t.Fatal("retirement waited for the HTTP/2 write mutex")
			}
			if got := wire.closes.Load(); (got != 0) != (active == 0) {
				t.Fatalf("wire closes=%d with active=%d", got, active)
			}
			dialCtx, dialCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer dialCancel()
			dialDone := make(chan error, 1)
			go func() { _, err := client.DialContext(dialCtx, "tcp", "target.invalid:443"); dialDone <- err }()
			select {
			case err := <-dialDone:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("pending dial error=%v, want context deadline", err)
				}
			case <-time.After(time.Second):
				_ = wire.Close()
				t.Fatal("pending dial did not honor its context deadline")
			}
			closed := make(chan error, 1)
			go func() { closed <- client.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				_ = wire.Close()
				<-closed
				t.Fatal("client Close did not interrupt the stalled wire")
			}
		})
	}
}

func TestWebH2RetirementKeepsOpeningReservation(t *testing.T) {
	wire, h2 := newWebH2StalledWriter(t)
	session := &webH2ClientSession{raw: wire, h2: h2, opening: 2}
	client := &WebH2Client{sessions: map[*webH2ClientSession]struct{}{session: {}}}
	client.releaseSessionReservation(session)
	if wire.closes.Load() != 0 || len(client.sessions) != 1 || session.opening != 1 {
		t.Fatal("retirement closed a session with another opening stream")
	}
	client.releaseSessionReservation(session)
	if wire.closes.Load() == 0 || len(client.sessions) != 0 || session.opening != 0 {
		t.Fatal("last opening reservation did not retire the drained session")
	}
}

func TestWebH2RetirementPreservesSiblingsAndHalfClose(t *testing.T) {
	target := startWebTCPEcho(t)
	client := newWebH2DeadlineTestClient(t, transport.DialFunc((&net.Dialer{}).DialContext))
	first := dialWebH2DeadlineTestConn(t, client, target)
	sibling := dialWebH2DeadlineTestConn(t, client, target)
	client.mu.Lock()
	old := client.current
	client.mu.Unlock()
	old.h2.SetDoNotReuse()
	fresh := dialWebH2DeadlineTestConn(t, client, target)
	assertH2Ownership(t, client, old, 2, 2)
	assertWebSessionSiblingEcho(t, first)
	assertWebSessionSiblingEcho(t, sibling)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	assertH2Ownership(t, client, old, 1, 2)
	assertWebSessionSiblingEcho(t, sibling)
	if err := sibling.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	assertWebEOFBody(t, sibling, nil)
	// Neither upload FIN nor response EOF releases the caller's net.Conn.
	assertH2Ownership(t, client, old, 1, 2)
	if err := sibling.Close(); err != nil {
		t.Fatal(err)
	}
	assertH2Ownership(t, client, old, 0, 1)
	assertWebSessionSiblingEcho(t, fresh)
}

func TestWebH2DeadlineReleasesRetiredStreamExactlyOnce(t *testing.T) {
	target := startWebTCPEcho(t)
	client := newWebH2DeadlineTestClient(t, transport.DialFunc((&net.Dialer{}).DialContext))
	oldConn := dialWebH2DeadlineTestConn(t, client, target)
	client.mu.Lock()
	old := client.current
	client.mu.Unlock()
	old.h2.SetDoNotReuse()
	fresh := dialWebH2DeadlineTestConn(t, client, target)
	assertH2Ownership(t, client, old, 1, 2)
	if err := oldConn.SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	_, _ = oldConn.Read(data[:])
	// Close joins any concurrent deadline callback, including onClose.
	if err := oldConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := oldConn.Close(); err != nil {
		t.Fatal(err)
	}
	assertH2Ownership(t, client, old, 0, 1)
	assertWebSessionSiblingEcho(t, fresh)
}

func TestWebH2RetiredStreamCloseRacesClientClose(t *testing.T) {
	for range 10 {
		t.Run("close", func(t *testing.T) {
			client := newWebH2DeadlineTestClient(t, transport.DialFunc((&net.Dialer{}).DialContext))
			target := startWebTCPEcho(t)
			conn := dialWebH2DeadlineTestConn(t, client, target)
			client.mu.Lock()
			old := client.current
			client.mu.Unlock()
			old.h2.SetDoNotReuse()
			_ = dialWebH2DeadlineTestConn(t, client, target)
			start, done := make(chan struct{}), make(chan struct{}, 3)
			for _, operation := range []func(){
				func() { _ = conn.Close() },
				func() { _ = client.Close() },
				func() { _ = conn.SetDeadline(time.Now()) },
			} {
				go func() { <-start; operation(); done <- struct{}{} }()
			}
			close(start)
			for range 3 {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("stream deadline/Close and client Close deadlocked")
				}
			}
			assertH2Ownership(t, client, old, 0, 0)
		})
	}
}

func assertH2Ownership(t *testing.T, client *WebH2Client, session *webH2ClientSession, active, sessions int) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if session.opening != 0 || session.active != active || len(client.sessions) != sessions {
		t.Fatalf("opening/active/sessions=%d/%d/%d, want 0/%d/%d", session.opening, session.active, len(client.sessions), active, sessions)
	}
}

type webH2StalledWriter struct {
	net.Conn
	signal  atomic.Bool
	closes  atomic.Int32
	started chan struct{}
	once    sync.Once
}

func (c *webH2StalledWriter) Write(p []byte) (int, error) {
	if c.signal.Load() {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Write(p)
}

func (c *webH2StalledWriter) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func newWebH2StalledWriter(t *testing.T) (*webH2StalledWriter, *http2.ClientConn) {
	t.Helper()
	raw, peer := net.Pipe()
	wire := &webH2StalledWriter{Conn: raw, started: make(chan struct{})}
	t.Cleanup(func() { _ = raw.Close(); _ = peer.Close() })
	initialRead := make(chan error, 1)
	go func() {
		prefix := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(peer, prefix); err != nil {
			initialRead <- err
			return
		}
		fr := http2.NewFramer(peer, peer)
		for range 2 { // Initial SETTINGS and connection WINDOW_UPDATE.
			if _, err := fr.ReadFrame(); err != nil {
				initialRead <- err
				return
			}
		}
		initialRead <- nil
	}()
	h2, err := (&http2.Transport{}).NewClientConn(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Always release the physical writer before closing the H2 wrapper.
	t.Cleanup(func() { _ = raw.Close(); _ = h2.Close() })
	if err := <-initialRead; err != nil {
		t.Fatal(err)
	}
	wire.signal.Store(true)
	settingsSent := make(chan error, 1)
	go func() { settingsSent <- http2.NewFramer(peer, peer).WriteSettings() }()
	select {
	case <-wire.started:
	case <-time.After(time.Second):
		t.Fatal("SETTINGS ACK did not reach the blocked transport writer")
	}
	if err := <-settingsSent; err != nil {
		t.Fatal(err)
	}
	return wire, h2
}
