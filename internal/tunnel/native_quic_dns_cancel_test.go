package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const nativeQUICDNSCancelChild = "AUTOCAR_NATIVE_QUIC_DNS_CANCEL_CHILD"

func TestNativeQUICCloseCancelsDNSLookup(t *testing.T) {
	nativeQUICDNSCancelIsolated(t, "close", "TestNativeQUICCloseCancelsDNSLookup")
}

func TestNativeQUICDialBudgetIncludesDNSLookup(t *testing.T) {
	nativeQUICDNSCancelIsolated(t, "budget", "TestNativeQUICDialBudgetIncludesDNSLookup")
}

// Resolver replacement is confined to an isolated test process. The parent
// never mutates net.DefaultResolver, and every actual DNS socket is loopback.
func nativeQUICDNSCancelIsolated(t *testing.T, mode, top string) {
	t.Helper()
	if os.Getenv(nativeQUICDNSCancelChild) == mode {
		nativeQUICDNSCancelChildTest(t, mode)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$",
		"-test.count=1", "-test.v", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), nativeQUICDNSCancelChild+"="+mode)
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		t.Logf("isolated child | %s", line)
	}
	if ctx.Err() != nil {
		t.Fatalf("isolated DNS probe exceeded its outer budget: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("isolated DNS probe failed: %v", err)
	}
}

type nativeQUICDNSQuestion struct {
	id        uint16
	questions []dnsmessage.Question
	peer      *net.UDPAddr
}

// Embedding UDPConn preserves its PacketConn capability so the real resolver
// exchanges ordinary UDP DNS messages. Close records actual socket disposal;
// it deliberately does not add a context-cancellation watcher.
type nativeQUICDNSConn struct {
	*net.UDPConn
	once sync.Once
	done chan struct{}
	err  error
}

func (c *nativeQUICDNSConn) Close() error {
	c.once.Do(func() {
		c.err = c.UDPConn.Close()
		close(c.done)
	})
	return c.err
}

type nativeQUICDNSFixture struct {
	peer      *net.UDPConn
	peerDone  chan struct{}
	querySeen chan struct{}
	mu        sync.Mutex
	released  bool
	stopping  bool
	questions []nativeQUICDNSQuestion
	conns     []*nativeQUICDNSConn
	attempt   *quicDialAttempt
	queries   int
	responses int
	problem   error
	client    *Client
}

func (f *nativeQUICDNSFixture) serve() {
	defer close(f.peerDone)
	buf := make([]byte, 4096)
	for {
		n, peer, err := f.peer.ReadFromUDP(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				f.recordProblem(err)
			}
			return
		}
		var message dnsmessage.Message
		if err := message.Unpack(buf[:n]); err != nil || message.Header.Response || len(message.Questions) != 1 {
			f.recordProblem(errors.New("unexpected DNS query framing"))
			continue
		}
		q := nativeQUICDNSQuestion{id: message.Header.ID, questions: message.Questions, peer: peer}
		f.mu.Lock()
		f.queries++
		released := f.released
		if !released {
			if len(f.questions) >= 32 {
				f.problem = errors.New("unexpected DNS query count beyond fixture bound")
			} else {
				f.questions = append(f.questions, q)
			}
		}
		f.mu.Unlock()
		select {
		case f.querySeen <- struct{}{}:
		default:
		}
		if released {
			f.respond(q)
		}
	}
}

func (f *nativeQUICDNSFixture) recordProblem(err error) {
	f.mu.Lock()
	if f.problem == nil {
		f.problem = err
	}
	f.mu.Unlock()
}

func (f *nativeQUICDNSFixture) respond(q nativeQUICDNSQuestion) {
	response := dnsmessage.Message{Header: dnsmessage.Header{
		ID: q.id, Response: true, Authoritative: true, RecursionAvailable: true,
		RCode: dnsmessage.RCodeNameError,
	}, Questions: q.questions}
	payload, err := response.Pack()
	if err == nil {
		_, err = f.peer.WriteToUDP(payload, q.peer)
	}
	if err != nil {
		f.recordProblem(err)
		return
	}
	f.mu.Lock()
	f.responses++
	f.mu.Unlock()
}

func (f *nativeQUICDNSFixture) releaseResponses() {
	f.mu.Lock()
	f.released = true
	questions := f.questions
	f.questions = nil
	f.mu.Unlock()
	for _, q := range questions {
		f.respond(q)
	}
}

func (f *nativeQUICDNSFixture) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		f.recordProblem(errors.New("unexpected non-UDP resolver dial"))
		return nil, errors.New("fixture supports UDP DNS only")
	}
	f.mu.Lock()
	stopping := f.stopping
	f.mu.Unlock()
	if stopping {
		return nil, net.ErrClosed
	}
	// The DNS service address passed by the resolver is deliberately ignored.
	// This numeric owned endpoint never recursively performs DNS or leaves the
	// process's loopback network.
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", f.peer.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	raw, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("fixture DNS connection is not UDP")
	}
	tracked := &nativeQUICDNSConn{UDPConn: raw, done: make(chan struct{})}
	f.client.mu.Lock()
	attempt := f.client.dialing
	f.client.mu.Unlock()
	f.mu.Lock()
	if f.stopping {
		f.mu.Unlock()
		_ = tracked.Close()
		return nil, net.ErrClosed
	}
	f.conns = append(f.conns, tracked)
	if f.attempt == nil {
		f.attempt = attempt
	}
	f.mu.Unlock()
	return tracked, nil
}

func nativeQUICDNSCancelChildTest(t *testing.T, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	// Close is intentionally tested before the long physical timeout. The
	// budget case instead separates a short physical timer from its live caller.
	dialBudget := 4 * time.Second
	if mode == "budget" {
		dialBudget = 150 * time.Millisecond
	}
	client, err := NewClient(ClientConfig{ServerAddress: "native-dns-owner.invalid.:443",
		Token: testToken, TLSConfig: &tls.Config{ServerName: "native-dns-owner.invalid"},
		QUICDialTimeout: dialBudget})
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	f := &nativeQUICDNSFixture{peer: peer, peerDone: make(chan struct{}),
		querySeen: make(chan struct{}, 1), client: client}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: f.dial}
	go f.serve()
	callerDone := make(chan struct{})
	callerResult := make(chan error, 1)
	closeDone := make(chan struct{})
	closeResult := make(chan error, 1)
	var closeOnce sync.Once
	startClose := func() {
		closeOnce.Do(func() {
			go func() {
				defer close(closeDone)
				closeResult <- client.Close()
			}()
		})
	}
	// Cleanup independently unblocks actual DNS I/O, then disposes every owned
	// socket and joins our caller/Close/peer workers even after a failed oracle.
	// Standard-library singleflight DNS goroutines are not claimed to be part
	// of Client.Close's physical-dial WaitGroup.
	t.Cleanup(func() {
		f.releaseResponses()
		startClose()
		f.mu.Lock()
		f.stopping = true
		conns := append([]*nativeQUICDNSConn(nil), f.conns...)
		f.mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		cancel()
		joined := true
		for name, done := range map[string]<-chan struct{}{"caller": callerDone, "client Close": closeDone} {
			joined = nativeQUICDNSJoin(t, name, done) && joined
		}
		select {
		case err := <-closeResult:
			if err != nil {
				t.Errorf("cleanup client Close returned an error: %v", err)
			}
		default: // The main close oracle may already have consumed this result.
		}
		_ = peer.Close()
		joined = nativeQUICDNSJoin(t, "DNS peer", f.peerDone) && joined
		for _, conn := range conns {
			joined = nativeQUICDNSJoin(t, "DNS socket Close", conn.done) && joined
		}
		f.mu.Lock()
		problem, queries, responses := f.problem, f.queries, f.responses
		f.mu.Unlock()
		if problem != nil {
			t.Errorf("fixture DNS I/O/framing failure: %v", problem)
		}
		t.Logf("cleanup all_owned_workers_joined=%t; actual DNS queries=%d cleanup responses=%d DNS sockets=%d", joined, queries, responses, len(conns))
		// Keep the replacement until this isolated process exits: a standard
		// resolver singleflight worker may still exist after our owned joins.
		// The parent global was never changed.
	})
	go func() {
		defer close(callerDone)
		conn, err := client.DialContext(ctx, "tcp", "127.0.0.1:1")
		if conn != nil {
			_ = conn.Close()
			callerResult <- errors.New("unexpected tunnel connection without a DNS response")
			return
		}
		callerResult <- err
	}()
	select {
	case <-f.querySeen:
	case <-time.After(2 * time.Second):
		t.Fatal("no actual loopback DNS query reached the blackhole peer")
	}
	f.mu.Lock()
	attempt, responses := f.attempt, f.responses
	f.mu.Unlock()
	if attempt == nil || responses != 0 {
		t.Fatalf("missing real physical attempt or premature DNS response: attempt=%t responses=%d", attempt != nil, responses)
	}
	t.Log("actual loopback DNS query received; no DNS response sent before the cancellation oracle")
	if mode == "close" {
		startClose()
		select {
		case <-client.ctx.Done():
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Close did not reach the actual client cancellation gate")
		}
		select {
		case <-closeDone:
			if err := <-closeResult; err != nil {
				t.Errorf("client Close returned an error: %v", err)
			}
			select {
			case <-attempt.done:
			default:
				t.Error("Client.Close returned before the real physical attempt published completion")
			}
		case <-time.After(500 * time.Millisecond):
			t.Error("Client.Close remained blocked on DNS after canceling its owned physical attempt")
		}
		select {
		case <-callerDone:
			if err := <-callerResult; !errors.Is(err, net.ErrClosed) {
				t.Errorf("closed-client caller error is not net.ErrClosed: %T %v", err, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Error("public caller did not return after actual client cancellation")
		}
	} else {
		select {
		case <-callerDone:
			if err := <-callerResult; !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("physical DNS timeout did not preserve deadline identity: %T %v", err, err)
			}
			if ctx.Err() != nil {
				t.Error("caller context expired instead of the shorter physical dial budget")
			}
			select {
			case <-attempt.done:
			default:
				t.Error("deadline result preceded actual physical-attempt completion")
			}
		case <-time.After(500 * time.Millisecond):
			t.Error("default native DNS lookup outlived the 150ms physical dial budget")
		}
	}
}

func nativeQUICDNSJoin(t *testing.T, name string, done <-chan struct{}) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("owned %s worker did not join after independent cleanup", name)
		return false
	}
}
