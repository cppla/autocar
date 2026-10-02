package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type socksTCPPreservePayload struct {
	body []byte
	err  error
}

// The fixture accepts through the production managedListener, then runs the
// unmodified serveConn with a completion signal. The dial gate delays a real
// TCP origin connection without reading any downstream application bytes.
type socksTCPPreserveFixture struct {
	server        *SOCKS5Server
	client        *net.TCPConn
	originAddress string
	setupContext  chan context.Context
	dialDone      chan struct{}
	dialRelease   chan struct{}
	dialOnce      sync.Once
	originPayload chan socksTCPPreservePayload
	replyRelease  chan struct{}
	replyOnce     sync.Once
	originDone    chan struct{}
	originError   error
	serveDone     chan struct{}
	serveError    error
	mu            sync.Mutex
	closed        bool
	connections   []net.Conn
}

func (f *socksTCPPreserveFixture) releaseDial() {
	f.dialOnce.Do(func() { close(f.dialRelease) })
}

func (f *socksTCPPreserveFixture) releaseReply() {
	f.replyOnce.Do(func() { close(f.replyRelease) })
}

func (f *socksTCPPreserveFixture) ownConnection(conn net.Conn) bool {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = conn.Close()
		return false
	}
	f.connections = append(f.connections, conn)
	f.mu.Unlock()
	return true
}

func socksTCPPreserveWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not finish", label)
		return false
	}
}

func newSOCKSTCPPreserveFixture(t *testing.T, response []byte) *socksTCPPreserveFixture {
	t.Helper()
	originListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &socksTCPPreserveFixture{
		originAddress: originListener.Addr().String(),
		setupContext:  make(chan context.Context, 1),
		dialDone:      make(chan struct{}),
		dialRelease:   make(chan struct{}),
		originPayload: make(chan socksTCPPreservePayload, 1),
		replyRelease:  make(chan struct{}),
		originDone:    make(chan struct{}),
		serveDone:     make(chan struct{}),
	}
	var proxyListener *net.TCPListener
	workersStarted := false
	t.Cleanup(func() {
		// These releases work independently of production context propagation.
		f.releaseDial()
		f.releaseReply()
		_ = originListener.Close()
		if proxyListener != nil {
			_ = proxyListener.Close()
		}
		f.mu.Lock()
		f.closed = true
		connections := append([]net.Conn(nil), f.connections...)
		f.mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		if f.client != nil {
			_ = f.client.Close()
		}
		if f.server != nil {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = f.server.Shutdown(ctx)
		}
		if workersStarted {
			socksTCPPreserveWait(t, f.serveDone, "SOCKS serveConn cleanup")
			socksTCPPreserveWait(t, f.originDone, "TCP origin cleanup")
		}
	})

	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		defer close(f.dialDone)
		f.setupContext <- ctx
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.dialRelease:
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if !f.ownConnection(conn) {
			return nil, net.ErrClosed
		}
		return conn, nil
	})
	f.server, err = NewSOCKS5Server(Config{
		Dialer:           dialer,
		DialTimeout:      750 * time.Millisecond,
		HandshakeTimeout: 2 * time.Second,
		IdleTimeout:      3 * time.Second,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	managed, err := f.server.lifecycle.manage(proxyListener)
	if err != nil {
		t.Fatal(err)
	}
	workersStarted = true
	go func() {
		defer close(f.serveDone)
		conn, err := managed.Accept()
		if err != nil {
			f.serveError = err
			return
		}
		f.server.serveConn(conn)
	}()
	go func() {
		defer close(f.originDone)
		conn, err := originListener.AcceptTCP()
		if err != nil {
			f.originError = err
			return
		}
		defer conn.Close()
		if !f.ownConnection(conn) {
			f.originError = net.ErrClosed
			return
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			f.originError = err
			return
		}
		body, err := io.ReadAll(conn)
		f.originPayload <- socksTCPPreservePayload{body: body, err: err}
		if err != nil {
			f.originError = err
			return
		}
		<-f.replyRelease
		if _, err := io.Copy(conn, bytes.NewReader(response)); err != nil {
			f.originError = err
			return
		}
		f.originError = conn.CloseWrite()
	}()
	f.client, err = net.DialTCP("tcp", nil, proxyListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSOCKS5TCPSetupPreservesEarlyBytesAndHalfClose(t *testing.T) {
	for _, crossSetupDeadline := range []bool{false, true} {
		name := "reply-after-setup"
		if crossSetupDeadline {
			name = "reply-after-original-setup-deadline"
		}
		t.Run(name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("\x00\x16\x03\x01 early SOCKS TCP payload\xff"), 1024)
			response := bytes.Repeat([]byte("reverse reply after upload EOF\x00"), 256)
			f := newSOCKSTCPPreserveFixture(t, response)
			socksGreeting(t, f.client, nil)
			host, port := splitAddress(t, f.originAddress)
			mustWrite(t, f.client, domainSOCKSRequest(socksCommandConnect, host, port))
			var setupCtx context.Context
			select {
			case setupCtx = <-f.setupContext:
			case <-time.After(2 * time.Second):
				t.Fatal("SOCKS CONNECT did not enter pending DialContext")
			}
			setupDeadline, ok := setupCtx.Deadline()
			if !ok {
				t.Fatal("configured SOCKS setup context has no deadline")
			}
			// Only the client writes these bytes. There is no extra downstream
			// reader while DialContext is pending, even after the write half-close.
			mustWrite(t, f.client, payload)
			if err := f.client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-setupCtx.Done():
				t.Fatalf("early data/write half-close canceled pending setup: %v", setupCtx.Err())
			case <-time.After(30 * time.Millisecond):
			}
			f.releaseDial()
			if reply := readSOCKSReply(t, f.client); reply != socksReplySucceeded {
				t.Fatalf("CONNECT reply = %d, want success", reply)
			}
			if !socksTCPPreserveWait(t, f.dialDone, "completed TCP dial") {
				return
			}
			if !errors.Is(setupCtx.Err(), context.Canceled) {
				t.Fatalf("successful setup retained its context: %v", setupCtx.Err())
			}
			select {
			case received := <-f.originPayload:
				if received.err != nil || !bytes.Equal(received.body, payload) {
					t.Fatalf("origin payload = %d/%d bytes, equal=%t, error=%v", len(received.body), len(payload), bytes.Equal(received.body, payload), received.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("origin did not receive intact early payload followed by EOF")
			}
			if crossSetupDeadline {
				// The setup context is already canceled, so wait on the saved
				// original deadline rather than on that context's Done channel.
				if delay := time.Until(setupDeadline.Add(50 * time.Millisecond)); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-f.serveDone:
						t.Fatal("relay ended before reply across original setup deadline")
					}
				}
			}
			f.releaseReply()
			got, err := io.ReadAll(f.client)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatalf("reverse reply = %d/%d bytes, equal=%t, error=%v", len(got), len(response), bytes.Equal(got, response), err)
			}
			if socksTCPPreserveWait(t, f.originDone, "completed TCP origin") && f.originError != nil {
				t.Errorf("origin: %v", f.originError)
			}
			if socksTCPPreserveWait(t, f.serveDone, "completed SOCKS serveConn") && f.serveError != nil {
				t.Errorf("serveConn fixture: %v", f.serveError)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := f.server.lifecycle.tracker.wait(ctx); err != nil {
				t.Errorf("finished healthy relay retained its accepted slot: %v", err)
			}
		})
	}
}
