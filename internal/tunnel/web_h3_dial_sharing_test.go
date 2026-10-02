package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/cppla/autocar/internal/transport"
)

const webH3DialSharingBudget = time.Second

type webH3DialSharingJoin struct {
	name string
	done <-chan struct{}
}

// All fixture networking is exact-owned IPv4 loopback. Cleanup independently
// cancels callers, closes resources and joins workers; result arrival is not a
// substitute for completion of the goroutine that produced that result.
type webH3DialSharingFixture struct {
	t         *testing.T
	ctx       context.Context
	cancel    context.CancelFunc
	serverTLS *tls.Config
	clientTLS *tls.Config
	closers   []func()
	checks    []func()
	mu        sync.Mutex
	joins     []webH3DialSharingJoin
}

func newWebH3DialSharingFixture(t *testing.T) *webH3DialSharingFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	f := &webH3DialSharingFixture{t: t, ctx: ctx, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		for i := len(f.closers) - 1; i >= 0; i-- {
			f.closers[i]()
		}
		// Resources are closed before taking the final worker snapshot. Caller
		// and Serve workers are registered before launch; handler completion is
		// also registered at entry and explicitly observed on successful paths.
		f.mu.Lock()
		joins := append([]webH3DialSharingJoin(nil), f.joins...)
		f.mu.Unlock()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for _, worker := range joins {
			select {
			case <-worker.done:
			case <-deadline.C:
				t.Errorf("cleanup did not join %s", worker.name)
				return
			}
		}
		for _, check := range f.checks {
			check()
		}
	})
	f.serverTLS, f.clientTLS = testTLSConfigs(t)
	return f
}

func (f *webH3DialSharingFixture) join(name string, done <-chan struct{}) {
	f.mu.Lock()
	f.joins = append(f.joins, webH3DialSharingJoin{name: name, done: done})
	f.mu.Unlock()
}

func (f *webH3DialSharingFixture) wait(done <-chan struct{}, name string) {
	f.t.Helper()
	select {
	case <-done:
	case <-f.ctx.Done():
		f.t.Fatalf("%s exceeded independent fixture budget", name)
	}
}

type webH3DialSharingPhase struct{ peer, dcid string }

type webH3DialSharingUDP struct {
	front, back *net.UDPConn
	remote      *net.UDPAddr
	mu          sync.Mutex
	phases      []webH3DialSharingPhase
	seen        map[string]bool
	peer        *net.UDPAddr
	first       chan struct{}
	forward     bool
	pending     []byte
	unowned     int
	err         error
}

// With no destination this is a real UDP blackhole. With a destination it
// buffers the first actual datagram until release and then forwards both ways
// to an owned real HTTP/3 server; it never synthesizes protocol responses.
func (f *webH3DialSharingFixture) udp(address, destination string) *webH3DialSharingUDP {
	f.t.Helper()
	local, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		f.t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", local)
	if err != nil {
		f.t.Fatal(err)
	}
	u := &webH3DialSharingUDP{front: front, seen: make(map[string]bool), first: make(chan struct{})}
	f.closers = append(f.closers, func() { _ = front.Close() })
	if err := front.SetDeadline(time.Now().Add(7 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	if destination != "" {
		u.remote, err = net.ResolveUDPAddr("udp4", destination)
		if err != nil || !u.remote.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			f.t.Fatalf("non-owned UDP forwarding destination %q: %v", destination, err)
		}
		u.back, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			f.t.Fatal(err)
		}
		f.closers = append(f.closers, func() { _ = u.back.Close() })
		if err := u.back.SetDeadline(time.Now().Add(7 * time.Second)); err != nil {
			f.t.Fatal(err)
		}
		joined := make(chan struct{})
		f.join("UDP return forwarder", joined)
		go func() {
			defer close(joined)
			var buffer [65536]byte
			for {
				n, source, err := u.back.ReadFromUDP(buffer[:])
				if err != nil {
					u.noteError(err)
					return
				}
				u.mu.Lock()
				peer := u.peer
				if source.String() != u.remote.String() {
					u.unowned++
					u.mu.Unlock()
					continue
				}
				u.mu.Unlock()
				if peer != nil {
					if _, err := front.WriteToUDP(buffer[:n], peer); err != nil {
						u.noteError(err)
						return
					}
				}
			}
		}()
	}
	joined := make(chan struct{})
	f.join("UDP Initial observer", joined)
	go func() {
		defer close(joined)
		var buffer [65536]byte
		for {
			n, peer, err := front.ReadFromUDP(buffer[:])
			if err != nil {
				u.noteError(err)
				return
			}
			u.mu.Lock()
			if !peer.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				u.unowned++
				u.mu.Unlock()
				continue
			}
			u.peer = peer
			// Count public v1 Initial/DCID invariant fields only. Repeated
			// packets from one peer/DCID are not new physical attempts.
			if n >= 7 && buffer[0]&0xc0 == 0xc0 && buffer[0]&0x30 == 0 && binary.BigEndian.Uint32(buffer[1:5]) == 1 {
				length := int(buffer[5])
				if length > 0 && length <= 20 && 6+length < n {
					dcid := fmt.Sprintf("%x", buffer[6:6+length])
					key := peer.String() + "/" + dcid
					// A live server can change an Initial's destination CID to
					// its SCID without a new connection. Forwarding controls
					// therefore record the first Initial per peer and separately
					// verify server-auth physical identity after success. A true
					// blackhole cannot change that DCID; peer/DCID grouping there
					// also permits a later socket to reuse an ephemeral port.
					if u.back != nil {
						key = peer.String()
					}
					if !u.seen[key] {
						u.seen[key] = true
						u.phases = append(u.phases, webH3DialSharingPhase{peer.String(), dcid})
						if len(u.phases) == 1 {
							close(u.first)
						}
					}
				}
			}
			forward := u.forward
			if u.back != nil && !forward && u.pending == nil {
				u.pending = bytes.Clone(buffer[:n])
			}
			u.mu.Unlock()
			if u.back != nil && forward {
				if _, err := u.back.WriteToUDP(buffer[:n], u.remote); err != nil {
					u.noteError(err)
					return
				}
			}
		}
	}()
	return u
}

func (u *webH3DialSharingUDP) noteError(err error) {
	if errors.Is(err, net.ErrClosed) {
		return
	}
	u.mu.Lock()
	u.err = errors.Join(u.err, err)
	u.mu.Unlock()
}

func (u *webH3DialSharingUDP) release() error {
	u.mu.Lock()
	u.forward = true
	pending := u.pending
	u.pending = nil
	u.mu.Unlock()
	if u.back == nil || len(pending) == 0 {
		return errors.New("missing owned first UDP datagram")
	}
	_, err := u.back.WriteToUDP(pending, u.remote)
	return err
}

func (u *webH3DialSharingUDP) snapshot() ([]webH3DialSharingPhase, int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]webH3DialSharingPhase(nil), u.phases...), u.unowned, u.err
}

func (f *webH3DialSharingFixture) phaseCount(u *webH3DialSharingUDP, want int) {
	f.t.Helper()
	phases, unowned, err := u.snapshot()
	for i, phase := range phases {
		f.t.Logf("actual v1 Initial phase=%d peer=%s dcid=%s", i+1, phase.peer, phase.dcid)
	}
	if len(phases) != want || unowned != 0 || err != nil {
		f.t.Errorf("physical Initial phases=%d want=%d non-owned=%d observer error=%v", len(phases), want, unowned, err)
	}
}

func (f *webH3DialSharingFixture) h3(address string) *WebH3Client {
	f.t.Helper()
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: address, Token: testToken, TLSConfig: f.clientTLS,
		FingerprintProfile: H3FingerprintNative, DialTimeout: webH3DialSharingBudget,
		HandshakeTimeout: 2 * time.Second, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.closers = append(f.closers, func() { _ = client.Close() })
	return client
}

type webH3DialSharingCaller struct {
	result      chan webH3DialSharingResult
	joined      chan struct{}
	cancel      context.CancelCauseFunc
	goroutineID atomic.Uint64
}

type webH3DialSharingResult struct {
	err     error
	success bool
}

func (f *webH3DialSharingFixture) caller(gate <-chan struct{}, entered chan<- struct{}, dial func(context.Context) (net.Conn, error), payload string) *webH3DialSharingCaller {
	ctx, cancel := context.WithCancelCause(f.ctx)
	c := &webH3DialSharingCaller{result: make(chan webH3DialSharingResult, 1), joined: make(chan struct{}), cancel: cancel}
	f.join("dial caller", c.joined)
	go func() {
		defer close(c.joined)
		defer cancel(nil)
		var stack [128]byte
		n := runtime.Stack(stack[:], false)
		fields := strings.Fields(strings.SplitN(string(stack[:n]), "\n", 2)[0])
		if len(fields) >= 2 {
			id, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				c.goroutineID.Store(id)
			}
		}
		if entered != nil {
			entered <- struct{}{}
		}
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				c.result <- webH3DialSharingResult{err: context.Cause(ctx)}
				return
			}
		}
		conn, err := dial(ctx)
		success := conn != nil && err == nil
		if conn != nil {
			if success && payload != "" {
				err = webH3DialSharingExchange(conn, payload)
			}
			_ = conn.Close()
		}
		c.result <- webH3DialSharingResult{err: err, success: success}
	}()
	return c
}

func webH3DialSharingExchange(conn net.Conn, payload string) error {
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		return err
	}
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("real tunnel omitted CloseWrite")
	}
	if err := writer.CloseWrite(); err != nil {
		return err
	}
	reply, err := io.ReadAll(conn)
	if err == nil && string(reply) != "reply:"+payload {
		err = fmt.Errorf("real target reply=%q want=%q", reply, "reply:"+payload)
	}
	return err
}

func (f *webH3DialSharingFixture) result(c *webH3DialSharingCaller) webH3DialSharingResult {
	f.t.Helper()
	var r webH3DialSharingResult
	select {
	case r = <-c.result:
	case <-f.ctx.Done():
		f.t.Fatal("dial result exceeded independent fixture budget")
	}
	f.wait(c.joined, "dial caller after result")
	return r
}

// Identity only: no unexported reflected fields, Interface, unsafe or new
// production types. The same source compiles with the old channel and the new
// result-bearing pointer. Access to c.dial always holds its production mutex.
func webH3DialSharingAttempt(client *WebH3Client) uintptr {
	client.mu.Lock()
	defer client.mu.Unlock()
	v := reflect.ValueOf(client.dial)
	if v.IsNil() {
		return 0
	}
	return v.Pointer()
}

func webH3DialSharingWaitStacks() map[uint64]string {
	buffer := make([]byte, 512<<10)
	n := runtime.Stack(buffer, true)
	waiters := make(map[uint64]string)
	for _, block := range strings.Split(string(buffer[:n]), "\n\n") {
		lines := strings.Split(block, "\n")
		if len(lines) > 1 && strings.Contains(lines[0], "[select") && strings.Contains(lines[1], "(*WebH3Client).connection(") && strings.Contains(block, "(*webH3DialSharingFixture).caller.func") {
			fields := strings.Fields(lines[0])
			if len(fields) >= 2 {
				id, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					waiters[id] = block
				}
			}
		}
	}
	return waiters
}

func (f *webH3DialSharingFixture) joinedAttempt(client *WebH3Client, u *webH3DialSharingUDP, attempt uintptr, followers []*webH3DialSharingCaller) {
	f.t.Helper()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		waiters := webH3DialSharingWaitStacks()
		joined := 0
		for _, follower := range followers {
			if id := follower.goroutineID.Load(); id != 0 && waiters[id] != "" {
				joined++
			}
		}
		phases, _, _ := u.snapshot()
		if joined == len(followers) && webH3DialSharingAttempt(client) == attempt && len(phases) == 1 {
			f.t.Logf("joined first physical attempt: both exact follower goroutine IDs in actual connection-select stacks, same identity, one Initial phase")
			return
		}
		select {
		case <-timer.C:
			f.t.Fatalf("same in-flight join not proved: exact followers=%d/%d same=%v phases=%d", joined, len(followers), webH3DialSharingAttempt(client) == attempt, len(phases))
		case <-f.ctx.Done():
			f.t.Fatal("same-attempt witness exceeded independent fixture budget")
		case <-tick.C:
		}
	}
}

func (f *webH3DialSharingFixture) batch(client *WebH3Client, u *webH3DialSharingUDP, dial func(context.Context) (net.Conn, error), payload string) ([]*webH3DialSharingCaller, uintptr) {
	f.t.Helper()
	callers := []*webH3DialSharingCaller{f.caller(nil, nil, dial, payload+"0")}
	f.wait(u.first, "actual leader Initial")
	attempt := webH3DialSharingAttempt(client)
	if attempt == 0 {
		f.t.Fatal("actual Initial without live physical attempt")
	}
	gate, entered := make(chan struct{}), make(chan struct{}, 2)
	var release sync.Once
	f.closers = append(f.closers, func() { release.Do(func() { close(gate) }) })
	for i := 1; i < 3; i++ {
		callers = append(callers, f.caller(gate, entered, dial, payload+fmt.Sprint(i)))
	}
	for range 2 {
		select {
		case <-entered:
		case <-f.ctx.Done():
			f.t.Fatal("followers did not enter actual call barrier")
		}
	}
	release.Do(func() { close(gate) })
	f.joinedAttempt(client, u, attempt, callers[1:])
	return callers, attempt
}

func TestWebH3DialSharingFailedAttemptAndLaterRetry(t *testing.T) {
	f := newWebH3DialSharingFixture(t)
	u := f.udp("127.0.0.1:0", "")
	client := f.h3(u.front.LocalAddr().String())
	dial := func(ctx context.Context) (net.Conn, error) {
		return client.DialContext(ctx, "tcp", "owned-dummy.example:443")
	}
	callers, first := f.batch(client, u, dial, "")
	var shared error
	for i, caller := range callers {
		r := f.result(caller)
		if r.success || !errors.Is(r.err, context.DeadlineExceeded) {
			t.Errorf("caller %d: success=%v error=%v, want physical deadline", i, r.success, r.err)
		}
		if i == 0 {
			shared = r.err
		} else if r.err != shared {
			t.Errorf("caller %d lost immutable shared failure identity: got=%v first=%v", i, r.err, shared)
		}
	}
	f.phaseCount(u, 1)
	if webH3DialSharingAttempt(client) != 0 {
		t.Error("completed failure retained active physical attempt")
	}
	// A new invocation, after all original callers joined, may independently
	// retry. Failure sharing must not become a permanent cached failure.
	retry := f.caller(nil, nil, dial, "")
	r := f.result(retry)
	if r.success || !errors.Is(r.err, context.DeadlineExceeded) || r.err == shared {
		t.Errorf("later independent retry success=%v error=%v shared=%v", r.success, r.err, r.err == shared)
	}
	f.phaseCount(u, 2)
	phases, _, _ := u.snapshot()
	if len(phases) >= 2 && phases[0].dcid == phases[1].dcid {
		t.Error("later independent retry reused the original Initial DCID")
	}
	t.Logf("first attempt identity=%x; original callers joined before fresh retry", first)
}

func (f *webH3DialSharingFixture) target(count int) (string, <-chan error) {
	f.t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.t.Fatal(err)
	}
	var mu sync.Mutex
	var current *net.TCPConn
	closed := false
	f.closers = append(f.closers, func() {
		_ = listener.Close()
		mu.Lock()
		closed = true
		if current != nil {
			_ = current.Close()
		}
		mu.Unlock()
	})
	results := make(chan error, count)
	joined := make(chan struct{})
	f.join("real TCP destination", joined)
	go func() {
		defer close(joined)
		for range count {
			if err := listener.SetDeadline(time.Now().Add(7 * time.Second)); err != nil {
				results <- err
				return
			}
			conn, err := listener.AcceptTCP()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					results <- err
				}
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			current = conn
			mu.Unlock()
			err = conn.SetDeadline(time.Now().Add(2 * time.Second))
			var payload []byte
			if err == nil {
				payload, err = io.ReadAll(conn)
			}
			if err == nil {
				_, err = io.Copy(conn, bytes.NewReader(append([]byte("reply:"), payload...)))
			}
			if err == nil {
				err = conn.CloseWrite()
			}
			_ = conn.Close()
			mu.Lock()
			current = nil
			mu.Unlock()
			results <- err
		}
	}()
	return listener.Addr().String(), results
}

type webH3DialSharingResponse struct {
	proof      bool
	bearerSize int
	short      bool
	proto      int
	tlsVersion uint16
	auth       *webServerConnectionAuth
	joined     <-chan struct{}
}

type webH3DialSharingRelay struct {
	address   string
	handler   *webTunnelHandler
	responses chan webH3DialSharingResponse
	dials     atomic.Int32
	cover     atomic.Int32
}

func (f *webH3DialSharingFixture) relay(h3 bool, target string, count int) *webH3DialSharingRelay {
	f.t.Helper()
	r := &webH3DialSharingRelay{responses: make(chan webH3DialSharingResponse, count)}
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != target {
			return nil, fmt.Errorf("refused non-owned destination %s/%s", network, address)
		}
		r.dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	cover := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.cover.Add(1)
		http.NotFound(w, nil)
	})
	var serve func(context.Context) error
	var closeServer func() error
	var install func(http.Handler)
	if h3 {
		server, err := ListenWebH3(WebH3ServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: f.serverTLS,
			QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}},
			Cover:      cover, Dialer: dialer,
		})
		if err != nil {
			f.t.Fatal(err)
		}
		r.address, r.handler = server.Addr().String(), server.server.Handler.(*webTunnelHandler)
		serve, closeServer = server.Serve, server.Close
		install = func(h http.Handler) { server.server.Handler = h }
	} else {
		server, err := ListenWebH2(WebH2ServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: f.serverTLS, Cover: cover, Dialer: dialer,
		})
		if err != nil {
			f.t.Fatal(err)
		}
		r.address, r.handler = server.Addr().String(), server.server.Handler.(*webTunnelHandler)
		serve, closeServer = server.Serve, server.Close
		install = func(h http.Handler) { server.server.Handler = h }
	}
	install(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		joined := make(chan struct{})
		f.join("authenticated handler", joined)
		defer close(joined)
		_, short := parseWebSessionBearer(request.Header.Get("Proxy-Authorization"))
		auth, _ := request.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		r.handler.ServeHTTP(w, request)
		r.responses <- webH3DialSharingResponse{
			proof: w.Header().Get(webAuthResponseHeader) != "", bearerSize: len(request.Header.Get("Proxy-Authorization")),
			short: short, proto: request.ProtoMajor, tlsVersion: webRequestTLSVersion(request), auth: auth, joined: joined,
		}
	}))
	f.closers = append(f.closers, func() { _ = closeServer() })
	joined := make(chan struct{})
	f.join("relay Serve", joined)
	var serveErr error
	go func() { defer close(joined); serveErr = serve(f.ctx) }()
	f.checks = append(f.checks, func() {
		if serveErr != nil {
			f.t.Errorf("owned relay Serve: %v", serveErr)
		}
	})
	return r
}

func (f *webH3DialSharingFixture) healthy(relay *webH3DialSharingRelay, target <-chan error, count, proto int) {
	f.t.Helper()
	var physical *webServerConnectionAuth
	full, short := 0, 0
	for range count {
		var response webH3DialSharingResponse
		select {
		case response = <-relay.responses:
		case <-f.ctx.Done():
			f.t.Fatal("real authenticated handler did not complete")
		}
		f.wait(response.joined, "authenticated handler after result")
		if !response.proof || response.proto != proto || response.tlsVersion != tls.VersionTLS13 || response.auth == nil {
			f.t.Errorf("real authenticated response proof=%v protocol=%d TLS=%x physical=%v", response.proof, response.proto, response.tlsVersion, response.auth != nil)
		}
		if physical == nil {
			physical = response.auth
		} else if response.auth != physical {
			f.t.Error("concurrent healthy requests replaced physical authenticated connection")
		}
		if response.short {
			short++
		} else {
			full++
			if response.bearerSize < 385 {
				f.t.Error("bootstrap did not contain the full padded credential")
			}
		}
		select {
		case err := <-target:
			if err != nil {
				f.t.Errorf("owned TCP full payload / FIN: %v", err)
			}
		case <-f.ctx.Done():
			f.t.Fatal("real TCP target did not complete")
		}
	}
	if full != 1 || short != count-1 || relay.dials.Load() != int32(count) || relay.cover.Load() != 0 || len(relay.handler.core.sem) != 0 {
		f.t.Errorf("authenticated healthy control full=%d short=%d destination dials=%d cover=%d slots=%d", full, short, relay.dials.Load(), relay.cover.Load(), len(relay.handler.core.sem))
	}
	f.t.Logf("real TLS1.3 protocol=%d healthy CONNECTs=%d: one full bootstrap, %d short continuations, full payload+FIN, joined handlers and zero slots", proto, count, count-1)
}

func TestWebH3DialCancellationIsolation(t *testing.T) {
	for _, canceled := range []int{0, 1} {
		name := "initiating_caller"
		if canceled == 1 {
			name = "joined_follower"
		}
		t.Run(name, func(t *testing.T) {
			f := newWebH3DialSharingFixture(t)
			target, targetResults := f.target(2)
			relay := f.relay(true, target, 2)
			u := f.udp("127.0.0.1:0", relay.address)
			client := f.h3(u.front.LocalAddr().String())
			dial := func(ctx context.Context) (net.Conn, error) { return client.DialContext(ctx, "tcp", target) }
			callers, attempt := f.batch(client, u, dial, "h3-cancellation-")
			cause := errors.New("owned custom caller cancellation")
			callers[canceled].cancel(cause)
			r := f.result(callers[canceled])
			if r.success || r.err != cause {
				t.Errorf("canceled caller lost custom cause: success=%v err=%v want=%v", r.success, r.err, cause)
			}
			if got := webH3DialSharingAttempt(client); got != attempt {
				t.Errorf("caller cancellation replaced shared physical attempt: got=%x first=%x", got, attempt)
			}
			if err := u.release(); err != nil {
				t.Fatal(err)
			}
			for i, caller := range callers {
				if i == canceled {
					continue
				}
				r := f.result(caller)
				if !r.success || r.err != nil {
					t.Errorf("surviving caller %d real H3 payload: success=%v err=%v", i, r.success, r.err)
				}
			}
			f.phaseCount(u, 1)
			f.healthy(relay, targetResults, 2, 3)
		})
	}
	t.Run("pre_canceled_skips_physical_dial", func(t *testing.T) {
		f := newWebH3DialSharingFixture(t)
		u := f.udp("127.0.0.1:0", "")
		client := f.h3(u.front.LocalAddr().String())
		ctx, cancel := context.WithCancelCause(f.ctx)
		cause := errors.New("owned pre-canceled cause")
		cancel(cause)
		conn, err := client.DialContext(ctx, "tcp", "owned-dummy.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		if conn != nil || err != cause || webH3DialSharingAttempt(client) != 0 {
			t.Errorf("pre-canceled dial conn=%v error=%v attempt=%x", conn != nil, err, webH3DialSharingAttempt(client))
		}
		f.phaseCount(u, 0)
	})
}

func TestWebH3DialClientCloseJoinsBlackhole(t *testing.T) {
	f := newWebH3DialSharingFixture(t)
	u := f.udp("127.0.0.1:0", "")
	client := f.h3(u.front.LocalAddr().String())
	callers, _ := f.batch(client, u, func(ctx context.Context) (net.Conn, error) {
		return client.DialContext(ctx, "tcp", "owned-dummy.example:443")
	}, "")
	closeJoined := make(chan struct{})
	f.join("client Close", closeJoined)
	var closeErr error
	go func() { defer close(closeJoined); closeErr = client.Close() }()
	f.wait(closeJoined, "Close of active physical blackhole")
	if closeErr != nil || webH3DialSharingAttempt(client) != 0 {
		t.Errorf("Close returned with error=%v live physical attempt=%x", closeErr, webH3DialSharingAttempt(client))
	}
	for i, caller := range callers {
		r := f.result(caller)
		if r.success || !errors.Is(r.err, net.ErrClosed) {
			t.Errorf("caller %d after joined client Close: success=%v error=%v", i, r.success, r.err)
		}
	}
	stacks := make([]byte, 512<<10)
	n := runtime.Stack(stacks, true)
	if strings.Contains(string(stacks[:n]), "(*WebH3Client).dialSession(") || strings.Contains(string(stacks[:n]), "(*WebH3Client).dialSessionAddresses(") {
		t.Error("physical dial worker still running after client Close and caller joins")
	}
	f.phaseCount(u, 1)
}

func TestWebH3DialFallbackReachesAuthenticatedH2(t *testing.T) {
	f := newWebH3DialSharingFixture(t)
	target, targetResults := f.target(4)
	relay := f.relay(false, target, 4)
	// Same owned address/port: real TCP HTTP/2 relay, UDP blackhole.
	u := f.udp(relay.address, "")
	client, err := NewWebClient(WebClientConfig{
		ServerAddress: relay.address, Token: testToken, TLSConfig: f.clientTLS,
		H3FingerprintProfile: H3FingerprintNative, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}},
		H3DialTimeout: webH3DialSharingBudget, H2DialTimeout: time.Second,
		HandshakeTimeout: 2 * time.Second, PrimaryAttemptTimeout: 4 * time.Second, FallbackCooldown: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.closers = append(f.closers, func() { _ = client.Close() })
	h3 := client.primary.dialer.(*WebH3Client)
	dial := func(ctx context.Context) (net.Conn, error) { return client.DialContext(ctx, "tcp", target) }
	callers, _ := f.batch(h3, u, dial, "real-h2-fallback-")
	for i, caller := range callers {
		r := f.result(caller)
		if !r.success || r.err != nil {
			t.Errorf("caller %d verified real H2 fallback: success=%v error=%v", i, r.success, r.err)
		}
	}
	f.phaseCount(u, 1)
	client.mu.Lock()
	cooldown := !client.primaryFailedAt.IsZero()
	client.mu.Unlock()
	if !cooldown || client.SelectedTransport() != webAuthTransportH2 {
		t.Errorf("fallback cooldown=%v selected=%q", cooldown, client.SelectedTransport())
	}
	// A later invocation uses the existing cooldown and warm real H2 session,
	// not a synthetic fallback. It must not start a new physical UDP attempt.
	later := f.caller(nil, nil, dial, "real-h2-cooldown")
	if r := f.result(later); !r.success || r.err != nil {
		t.Errorf("later real H2 cooldown exchange success=%v error=%v", r.success, r.err)
	}
	f.phaseCount(u, 1)
	f.healthy(relay, targetResults, 4, 2)
	t.Log("custom physical budget=1s, primary budget=4s; defaults remain 5s, not a default latency or browser-equivalence claim")
}

// webH3DialUnpublishedDeadlineContext is a synthetic, fixed-deadline Context
// model. Err and Done delegate to the independently bounded fixture context,
// deliberately holding publication of this deadline until fixture cleanup.
// This models the timer-publication gap; it is not evidence of a naturally
// observed scheduling race. Deadline never changes, and no sleep is an entry
// or completion witness.
type webH3DialUnpublishedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (ctx webH3DialUnpublishedDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

func TestWebH3DialElapsedDeadlineBeforePublication(t *testing.T) {
	t.Run("expired_entry_skips_physical_dial", func(t *testing.T) {
		f := newWebH3DialSharingFixture(t)
		u := f.udp("127.0.0.1:0", "")
		client := f.h3(u.front.LocalAddr().String())
		ctx := webH3DialUnpublishedDeadlineContext{Context: f.ctx, deadline: time.Now().Add(-time.Second)}
		if ctx.Err() != nil {
			t.Fatal("synthetic deadline was already published")
		}
		conn, err := client.DialContext(ctx, "tcp", "owned-dummy.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		if conn != nil || err != context.DeadlineExceeded || webH3DialSharingAttempt(client) != 0 {
			t.Errorf("expired entry conn=%v error=%v attempt=%x; want exact caller DeadlineExceeded and no dial", conn != nil, err, webH3DialSharingAttempt(client))
		}
		f.phaseCount(u, 0)
	})

	t.Run("caller_context_precedes_closed_client", func(t *testing.T) {
		f := newWebH3DialSharingFixture(t)
		u := f.udp("127.0.0.1:0", "")
		client := f.h3(u.front.LocalAddr().String())
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		expired := time.Now().Add(-time.Second)
		ctx := webH3DialUnpublishedDeadlineContext{Context: f.ctx, deadline: expired}
		conn, err := client.DialContext(ctx, "tcp", "owned-dummy.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		if conn != nil || err != context.DeadlineExceeded {
			t.Errorf("expired closed-client conn=%v error=%v; want exact caller DeadlineExceeded before ErrClosed", conn != nil, err)
		}
		parent, cancel := context.WithCancelCause(f.ctx)
		cause := errors.New("owned elapsed-deadline custom cause")
		cancel(cause)
		caused := webH3DialUnpublishedDeadlineContext{Context: parent, deadline: expired}
		conn, err = client.DialContext(caused, "tcp", "owned-dummy.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		if conn != nil || err != cause {
			t.Errorf("custom-cause closed-client conn=%v error=%v; want original cause identity", conn != nil, err)
		}
		f.phaseCount(u, 0)
	})

	t.Run("completed_attempt_preserves_elapsed_caller_priority", func(t *testing.T) {
		f := newWebH3DialSharingFixture(t)
		u := f.udp("127.0.0.1:0", "")
		client := f.h3(u.front.LocalAddr().String())
		ctx := webH3DialUnpublishedDeadlineContext{Context: f.ctx, deadline: time.Now().Add(500 * time.Millisecond)}
		result := make(chan webH3DialSharingResult, 1)
		joined := make(chan struct{})
		f.join("unpublished-deadline caller", joined)
		go func() {
			defer close(joined)
			conn, err := client.DialContext(ctx, "tcp", "owned-dummy.example:443")
			if conn != nil {
				_ = conn.Close()
			}
			result <- webH3DialSharingResult{err: err, success: conn != nil}
		}()
		f.wait(u.first, "actual Initial before synthetic deadline")
		if !time.Now().Before(ctx.deadline) {
			t.Fatal("first actual Initial not observed before fixed caller deadline; completion-path witness invalid")
		}
		client.mu.Lock()
		attempt := client.dial
		client.mu.Unlock()
		if attempt == nil {
			t.Fatal("actual Initial had no active physical attempt")
		}
		f.wait(joined, "caller after physical blackhole completion")
		r := <-result
		select {
		case <-attempt.done:
		default:
			t.Fatal("caller returned before immutable physical result was published")
		}
		if time.Now().Before(ctx.deadline) || ctx.Err() != nil {
			t.Fatal("fixed deadline not elapsed with Err still pending")
		}
		select {
		case <-ctx.Done():
			t.Fatal("synthetic deadline publication was not held")
		default:
		}
		if r.success || r.err != context.DeadlineExceeded {
			t.Errorf("completed caller success=%v error=%v; want exact caller DeadlineExceeded, not wrapped physical timeout", r.success, r.err)
		}
		if attempt.err == nil || !errors.Is(attempt.err, context.DeadlineExceeded) || attempt.err == r.err {
			t.Errorf("immutable physical error=%v caller=%v; want distinct physical timeout and caller deadline identities", attempt.err, r.err)
		}
		if webH3DialSharingAttempt(client) != 0 {
			t.Error("completed physical failure retained active attempt")
		}
		f.phaseCount(u, 1)
	})
}
