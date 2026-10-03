package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/transport"
)

// The direct positive control is actual HTTP/1.1 to the owned origin, not a
// bare H2/H3 server. The cover exchanges use actual combined ListenWeb H1/H2/H3.
// A complete origin body chunk must arrive before the client may publish its
// late trailers and EOF, so neither prepopulated values nor buffering can stand
// in for request-trailer streaming.
func TestWebCoverRequestTrailersStreamAcrossProtocols(t *testing.T) {
	for _, constructor := range []string{"fixed_origin", "public_origin"} {
		t.Run(constructor, func(t *testing.T) {
			for _, proto := range []int{1, 2, 3} {
				t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
					framings := []string{"unknown_length"}
					if proto != 1 {
						// H2/H3 can carry trailers with a positive Content-Length.
						// An H1 client cannot: its standard writer drops trailers.
						framings = append(framings, "known_length")
					}
					for _, framing := range framings {
						t.Run(framing, func(t *testing.T) {
							webCoverRequestTrailersExchange(t, constructor, proto, framing == "known_length", false)
						})
					}
				})
			}
		})
	}
}

// H1 accepts these declared fields on the wire. The pinned H2/H3 stacks reject
// Authorization and Proxy-Authorization as trailer fields, so those protocols
// are deliberately not given an invalid-request compatibility oracle here.
func TestWebCoverRequestTrailersFilterLateH1Credentials(t *testing.T) {
	for _, constructor := range []string{"fixed_origin", "public_origin"} {
		t.Run(constructor, func(t *testing.T) {
			webCoverRequestTrailersExchange(t, constructor, 1, false, true)
		})
	}
}

type webCoverRequestTrailersObservation struct {
	phase           string
	header, trailer http.Header
	body            []byte
	err             error
	joined          <-chan struct{}
}

type webCoverRequestTrailersEntry struct {
	phase    string
	proto    int
	physical any
	joined   <-chan struct{}
}

type webCoverRequestTrailersFixture struct {
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	closed       bool
	workers      sync.WaitGroup
	origin       *http.Server
	originDone   chan struct{}
	originResult chan error
	server       *WebServer
	serverDone   chan struct{}
	serverResult chan error
	upstream     *http.Transport
	direct       *http.Transport
	front        http.RoundTripper
	chunks       chan string
	records      chan webCoverRequestTrailersObservation
	entries      chan webCoverRequestTrailersEntry
	unexpected   atomic.Int64
	invalidDials atomic.Int64
	tunnelDials  atomic.Int64
	resolutions  atomic.Int64
}

func (f *webCoverRequestTrailersFixture) admit() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.workers.Add(1)
	return true
}

func newWebCoverRequestTrailersFixture(t *testing.T, constructor string, proto int, prefix, complete []byte, digest string) (*webCoverRequestTrailersFixture, *url.URL) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	f := &webCoverRequestTrailersFixture{ctx: ctx, cancel: cancel, chunks: make(chan string, 4), records: make(chan webCoverRequestTrailersObservation, 4), entries: make(chan webCoverRequestTrailersEntry, 4)}
	// Installed before binding or launching anything; early Fatal cleanup owns
	// exactly the successfully published resources and gates worker admission.
	t.Cleanup(func() { f.cleanup(t) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := &url.URL{Scheme: "http", Host: listener.Addr().String()}
	f.origin = &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.admit() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			defer f.workers.Done()
			joined := make(chan struct{})
			defer close(joined)
			defer r.Body.Close()
			phase := r.Header.Get("X-Request-Trailers-Phase")
			first := make([]byte, len(prefix))
			_, readErr := io.ReadFull(r.Body, first)
			if readErr == nil && bytes.Equal(first, prefix) {
				select {
				case f.chunks <- phase:
				default:
					f.unexpected.Add(1)
				}
			}
			rest, err := io.ReadAll(r.Body)
			if readErr == nil {
				readErr = err
			}
			body := append(first, rest...)
			// The body has reached EOF (or failed) before the server trailer map
			// is inspected. H3 may replace that map rather than populate it.
			observation := webCoverRequestTrailersObservation{phase: phase, header: r.Header.Clone(), trailer: r.Trailer.Clone(), body: body, err: readErr, joined: joined}
			select {
			case f.records <- observation:
			default:
				f.unexpected.Add(1)
			}
			if readErr != nil || r.Method != http.MethodPost || r.RequestURI != "/upload" || r.Host != target.Host ||
				!bytes.Equal(body, complete) || r.Trailer.Get("Content-Digest") != digest || r.Trailer.Get("X-Upload-End") != "complete-at-eof" {
				http.Error(w, "upload trailers missing", http.StatusUnprocessableEntity)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "upload accepted")
		})}
	f.originDone, f.originResult = make(chan struct{}), make(chan error, 1)
	go func() { defer close(f.originDone); f.originResult <- f.origin.Serve(listener) }()
	ownedDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != target.Host {
			f.invalidDials.Add(1)
			return nil, errors.New("request-trailer fixture forbids unowned upstream")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
	f.upstream = &http.Transport{Proxy: nil, DialContext: ownedDial, DisableCompression: true, ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second}
	f.direct = &http.Transport{Proxy: nil, DialContext: ownedDial, DisableCompression: true, ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second}
	public := &url.URL{Scheme: "https", Host: target.Host}
	var website http.Handler
	if constructor == "public_origin" {
		website, err = cover.NewReverseProxyHandlerWithPublicOrigin(target, public, f.upstream)
	} else {
		website, err = cover.NewReverseProxyHandler(target, f.upstream)
	}
	if err != nil {
		t.Fatal(err)
	}
	observingCover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !f.admit() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer f.workers.Done()
		joined := make(chan struct{})
		defer close(joined)
		var physical any
		if r.ProtoMajor == 3 {
			if conn, _ := r.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn); conn != nil {
				physical = conn
			}
		} else {
			if conn, _ := r.Context().Value(webTLSConnectionContextKey{}).(*tls.Conn); conn != nil {
				physical = conn
			}
		}
		select {
		case f.entries <- webCoverRequestTrailersEntry{r.Header.Get("X-Request-Trailers-Phase"), r.ProtoMajor, physical, joined}:
		default:
			f.unexpected.Add(1)
		}
		website.ServeHTTP(w, r)
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	f.server, err = ListenWeb(WebServerConfig{TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: observingCover,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			f.tunnelDials.Add(1)
			return nil, errors.New("request-trailer fixture forbids tunnel dial")
		}),
		UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
			f.resolutions.Add(1)
			return nil, errors.New("request-trailer fixture forbids UDP resolution")
		})})
	if err != nil {
		t.Fatal(err)
	}
	f.serverDone, f.serverResult = make(chan struct{}), make(chan error, 1)
	go func() { defer close(f.serverDone); f.serverResult <- f.server.Serve(f.ctx) }()
	f.front = webAltSvcPublicTransport(t, clientTLS, proto)
	return f, target
}

func webCoverRequestTrailersExchange(t *testing.T, constructor string, proto int, knownLength, lateCredentials bool) {
	t.Helper()
	prefix := bytes.Repeat([]byte("p"), 64<<10) // Exceeds the H1 writer buffer.
	complete := append(append([]byte(nil), prefix...), []byte("body-end")...)
	sum := sha256.Sum256(complete)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	f, target := newWebCoverRequestTrailersFixture(t, constructor, proto, prefix, complete, digest)
	wanted := http.Header{
		"Content-Digest": {digest}, "X-Upload-End": {"complete-at-eof"},
		"Proxy-Authentication-Info": {"fictional-late-proxy-proof"},
		"Forwarded":                 {"for=fictional-client"}, "X-Forwarded-Host": {"fictional.invalid"},
		"X-Forwarded-Proto": {"http"}, "X-Forwarded-For": {"192.0.2.3"},
		"X-Forwarded-Private-Alias": {"fictional"}, "X-Real-Ip": {"192.0.2.4"},
	}
	if lateCredentials {
		wanted.Set("Authorization", "fictional-late-authorization")
		wanted.Set("Proxy-Authorization", "fictional-late-proxy-authorization")
	}
	for _, phase := range []string{"direct", "cover"} {
		requestContext, cancel := context.WithTimeout(f.ctx, 2*time.Second)
		defer cancel()
		endpoint, rt, expectedProto := target.String()+"/upload", http.RoundTripper(f.direct), 1
		if phase == "cover" {
			endpoint, rt, expectedProto = "https://"+webAltSvcAddress(f.server, proto)+"/upload", f.front, proto
		}
		request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host, request.ContentLength = target.Host, -1
		if phase == "cover" && knownLength {
			request.ContentLength = int64(len(complete))
		}
		request.Header.Set("X-Request-Trailers-Phase", phase)
		request.Header.Set("Authorization", "fictional-header-authorization")
		request.Header.Set("Proxy-Authorization", "Bearer fictional-invalid-ticket")
		request.Header.Set("Origin", "https://"+target.Host)
		request.Header.Set("Referer", "https://"+target.Host+"/form")
		request.Trailer = make(http.Header, len(wanted))
		for key := range wanted {
			request.Trailer[key] = nil
		}
		body := &webCoverRequestTrailersBody{ctx: requestContext, prefix: prefix, tail: []byte("body-end"), trailer: request.Trailer, wanted: wanted, release: make(chan struct{}), closed: make(chan struct{})}
		request.Body = body
		// The gate is owned independently of success assertions and is released
		// before fixture cleanup closes either side of the real exchange.
		t.Cleanup(func() { body.allowEOF(); _ = body.Close() })
		outcome, joined := make(chan webCoverRequestTrailersOutcome, 1), make(chan struct{})
		if !f.admit() {
			t.Fatal("request worker rejected by fixture cleanup")
		}
		go func() {
			defer f.workers.Done()
			defer close(joined)
			response, err := rt.RoundTrip(request)
			result := webCoverRequestTrailersOutcome{err: err}
			if response != nil {
				result.status, result.proto = response.StatusCode, response.ProtoMajor
				result.body, result.readErr = io.ReadAll(response.Body)
				result.closeErr = response.Body.Close()
			}
			outcome <- result
		}()
		select {
		case observed := <-f.chunks:
			if observed != phase {
				t.Fatalf("first-body witness phase=%q, want %q", observed, phase)
			}
		case <-joined:
			t.Fatalf("exchange completed before real origin first chunk: %+v", <-outcome)
		case <-requestContext.Done():
			t.Fatal("real origin did not receive a complete first chunk before the request budget")
		}
		body.allowEOF()
		webCoverRequestTrailersRequireJoin(t, joined, "public request")
		result := <-outcome
		if result.err != nil || result.readErr != nil || result.closeErr != nil || result.status != http.StatusOK || result.proto != expectedProto || string(result.body) != "upload accepted" {
			t.Errorf("%s result status/protocol/body=%d/h%d/%q errors=%v/%v/%v; want 200/h%d/upload accepted", phase, result.status, result.proto, result.body, result.err, result.readErr, result.closeErr, expectedProto)
		}
		var observed webCoverRequestTrailersObservation
		select {
		case observed = <-f.records:
		case <-f.ctx.Done():
			t.Fatal("origin never completed its body/trailer observation")
		}
		webCoverRequestTrailersRequireJoin(t, observed.joined, "origin handler")
		if observed.phase != phase || observed.err != nil || !bytes.Equal(observed.body, complete) {
			t.Errorf("%s origin phase/body/read error=%q/%d/%v", phase, observed.phase, len(observed.body), observed.err)
		}
		if phase == "direct" {
			for key, values := range wanted {
				if observed.trailer.Get(key) != values[0] {
					t.Errorf("direct H1 origin did not receive late %s: %v", key, observed.trailer)
				}
			}
			continue
		}
		var entry webCoverRequestTrailersEntry
		select {
		case entry = <-f.entries:
		case <-f.ctx.Done():
			t.Fatal("cover handler entry absent")
		}
		webCoverRequestTrailersRequireJoin(t, entry.joined, "cover handler")
		if entry.phase != phase || entry.proto != proto || entry.physical == nil {
			t.Errorf("actual cover entry phase/protocol/physical=%q/h%d/%T", entry.phase, entry.proto, entry.physical)
		}
		for _, key := range []string{"Content-Digest", "X-Upload-End"} {
			if observed.trailer.Get(key) != wanted.Get(key) {
				t.Errorf("ordinary late %s lost: %v", key, observed.trailer)
			}
		}
		for _, key := range []string{"Authorization", "Proxy-Authorization", "Proxy-Authentication-Info"} {
			if len(observed.header.Values(key)) != 0 || len(observed.trailer.Values(key)) != 0 {
				t.Errorf("relay credential namespace %s reached origin header/trailer: %v/%v", key, observed.header, observed.trailer)
			}
		}
		if constructor == "public_origin" {
			for key := range wanted {
				if key == "Forwarded" || key == "X-Real-Ip" || bytes.HasPrefix([]byte(key), []byte("X-Forwarded-")) {
					if len(observed.trailer.Values(key)) != 0 {
						t.Errorf("late public forwarding field %s reached origin: %v", key, observed.trailer)
					}
				}
			}
			if observed.header.Get("X-Forwarded-Host") != target.Host || observed.header.Get("X-Forwarded-Proto") != "https" {
				t.Errorf("configured public forwarding headers changed: %v", observed.header)
			}
		}
	}
	if f.invalidDials.Load() != 0 || f.tunnelDials.Load() != 0 || f.resolutions.Load() != 0 || f.unexpected.Load() != 0 {
		t.Errorf("unowned/tunnel/resolver/unexpected counts=%d/%d/%d/%d", f.invalidDials.Load(), f.tunnelDials.Load(), f.resolutions.Load(), f.unexpected.Load())
	}
}

type webCoverRequestTrailersOutcome struct {
	status, proto          int
	body                   []byte
	err, readErr, closeErr error
}

type webCoverRequestTrailersBody struct {
	ctx                    context.Context
	prefix, tail           []byte
	offset                 int
	eof                    bool
	trailer, wanted        http.Header
	release, closed        chan struct{}
	releaseOnce, closeOnce sync.Once
}

func (b *webCoverRequestTrailersBody) Read(p []byte) (int, error) {
	if b.offset < len(b.prefix) {
		n := copy(p, b.prefix[b.offset:])
		b.offset += n
		return n, nil
	}
	select {
	case <-b.closed:
		return 0, net.ErrClosed
	case <-b.ctx.Done():
		return 0, context.Cause(b.ctx)
	case <-b.release:
	}
	if tailOffset := b.offset - len(b.prefix); tailOffset < len(b.tail) {
		n := copy(p, b.tail[tailOffset:])
		b.offset += n
		return n, nil
	}
	// The client transport consumes this map only after the body returns EOF.
	if !b.eof {
		for key, values := range b.wanted {
			b.trailer[key] = append([]string(nil), values...)
		}
		b.eof = true
	}
	return 0, io.EOF
}

func (b *webCoverRequestTrailersBody) allowEOF() { b.releaseOnce.Do(func() { close(b.release) }) }
func (b *webCoverRequestTrailersBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

func webCoverRequestTrailersWait(t *testing.T, done <-chan struct{}, name string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(3 * time.Second):
		t.Errorf("did not join %s", name)
		return false
	}
}

func webCoverRequestTrailersRequireJoin(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	if !webCoverRequestTrailersWait(t, done, name) {
		t.FailNow()
	}
}

func (f *webCoverRequestTrailersFixture) cleanup(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.cancel()
	if f.front != nil {
		switch rt := f.front.(type) {
		case *http.Transport:
			rt.CloseIdleConnections()
		case *http3.Transport:
			_ = rt.Close()
		}
	}
	if f.server != nil {
		if err := f.server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("owned combined Close: %v", err)
		}
	}
	if f.origin != nil {
		_ = f.origin.Close()
	}
	if f.direct != nil {
		f.direct.CloseIdleConnections()
	}
	if f.upstream != nil {
		f.upstream.CloseIdleConnections()
	}
	if f.originDone != nil && webCoverRequestTrailersWait(t, f.originDone, "origin Serve") {
		if err := <-f.originResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("origin Serve: %v", err)
		}
	}
	if f.serverDone != nil && webCoverRequestTrailersWait(t, f.serverDone, "combined Serve") {
		if err := <-f.serverResult; err != nil {
			t.Errorf("combined Serve: %v", err)
		}
	}
	joined := make(chan struct{})
	go func() { defer close(joined); f.workers.Wait() }()
	webCoverRequestTrailersWait(t, joined, "all registered request/handler workers")
}
