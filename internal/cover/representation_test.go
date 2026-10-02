package cover

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// These are owned HTTP/1.1 wire tests, not a browser or fingerprint experiment.
// Client transports never request or decode gzip on the test's behalf. A
// synthetic website generates Content-Digest from actual message content;
// the proxy must forward the representation, not authenticate that website.
func TestReverseProxyRepresentationOnWire(t *testing.T) {
	cases := []struct {
		name, method, path, acceptEncoding, byteRange string
	}{
		{"absent_accept_encoding", http.MethodGet, "/negotiated", "", ""},
		{"explicit_gzip", http.MethodGet, "/negotiated", "gzip", ""},
		{"explicit_identity", http.MethodGet, "/negotiated", "identity", ""},
		{"head", http.MethodHead, "/negotiated", "", ""},
		{"range", http.MethodGet, "/negotiated", "", "bytes=2-8"},
		// With no Accept-Encoding, a server may legitimately choose gzip.
		// This separately exposes decoding, not just changed negotiation.
		{"always_gzip_without_accept_encoding", http.MethodGet, "/always-gzip", "", ""},
	}
	for _, mode := range []string{"default", "public_origin"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					f := newRepresentationFixture(t, mode, nil)
					direct, directSeen := f.exchange(f.origin.URL, tc.method, tc.path, tc.acceptEncoding, tc.byteRange)
					proxied, proxySeen := f.exchange(f.front.URL, tc.method, tc.path, tc.acceptEncoding, tc.byteRange)
					if !reflect.DeepEqual(proxySeen.acceptEncoding, directSeen.acceptEncoding) {
						t.Errorf("upstream Accept-Encoding changed: direct=%q proxy=%q", directSeen.acceptEncoding, proxySeen.acceptEncoding)
					}
					if proxySeen.method != tc.method || proxySeen.byteRange != tc.byteRange {
						t.Errorf("upstream method/Range changed: %q/%q", proxySeen.method, proxySeen.byteRange)
					}
					assertRepresentationTransparent(t, proxied, direct, proxySeen)
					if tc.method == http.MethodHead && (len(proxied.body) != 0 || proxied.header.Get("Content-Digest") != representationDigest(nil)) {
						t.Error("HEAD must carry no message content and its digest must describe that empty content")
					}
					if tc.byteRange != "" && (proxied.status != http.StatusPartialContent || proxied.header.Get("Content-Range") != fmt.Sprintf("bytes 2-8/%d", len(f.identity))) {
						t.Errorf("ordinary range status/metadata = %d/%q", proxied.status, proxied.header.Get("Content-Range"))
					}
					t.Logf("owned HTTP/1.1 method=%s path=%s directAE=%q proxyAE=%q directEncoding=%q proxyEncoding=%q directBytes=%d proxyBytes=%d",
						tc.method, tc.path, directSeen.acceptEncoding, proxySeen.acceptEncoding, direct.header.Get("Content-Encoding"), proxied.header.Get("Content-Encoding"), len(direct.body), len(proxied.body))
				})
			}
		})
	}
}

func TestReverseProxyRepresentationCustomTransportPolicy(t *testing.T) {
	for _, mode := range []string{"default", "public_origin"} {
		t.Run(mode, func(t *testing.T) {
			// An explicitly supplied transport owns its policy, including Go's
			// automatic gzip decoding. The constructor must not mutate it to
			// enforce the default policy; callers needing transparency must
			// configure that policy themselves.
			custom := &http.Transport{Proxy: nil, DisableCompression: false, ResponseHeaderTimeout: time.Second, IdleConnTimeout: time.Second}
			t.Cleanup(custom.CloseIdleConnections)
			f := newRepresentationFixture(t, mode, custom)
			custom.DialContext = representationOwnedDial(f.origin.Listener.Addr().String())
			dialPointer := reflect.ValueOf(custom.DialContext).Pointer()
			got, seen := f.exchange(f.front.URL, http.MethodGet, "/negotiated", "", "")
			if custom.DisableCompression || custom.Proxy != nil || custom.ResponseHeaderTimeout != time.Second || custom.IdleConnTimeout != time.Second || reflect.ValueOf(custom.DialContext).Pointer() != dialPointer {
				t.Error("constructor or request processing mutated caller-owned transport configuration")
			}
			if !reflect.DeepEqual(seen.acceptEncoding, []string{"gzip"}) || !bytes.Equal(got.body, f.identity) || got.header.Get("Content-Encoding") != "" {
				t.Errorf("explicit custom gzip policy changed: AE=%q encoding=%q body=%q", seen.acceptEncoding, got.header.Get("Content-Encoding"), got.body)
			}
			if seen.encoding != "gzip" || bytes.Equal(got.body, seen.body) || got.header.Get("Content-Digest") != seen.digest || got.header.Get("ETag") != seen.etag {
				t.Error("custom transport's decoded body / untouched upstream metadata behavior was not preserved")
			}
			t.Log("explicit caller transport retains its automatic gzip policy; this is not a transparent-policy assertion for that caller")
		})
	}
}

type representationSeen struct {
	acceptEncoding []string
	method         string
	byteRange      string
	encoding       string
	digest         string
	etag           string
	length         int64
	body           []byte
	writeErr       error
	joined         <-chan struct{}
}

type representationResult struct {
	status        int
	contentLength int64
	header        http.Header
	body          []byte
}

type representationFixture struct {
	t          *testing.T
	origin     *httptest.Server
	front      *httptest.Server
	client     *http.Client
	identity   []byte
	gzipped    []byte
	seen       chan representationSeen
	requests   atomic.Int32
	unexpected atomic.Int32
	frontDone  chan struct{}
}

func newRepresentationFixture(t *testing.T, mode string, supplied http.RoundTripper) *representationFixture {
	t.Helper()
	global := http.DefaultTransport.(*http.Transport)
	globalCompression := global.Clone().DisableCompression
	t.Cleanup(func() {
		if global.Clone().DisableCompression != globalCompression {
			t.Error("fixture/constructor changed global DefaultTransport compression configuration")
		}
	})
	f := &representationFixture{t: t, identity: []byte("owned website payload: preserve encoded content and ordinary metadata, not client-side transparent decompression"), seen: make(chan representationSeen, 2), frontDone: make(chan struct{}, 1)}
	wantRequests := int32(2)
	if supplied != nil {
		wantRequests = 1
	}
	t.Cleanup(func() {
		if got := f.requests.Load(); got != wantRequests || f.unexpected.Load() != 0 {
			t.Errorf("owned request/observer counts: requests=%d want=%d unexpected=%d", got, wantRequests, f.unexpected.Load())
		}
	})
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(f.identity); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	f.gzipped = bytes.Clone(compressed.Bytes())
	f.origin = httptest.NewUnstartedServer(http.HandlerFunc(f.serveOrigin))
	representationServerBudgets(f.origin)
	f.origin.Start()
	t.Cleanup(func() { f.origin.CloseClientConnections(); f.origin.Close() })
	originURL, err := url.Parse(f.origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.front = httptest.NewUnstartedServer(nil)
	representationServerBudgets(f.front)
	publicURL := &url.URL{Scheme: "https", Host: f.front.Listener.Addr().String()}
	var handler http.Handler
	if mode == "default" {
		handler, err = NewReverseProxyHandler(originURL, supplied)
	} else {
		handler, err = NewReverseProxyHandlerWithPublicOrigin(originURL, publicURL, supplied)
	}
	if err != nil {
		_ = f.front.Listener.Close()
		t.Fatal(err)
	}
	// Inspect the private wrapper solely to close the fixture-owned default
	// transport. Wire assertions above depend only on the public constructors.
	if supplied == nil {
		proxy, ok := handler.(*httputil.ReverseProxy)
		if !ok {
			proxy = handler.(*publicOriginHandler).proxy.(*httputil.ReverseProxy)
		}
		owned := proxy.Transport.(*informationalHeaderTransport).base.(*http.Transport)
		t.Cleanup(owned.CloseIdleConnections)
	}
	f.front.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			select {
			case f.frontDone <- struct{}{}:
			default:
				f.unexpected.Add(1)
			}
		}()
		handler.ServeHTTP(w, r)
	})
	f.front.Start()
	t.Cleanup(func() { f.front.CloseClientConnections(); f.front.Close() })
	clientTransport := &http.Transport{Proxy: nil, DisableCompression: true, ResponseHeaderTimeout: time.Second, IdleConnTimeout: time.Second}
	clientTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != f.origin.Listener.Addr().String() && address != f.front.Listener.Addr().String() {
			return nil, fmt.Errorf("representation fixture refuses non-owned destination %s/%s", network, address)
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
	t.Cleanup(clientTransport.CloseIdleConnections)
	f.client = &http.Client{Transport: clientTransport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}

func representationServerBudgets(server *httptest.Server) {
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ReadTimeout = 2 * time.Second
	server.Config.WriteTimeout = 2 * time.Second
	server.Config.IdleTimeout = time.Second
}

func representationOwnedDial(target string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != target {
			return nil, fmt.Errorf("custom representation transport refuses non-owned destination %s/%s", network, address)
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
}

func (f *representationFixture) serveOrigin(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	joined := make(chan struct{})
	defer close(joined)
	s := representationSeen{acceptEncoding: append([]string(nil), r.Header.Values("Accept-Encoding")...), method: r.Method, byteRange: r.Header.Get("Range"), joined: joined}
	body := f.identity
	status := http.StatusOK
	if r.URL.Path == "/always-gzip" || r.Header.Get("Accept-Encoding") == "gzip" {
		body = f.gzipped
		s.encoding = "gzip"
		w.Header().Set("Content-Encoding", "gzip")
	}
	s.etag = fmt.Sprintf("\"%x\"", sha256.Sum256(body))
	if s.byteRange != "" {
		if s.byteRange != "bytes=2-8" || s.encoding != "" {
			http.Error(w, "invalid owned range", http.StatusBadRequest)
			return
		}
		status = http.StatusPartialContent
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 2-8/%d", len(body)))
		body = body[2:9]
	}
	s.length = int64(len(body))
	// HEAD has no message content. Content-Length and ETag still describe
	// the selected representation; Content-Digest describes empty content.
	if r.Method == http.MethodHead {
		s.body = nil
	} else {
		s.body = bytes.Clone(body)
	}
	s.digest = representationDigest(s.body)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-transform")
	w.Header().Set("Content-Digest", s.digest)
	w.Header().Set("Content-Length", strconv.FormatInt(s.length, 10))
	w.Header().Set("ETag", s.etag)
	w.Header().Set("Vary", "Accept-Encoding")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, s.writeErr = w.Write(s.body)
	}
	select {
	case f.seen <- s:
	default:
		f.unexpected.Add(1)
	}
}

func (f *representationFixture) exchange(base, method, path, acceptEncoding, byteRange string) (representationResult, representationSeen) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	if acceptEncoding != "" {
		request.Header.Set("Accept-Encoding", acceptEncoding)
	}
	if byteRange != "" {
		request.Header.Set("Range", byteRange)
	}
	response, err := f.client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		f.t.Fatalf("owned HTTP response read/close: %v/%v", readErr, closeErr)
	}
	var seen representationSeen
	select {
	case seen = <-f.seen:
	case <-ctx.Done():
		f.t.Fatal("owned origin result did not arrive")
	}
	select {
	case <-seen.joined:
	case <-ctx.Done():
		f.t.Fatal("owned origin handler did not join")
	}
	if seen.writeErr != nil {
		f.t.Fatalf("owned origin write: %v", seen.writeErr)
	}
	if base == f.front.URL {
		select {
		case <-f.frontDone:
		case <-ctx.Done():
			f.t.Fatal("owned front handler did not join")
		}
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 {
		f.t.Errorf("actual public protocol = %s, want HTTP/1.1", response.Proto)
	}
	if f.unexpected.Load() != 0 {
		f.t.Errorf("unexpected observer notifications=%d", f.unexpected.Load())
	}
	return representationResult{status: response.StatusCode, contentLength: response.ContentLength, header: response.Header.Clone(), body: body}, seen
}

func assertRepresentationTransparent(t *testing.T, got, direct representationResult, seen representationSeen) {
	t.Helper()
	if got.status != direct.status || !bytes.Equal(got.body, direct.body) {
		t.Errorf("direct/proxied status/body changed: status=%d/%d bytes=%d/%d", direct.status, got.status, len(direct.body), len(got.body))
	}
	if !bytes.Equal(got.body, seen.body) || got.header.Get("Content-Encoding") != seen.encoding || got.contentLength != seen.length {
		t.Errorf("no-transform upstream representation changed: bytes=%d/%d encoding=%q/%q length=%d/%d", len(seen.body), len(got.body), seen.encoding, got.header.Get("Content-Encoding"), seen.length, got.contentLength)
	}
	for _, field := range []string{"Content-Encoding", "Content-Type", "Content-Length", "Cache-Control", "Content-Digest", "ETag", "Vary", "Content-Range"} {
		if !reflect.DeepEqual(got.header.Values(field), direct.header.Values(field)) {
			t.Errorf("direct/proxied %s changed: %q/%q", field, direct.header.Values(field), got.header.Values(field))
		}
	}
	if got.header.Get("Content-Digest") != representationDigest(got.body) {
		t.Errorf("forwarded Content-Digest does not describe delivered message content: declared=%q actual=%q", got.header.Get("Content-Digest"), representationDigest(got.body))
	}
}

func representationDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}
