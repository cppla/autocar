package cover

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloneRequestForCover(t *testing.T) {
	t.Run("owned_maps_and_values", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
		request.Header = http.Header{
			"Authorization": {"website-header"}, "X-End": {"original-header"},
			"Proxy-Authorization": {"fictional-canonical"}, "proxy-authorization": {"fictional-alias"},
		}
		request.Trailer = http.Header{
			"X-End": {"original-trailer"}, "Authorization": {"website-trailer"},
			"Proxy-Authorization": {"fictional-canonical"}, "proxy-authorization": {"fictional-alias"},
		}
		beforeHeader, beforeTrailer := request.Header.Clone(), request.Trailer.Clone()
		clone := CloneRequestForCover(request)
		for _, fields := range []http.Header{clone.Header, clone.Trailer} {
			requestTrailerAssertAbsent(t, fields, "Proxy-Authorization")
		}
		if clone.Header.Get("Authorization") != "website-header" || clone.Trailer.Get("Authorization") != "website-trailer" {
			t.Error("cover cloning changed the custom website's ordinary Authorization policy")
		}
		clone.Header["X-End"][0] = "changed-clone-header"
		clone.Trailer["X-End"][0] = "changed-clone-trailer"
		clone.Header.Set("X-Only-Clone", "owned")
		clone.Trailer.Set("X-Only-Clone", "owned")
		if !reflect.DeepEqual(request.Header, beforeHeader) || !reflect.DeepEqual(request.Trailer, beforeTrailer) {
			t.Error("clone filtering or value mutations changed caller-owned maps/slices")
		}
	})
	t.Run("two_clone_layers_follow_replacement", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
		request.Header.Set("Content-Length", "10")
		request.Header.Set("Proxy-Authorization", "fictional-header")
		request.Trailer = http.Header{"X-End": nil, "Proxy-Authorization": nil}
		initial := request.Trailer
		beforeInitial := initial.Clone()
		request.ContentLength = 10
		request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("first-last")), nil }
		reads := 0
		request.Body = &requestTrailerUnitBody{read: func(p []byte) (int, error) {
			reads++
			if reads == 1 {
				return copy(p, "first-"), nil
			}
			// The pinned H3 server replaces Request.Trailer rather than filling
			// the initial map. Both clone layers must follow the current source.
			request.Trailer = http.Header{"X-End": {"retained"}, "Proxy-Authorization": {"fictional-late"}}
			return copy(p, "last"), io.EOF
		}}
		coverRequest := CloneRequestForCover(request)
		out := coverRequest.Clone(coverRequest.Context())
		prepareRequestTrailers(coverRequest, out, false)
		owned := out.Trailer
		if reads != 0 {
			t.Error("preparing trailers eagerly read the upload body")
		}
		requestTrailerAssertFraming(t, out)
		buffer := make([]byte, 16)
		n, err := out.Body.Read(buffer)
		if n != 6 || err != nil || string(buffer[:n]) != "first-" || reads != 1 {
			t.Fatalf("first streaming read = %d/%v/%q, reads=%d", n, err, buffer[:n], reads)
		}
		if owned.Get("X-End") != "" {
			t.Error("trailer values were published before EOF")
		}
		n, err = out.Body.Read(buffer)
		if n != 4 || err != io.EOF || string(buffer[:n]) != "last" {
			t.Fatalf("terminal byte+EOF read = %d/%v/%q", n, err, buffer[:n])
		}
		if owned.Get("X-End") != "retained" || coverRequest.Trailer.Get("X-End") != "retained" {
			t.Error("EOF did not update the originally owned destination maps")
		}
		requestTrailerAssertAbsent(t, out.Trailer, "Proxy-Authorization")
		requestTrailerAssertAbsent(t, coverRequest.Trailer, "Proxy-Authorization")
		if !reflect.DeepEqual(initial, beforeInitial) || request.Header.Get("Proxy-Authorization") != "fictional-header" ||
			request.Trailer.Get("Proxy-Authorization") != "fictional-late" || request.ContentLength != 10 || request.GetBody == nil {
			t.Error("proxy filtering changed caller-owned initial or terminal metadata")
		}
		request.Trailer["X-End"][0] = "changed-source"
		if coverRequest.Trailer.Get("X-End") != "retained" || out.Trailer.Get("X-End") != "retained" {
			t.Error("source terminal values alias a clone's copied values")
		}
		coverRequest.Trailer["X-End"][0] = "changed-inner-clone"
		if out.Trailer.Get("X-End") != "retained" {
			t.Error("the two clone layers share trailer value slices")
		}
	})
	t.Run("two_layers_preserve_undeclared_terminal_nominations", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
		request.Trailer = http.Header{"X-End": nil, "X-Late-Hop": nil}
		request.Body = &requestTrailerUnitBody{read: func(p []byte) (int, error) {
			request.Trailer = http.Header{
				// Connection itself was never declared and must not be copied
				// into either clone. Its nomination still constrains the outer
				// reverse-proxy trailer policy at successful EOF.
				"Connection": {"X-Late-Hop"}, "X-Late-Hop": {"fictional-hop"}, "X-End": {"retained"},
			}
			return copy(p, "x"), io.EOF
		}}
		inner := CloneRequestForCover(request)
		out := inner.Clone(inner.Context())
		prepareRequestTrailers(inner, out, false)
		body, err := io.ReadAll(out.Body)
		if err != nil || string(body) != "x" || out.Trailer.Get("X-End") != "retained" {
			t.Fatalf("nested upload control failed: %q/%v", body, err)
		}
		requestTrailerAssertAbsent(t, inner.Trailer, "Connection")
		requestTrailerAssertAbsent(t, out.Trailer, "Connection", "X-Late-Hop")
		if request.Trailer.Get("Connection") != "X-Late-Hop" || request.Trailer.Get("X-Late-Hop") != "fictional-hop" {
			t.Error("terminal policy filtering modified the original request")
		}
	})
	t.Run("case_aliases_are_copied_once", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
		request.Trailer = http.Header{"X-End": nil, "x-end": nil}
		initial := request.Trailer
		beforeInitial := initial.Clone()
		request.Body = &requestTrailerUnitBody{read: func(p []byte) (int, error) {
			request.Trailer = http.Header{"X-End": {"canonical-value"}, "x-end": {"alias-value"}}
			return copy(p, "x"), io.EOF
		}}
		inner := CloneRequestForCover(request)
		out := inner.Clone(inner.Context())
		prepareRequestTrailers(inner, out, false)
		body, err := io.ReadAll(out.Body)
		if err != nil || string(body) != "x" {
			t.Fatalf("case-alias upload control failed: %q/%v", body, err)
		}
		for _, destination := range []http.Header{inner.Trailer, out.Trailer} {
			values := append([]string(nil), destination.Values("X-End")...)
			sort.Strings(values) // Never assume an order across distinct map fields.
			if len(destination) != 1 || !reflect.DeepEqual(values, []string{"alias-value", "canonical-value"}) {
				t.Errorf("case-alias values duplicated or declarations remained split: %v", destination)
			}
		}
		if !reflect.DeepEqual(initial, beforeInitial) || len(request.Trailer) != 2 ||
			!reflect.DeepEqual(request.Trailer["X-End"], []string{"canonical-value"}) || !reflect.DeepEqual(request.Trailer["x-end"], []string{"alias-value"}) {
			t.Error("canonicalizing outbound aliases changed the original source maps/values")
		}
	})
}

func TestPrepareRequestTrailersMetadataPolicy(t *testing.T) {
	for _, publicOrigin := range []bool{false, true} {
		t.Run(fmt.Sprintf("public_origin_%t", publicOrigin), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
			request.Header = http.Header{"Connection": {"X-From-Header"}, "Content-Length": {"1"}}
			request.ContentLength = 1
			request.Trailer = http.Header{
				"Connection": {"X-From-Initial-Trailer"}, "X-From-Header": nil, "X-From-Initial-Trailer": nil,
				"X-Late-Hop": nil, "X-End": nil, "X-Missing": {"initial-only"},
				"Authentication-Info": nil, "WWW-Authenticate": nil,
				"Host": nil, "Content-Length": nil, "If-Match": nil, "bad field": nil, "X-ſafe": nil,
				"Authorization": nil, "proxy-authorization": nil, "Proxy-Authenticate": nil,
				"Proxy-Authentication-Info": nil, "Proxy-Connection": nil, "Keep-Alive": nil,
				"Te": nil, "Trailer": nil, "Transfer-Encoding": nil, "Upgrade": nil,
				"Forwarded": nil, "X-Forwarded-For": nil, "x-forwarded-proto": nil, "X-Real-IP": nil,
			}
			initial := request.Trailer
			beforeHeader, beforeInitial := request.Header.Clone(), initial.Clone()
			request.Body = &requestTrailerUnitBody{read: func(p []byte) (int, error) {
				request.Trailer = http.Header{
					"Connection": {"X-Late-Hop"}, "X-From-Header": {"fictional-initial-nominee"},
					"X-From-Initial-Trailer": {"fictional-trailer-nominee"}, "X-Late-Hop": {"fictional-late-nominee"},
					"X-End": {"retained"}, "X-Undeclared": {"not-supported"},
					"Authentication-Info": {"ordinary-auth-info"}, "WWW-Authenticate": {"ordinary-challenge"},
					"Authorization": {"fictional"}, "proxy-authorization": {"fictional"},
					"Proxy-Authenticate": {"fictional"}, "Proxy-Authentication-Info": {"fictional"},
					"Proxy-Connection": {"fictional"}, "Keep-Alive": {"fictional"}, "Te": {"fictional"},
					"Trailer": {"fictional"}, "Transfer-Encoding": {"fictional"}, "Upgrade": {"fictional"},
					"Forwarded": {"host=fictional.example"}, "X-Forwarded-For": {"192.0.2.1"},
					"x-forwarded-proto": {"fictional"}, "X-Real-IP": {"192.0.2.2"},
				}
				return copy(p, "x"), io.EOF
			}}
			out := request.Clone(request.Context())
			prepareRequestTrailers(request, out, publicOrigin)
			owned := out.Trailer
			unsafe := []string{"Connection", "Authorization", "Proxy-Authorization", "Proxy-Authenticate", "Proxy-Authentication-Info", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-From-Header", "X-From-Initial-Trailer", "WWW-Authenticate", "Host", "Content-Length", "If-Match", "bad field", "X-ſafe"}
			requestTrailerAssertAbsent(t, out.Trailer, unsafe...)
			if publicOrigin {
				requestTrailerAssertAbsent(t, out.Trailer, "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP")
			}
			body, err := io.ReadAll(out.Body)
			if err != nil || string(body) != "x" {
				t.Fatalf("upload body changed: %q/%v", body, err)
			}
			requestTrailerAssertAbsent(t, out.Trailer, append(unsafe, "X-Late-Hop", "X-Undeclared")...)
			if owned.Get("X-End") != "retained" || out.Trailer.Get("Authentication-Info") != "ordinary-auth-info" || out.Trailer.Get("X-Missing") != "" {
				t.Errorf("allowed declared trailer values changed or stale value survived: %v", out.Trailer)
			}
			if publicOrigin {
				requestTrailerAssertAbsent(t, out.Trailer, "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP")
			} else if out.Trailer.Get("Forwarded") != "host=fictional.example" || out.Trailer.Get("X-Forwarded-For") != "192.0.2.1" {
				t.Error("default mode acquired the opt-in forwarding metadata policy")
			}
			if !reflect.DeepEqual(request.Header, beforeHeader) || !reflect.DeepEqual(initial, beforeInitial) ||
				request.Trailer.Get("Authorization") != "fictional" || request.Trailer.Get("X-Undeclared") != "not-supported" {
				t.Error("request trailer policy mutated source metadata")
			}
		})
	}
}

func TestPrepareRequestTrailersNoBodyOrDeclaration(t *testing.T) {
	for _, mode := range []string{"nil_body", "http_no_body", "no_declaration", "reverse_proxy_zero_length_nil_body"} {
		t.Run(mode, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
			request.Header.Set("Proxy-Authorization", "fictional")
			request.Trailer = http.Header{"X-End": nil}
			request.ContentLength = 7
			request.Body = &requestTrailerUnitBody{}
			switch mode {
			case "nil_body":
				request.Body = nil
			case "http_no_body":
				request.Body = http.NoBody
			case "no_declaration":
				request.Trailer = nil
			case "reverse_proxy_zero_length_nil_body":
				request.ContentLength = 0
			}
			clone := CloneRequestForCover(request)
			if mode != "reverse_proxy_zero_length_nil_body" && clone.Body != request.Body {
				t.Error("cover clone unnecessarily wrapped a body without supported trailers")
			}
			out := clone.Clone(clone.Context())
			if mode == "reverse_proxy_zero_length_nil_body" {
				// ReverseProxy deliberately drops this Body before Rewrite. This
				// iteration does not restore empty-content upload bodies.
				out.Body = nil
			}
			beforeBody, beforeLength := out.Body, out.ContentLength
			prepareRequestTrailers(clone, out, false)
			if out.Body != beforeBody || out.ContentLength != beforeLength || len(out.TransferEncoding) != 0 {
				t.Error("trailer preparation altered an unsupported/body-free request")
			}
			requestTrailerAssertAbsent(t, clone.Header, "Proxy-Authorization")
		})
	}
}

func TestRequestTrailerBodyReadOutcomes(t *testing.T) {
	readFailure := errors.New("fictional upload read failure")
	closeFailure := errors.New("fictional upload close failure")
	for _, test := range []struct {
		name string
		data string
		err  error
	}{
		{"zero_eof", "", io.EOF},
		{"bytes_eof", "tail", io.EOF},
		{"read_failure", "tail", readFailure},
		{"read_canceled", "tail", context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
			request.Trailer = http.Header{"X-End": nil}
			reads, closes := 0, 0
			request.Body = &requestTrailerUnitBody{
				read: func(p []byte) (int, error) {
					reads++
					request.Trailer = http.Header{"X-End": {fmt.Sprintf("terminal-%d", reads)}}
					return copy(p, test.data), test.err
				},
				close: func() error { closes++; return closeFailure },
			}
			out := request.Clone(request.Context())
			prepareRequestTrailers(request, out, false)
			buffer := make([]byte, 16)
			n, err := out.Body.Read(buffer)
			if n != len(test.data) || err != test.err || string(buffer[:n]) != test.data {
				t.Fatalf("Read changed n/bytes/error: %d/%q/%v", n, buffer[:n], err)
			}
			if test.err == io.EOF {
				if out.Trailer.Get("X-End") != "terminal-1" {
					t.Error("successful EOF did not publish trailers before returning")
				}
				_, _ = out.Body.Read(buffer)
				if out.Trailer.Get("X-End") != "terminal-1" {
					t.Error("a repeated Read published trailer values more than once")
				}
			} else if out.Trailer.Get("X-End") != "" {
				t.Error("a non-EOF read failure was presented as completed trailers")
			}
			for expected := 1; expected <= 2; expected++ {
				if err := out.Body.Close(); err != closeFailure || closes != expected {
					t.Errorf("Close changed delegate result/count: %v/%d", err, closes)
				}
			}
		})
	}
	t.Run("close_without_eof_does_not_publish", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
		request.Trailer = http.Header{"X-End": nil}
		request.Body = &requestTrailerUnitBody{close: func() error {
			request.Trailer = http.Header{"X-End": {"close-only-value"}}
			return closeFailure
		}}
		out := request.Clone(request.Context())
		prepareRequestTrailers(request, out, false)
		if err := out.Body.Close(); err != closeFailure || out.Trailer.Get("X-End") != "" {
			t.Error("Close fabricated successful EOF metadata or changed its error")
		}
	})
}

func TestRequestTrailerBodyConcurrentClose(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil)
	request.Trailer = http.Header{"X-End": nil}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	readFailure := errors.New("fictional read interrupted by Close")
	closeFailure := errors.New("fictional Close result")
	var closes atomic.Int64
	request.Body = &requestTrailerUnitBody{
		read: func([]byte) (int, error) {
			close(entered)
			<-release
			// Only Read updates metadata. Close does not mutate a map while
			// Read is in progress: that is outside the supported source contract.
			request.Trailer = http.Header{"X-End": {"incomplete-upload"}}
			return 0, readFailure
		},
		close: func() error {
			closes.Add(1)
			releaseOnce.Do(func() { close(release) })
			return closeFailure
		},
	}
	out := request.Clone(request.Context())
	prepareRequestTrailers(request, out, false)
	readDone, closeDone := make(chan error, 1), make(chan error, 1)
	readJoined, closeJoined := make(chan struct{}), make(chan struct{})
	closeStarted := false
	t.Cleanup(func() {
		// This independent release also joins a reader if a broken wrapper
		// holds a read lock and prevents its own Close from reaching the body.
		releaseOnce.Do(func() { close(release) })
		requestTrailerWait(t, readJoined, "blocked body reader cleanup")
		if closeStarted {
			requestTrailerWait(t, closeJoined, "body closer cleanup")
		}
	})
	go func() {
		defer close(readJoined)
		_, err := out.Body.Read(make([]byte, 1))
		readDone <- err
	}()
	if !requestTrailerWait(t, entered, "body Read entry") {
		return
	}
	closeStarted = true
	go func() { defer close(closeJoined); closeDone <- out.Body.Close() }()
	select {
	case err := <-closeDone:
		if err != closeFailure {
			t.Errorf("Close returned %v, not its original delegate error", err)
		}
	case <-time.After(time.Second):
		t.Error("Close waited for the blocked reader instead of interrupting it")
		return
	}
	select {
	case err := <-readDone:
		if err != readFailure {
			t.Errorf("interrupted Read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Close did not unblock the body reader")
		return
	}
	if !requestTrailerWait(t, readJoined, "body reader join") || !requestTrailerWait(t, closeJoined, "body closer join") {
		return
	}
	if closes.Load() != 1 || out.Trailer.Get("X-End") != "" || request.Trailer.Get("X-End") != "incomplete-upload" {
		t.Error("concurrent Close changed ownership/count or published non-EOF trailers")
	}
}

// This control uses a real verified TLS upstream, not an incoming H2/H3
// frontend. The combined-listener tests independently cover incoming protocols.
func TestReverseProxyRequestTrailersHTTPSUpstream(t *testing.T) {
	for _, constructor := range []string{"default", "public_origin"} {
		for _, protocol := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s_h%d", constructor, protocol), func(t *testing.T) {
				requestTrailerHTTPSExchange(t, constructor, protocol)
			})
		}
	}
}

func requestTrailerHTTPSExchange(t *testing.T, constructor string, protocol int) {
	t.Helper()
	payload := strings.Repeat("owned-checksum-upload;", 64)
	sum := sha256.Sum256([]byte(payload))
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	type observation struct {
		proto           int
		body            string
		header, trailer http.Header
		transfer        []string
		err             error
	}
	observed := make(chan observation, 1)
	var requests, unexpected atomic.Int64
	var workerMu sync.Mutex
	var workers sync.WaitGroup
	stopping := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerMu.Lock()
		if stopping {
			workerMu.Unlock()
			return
		}
		workers.Add(1)
		workerMu.Unlock()
		defer workers.Done()
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		result := observation{r.ProtoMajor, string(body), r.Header.Clone(), r.Trailer.Clone(), append([]string(nil), r.TransferEncoding...), err}
		select {
		case observed <- result:
		default:
			unexpected.Add(1)
		}
		if err != nil || string(body) != payload || r.Trailer.Get("Content-Digest") != digest || r.Trailer.Get("X-Upload-End") != "complete" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, "checksum rejected")
			return
		}
		_, _ = io.WriteString(w, "accepted")
	}))
	server.EnableHTTP2 = protocol == 2
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 2 * time.Second
	server.Config.WriteTimeout = 2 * time.Second
	server.Config.IdleTimeout = 2 * time.Second
	server.StartTLS()
	var transport *http.Transport
	cancel := context.CancelFunc(func() {})
	t.Cleanup(func() {
		cancel()
		if transport != nil {
			transport.CloseIdleConnections()
		}
		workerMu.Lock()
		stopping = true
		workerMu.Unlock()
		serverClosed := make(chan struct{})
		go func() { defer close(serverClosed); server.Close() }()
		requestTrailerWait(t, serverClosed, "owned TLS server close")
		joined := make(chan struct{})
		go func() { defer close(joined); workers.Wait() }()
		requestTrailerWait(t, joined, "owned TLS origin handler join")
		if unexpected.Load() != 0 {
			t.Errorf("unexpected observer sends = %d", unexpected.Load())
		}
	})
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var verified, badDials atomic.Int64
	transport = &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: protocol == 2, DisableCompression: true,
		TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second,
		TLSClientConfig: &tls.Config{RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 {
				return errors.New("owned TLS upstream was not verified")
			}
			verified.Add(1)
			return nil
		}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != origin.Host {
				badDials.Add(1)
				return nil, errors.New("nonowned upstream dial rejected")
			}
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			}
			return conn, err
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outboundClosed := make(chan struct{})
	var outboundCloseOnce sync.Once
	var outboundCloses atomic.Int64
	observedTransport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		// Observe the body handed to the real transport. A shallow copy keeps
		// the trailer bridge's destination map; Request.Clone would detach it.
		out := *request
		body := out.Body
		out.Body = &requestTrailerUnitBody{
			read: body.Read,
			close: func() error {
				err := body.Close()
				outboundCloses.Add(1)
				outboundCloseOnce.Do(func() { close(outboundClosed) })
				return err
			},
		}
		return transport.RoundTrip(&out)
	})
	var handler http.Handler
	if constructor == "public_origin" {
		public, _ := url.Parse("https://public.example")
		handler, err = NewReverseProxyHandlerWithPublicOrigin(origin, public, observedTransport)
	} else {
		handler, err = NewReverseProxyHandler(origin, observedTransport)
	}
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://public.example/upload", nil).WithContext(ctx)
	request.ContentLength = int64(len(payload))
	request.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("Authorization", "fictional-header")
	request.Header.Set("Proxy-Authorization", "fictional-header")
	request.Header.Set("Forwarded", "host=fictional.example")
	request.Trailer = http.Header{
		"Content-Digest": nil, "X-Upload-End": nil, "X-Hop": nil,
		"Authorization": nil, "Proxy-Authorization": nil, "Proxy-Authentication-Info": nil,
		"Forwarded": nil, "X-Forwarded-For": nil, "X-Real-IP": nil,
	}
	initial := request.Trailer
	beforeHeader, beforeInitial := request.Header.Clone(), initial.Clone()
	reader := strings.NewReader(payload)
	sourceEOF := make(chan struct{})
	var eofOnce sync.Once
	var inboundCloses atomic.Int64
	request.Body = &requestTrailerUnitBody{
		read: func(p []byte) (int, error) {
			n, err := reader.Read(p)
			if err == io.EOF {
				eofOnce.Do(func() {
					request.Trailer = http.Header{
						"Content-Digest": {digest}, "X-Upload-End": {"complete"}, "X-Hop": {"fictional-hop"},
						"Authorization": {"fictional-trailer"}, "Proxy-Authorization": {"fictional-trailer"},
						"Proxy-Authentication-Info": {"fictional-trailer"}, "Forwarded": {"host=fictional.example"},
						"X-Forwarded-For": {"192.0.2.1"}, "X-Real-IP": {"192.0.2.2"},
					}
					close(sourceEOF)
				})
			}
			return n, err
		},
		close: func() error { inboundCloses.Add(1); return nil },
	}
	// This direct ServeHTTP fixture owns inbound cleanup, as an HTTP server
	// would. ReverseProxy may shield that body from outbound Close calls.
	var inboundCloseOnce sync.Once
	closeInbound := func() {
		inboundCloseOnce.Do(func() {
			if err := request.Body.Close(); err != nil {
				t.Errorf("owned inbound body close: %v", err)
			}
		})
	}
	t.Cleanup(closeInbound)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	// RoundTrip may close its request body asynchronously after returning.
	if !requestTrailerWait(t, outboundClosed, "owned outbound transport body close") {
		return
	}
	closeInbound()
	var got observation
	select {
	case got = <-observed:
	case <-time.After(time.Second):
		t.Fatalf("real TLS origin was not reached; frontend status=%d", recorder.Code)
	}
	if !requestTrailerWait(t, sourceEOF, "owned source body EOF") {
		return
	}
	if got.err != nil || got.body != payload || got.proto != protocol || recorder.Code != http.StatusOK || recorder.Body.String() != "accepted" {
		t.Errorf("TLS upstream exchange = proto%d body%t readErr%v status%d response%q", got.proto, got.body == payload, got.err, recorder.Code, recorder.Body.String())
	}
	if got.trailer.Get("Content-Digest") != digest || got.trailer.Get("X-Upload-End") != "complete" {
		t.Errorf("declared EOF metadata lost: %v", got.trailer)
	}
	requestTrailerAssertAbsent(t, got.header, "Authorization", "Proxy-Authorization", "Proxy-Authentication-Info", "X-Hop")
	requestTrailerAssertAbsent(t, got.trailer, "Authorization", "Proxy-Authorization", "Proxy-Authentication-Info", "X-Hop")
	if protocol == 2 {
		if len(got.transfer) != 0 || got.header.Get("Transfer-Encoding") != "" {
			t.Error("H1 chunked framing leaked onto the actual H2 upstream")
		}
	} else if !reflect.DeepEqual(got.transfer, []string{"chunked"}) {
		t.Errorf("positive incoming length did not select trailer-capable H1 framing: %v", got.transfer)
	}
	if constructor == "public_origin" {
		requestTrailerAssertAbsent(t, got.trailer, "Forwarded", "X-Forwarded-For", "X-Real-IP")
		if got.header.Get("Forwarded") != "" || got.header.Get("X-Forwarded-Host") != "public.example" || got.header.Get("X-Forwarded-Proto") != "https" {
			t.Error("public origin forwarding header policy changed")
		}
	} else if got.trailer.Get("Forwarded") != "host=fictional.example" {
		t.Error("the opt-in trailer forwarding policy affected the default constructor")
	}
	if requests.Load() != 1 || unexpected.Load() != 0 || verified.Load() != 1 || badDials.Load() != 0 || outboundCloses.Load() == 0 || inboundCloses.Load() == 0 {
		t.Errorf("owned lifecycle controls: requests=%d unexpected=%d verified=%d badDials=%d outboundCloses=%d inboundCloses=%d", requests.Load(), unexpected.Load(), verified.Load(), badDials.Load(), outboundCloses.Load(), inboundCloses.Load())
	}
	if !reflect.DeepEqual(request.Header, beforeHeader) || !reflect.DeepEqual(initial, beforeInitial) ||
		request.ContentLength != int64(len(payload)) || request.Trailer.Get("Authorization") != "fictional-trailer" || request.Trailer.Get("X-Hop") != "fictional-hop" {
		t.Error("proxy altered original initial/terminal request metadata")
	}
	t.Logf("actual verified TLS upstream H%d; encoded message digest and full %d-byte upload retained", got.proto, len(payload))
}

type requestTrailerUnitBody struct {
	read  func([]byte) (int, error)
	close func() error
}

func (b *requestTrailerUnitBody) Read(p []byte) (int, error) {
	if b.read == nil {
		return 0, io.EOF
	}
	return b.read(p)
}

func (b *requestTrailerUnitBody) Close() error {
	if b.close == nil {
		return nil
	}
	return b.close()
}

func requestTrailerAssertAbsent(t *testing.T, header http.Header, names ...string) {
	t.Helper()
	for field := range header {
		for _, name := range names {
			if strings.EqualFold(field, name) {
				t.Errorf("unsafe/undeclared trailer or header %s survived", field)
			}
		}
	}
}

func requestTrailerAssertFraming(t *testing.T, request *http.Request) {
	t.Helper()
	if request.ContentLength != -1 || !reflect.DeepEqual(request.TransferEncoding, []string{"chunked"}) ||
		request.Header.Get("Content-Length") != "" || request.GetBody != nil {
		t.Error("wrapped request retained a known length or an unbridged replay path")
	}
}

func requestTrailerWait(t *testing.T, joined <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-joined:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not complete within the fixture budget", label)
		return false
	}
}
