package tunnel

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/cover"
)

// The frontend transports disable automatic compression and decompression.
// Each constructor uses its real nil-transport path, so this exercises the
// default origin transport rather than a test-configured replacement.
func TestWebCoverRepresentationTransparentAcrossProtocols(t *testing.T) {
	identity := []byte("<!doctype html><title>ordinary site</title><p>representation bytes stay intact</p>\n")
	var encoded bytes.Buffer
	zipped := gzip.NewWriter(&encoded)
	if _, err := zipped.Write(identity); err != nil {
		t.Fatal(err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	gzipBody := append([]byte(nil), encoded.Bytes()...)
	for _, constructor := range []string{"fixed_origin", "public_origin"} {
		t.Run(constructor, func(t *testing.T) {
			for _, proto := range []int{1, 2, 3} {
				t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
					for _, invalidCredential := range []bool{false, true} {
						t.Run(fmt.Sprintf("invalid_ticket_%t", invalidCredential), func(t *testing.T) {
							webCoverRepresentationExchange(t, constructor, proto, invalidCredential, identity, gzipBody)
						})
					}
				})
			}
		})
	}
}

type webCoverRepresentationObservation struct {
	phase, encoding, host, method, uri, credential string
	physical                                       any
	joined                                         <-chan struct{}
}

func webCoverRepresentationExchange(t *testing.T, constructor string, proto int, invalidCredential bool, identity, gzipBody []byte) {
	t.Helper()
	originRequests := make(chan webCoverRepresentationObservation, 2)
	coverRequests := make(chan webCoverRepresentationObservation, 2)
	var unexpected atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		defer close(joined)
		phase, encoding := r.Header.Get("X-Representation-Phase"), r.Header.Get("Accept-Encoding")
		observation := webCoverRepresentationObservation{
			phase: phase, encoding: encoding, host: r.Host, method: r.Method, uri: r.RequestURI,
			credential: r.Header.Get("Proxy-Authorization"), joined: joined,
		}
		select {
		case originRequests <- observation:
		default:
			unexpected.Add(1)
		}
		body := identity
		if encoding == "gzip" {
			body = gzipBody
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Content-Digest", webCoverRepresentationDigest(body))
		w.Header().Set("ETag", webCoverRepresentationETag(body))
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Cache-Control", "public, max-age=120, no-transform")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	origin.Config.ReadHeaderTimeout = 2 * time.Second
	origin.Config.ReadTimeout = 2 * time.Second
	origin.Config.WriteTimeout = 2 * time.Second
	origin.Config.IdleTimeout = 2 * time.Second
	origin.Start()
	// Closing the exact owned origin also releases the nil-transport proxy's
	// idle origin sockets. Its server waits for handlers; no unbounded worker
	// or response-body gate is used in this fixture.
	t.Cleanup(func() { origin.CloseClientConnections(); origin.Close() })
	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Both routing and the configured public authority stay numeric owned
	// loopback addresses, even if an authority regression occurs.
	public := &url.URL{Scheme: "https", Host: target.Host}
	var website http.Handler
	if constructor == "public_origin" {
		website, err = cover.NewReverseProxyHandlerWithPublicOrigin(target, public, nil)
	} else {
		website, err = cover.NewReverseProxyHandler(target, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	observingCover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		defer close(joined)
		var physical any
		if proto == 3 {
			physical, _ = r.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn)
		} else {
			physical, _ = r.Context().Value(webTLSConnectionContextKey{}).(*tls.Conn)
		}
		observation := webCoverRepresentationObservation{
			phase: r.Header.Get("X-Representation-Phase"), credential: r.Header.Get("Proxy-Authorization"),
			physical: physical, joined: joined,
		}
		select {
		case coverRequests <- observation:
		default:
			unexpected.Add(1)
		}
		website.ServeHTTP(w, r)
	})
	var dials, resolves atomic.Int64
	// This existing helper owns a real shared-port TCP/UDP server and joins its
	// Serve worker within three seconds after exact server Close/cancellation.
	server, clientTLS := webAltSvcCombinedServer(t, observingCover, webAltSvcForbiddenDialer(&dials), &resolves)
	rt := webAltSvcPublicTransport(t, clientTLS, proto)
	switch client := rt.(type) {
	case *http.Transport:
		client.DisableCompression = true
	case *http3.Transport:
		client.DisableCompression = true
	default:
		t.Fatalf("unexpected frontend transport type %T", rt)
	}
	var firstPhysical any
	for _, phase := range []string{"identity", "gzip"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+webAltSvcAddress(server, proto)+"/page?phase="+phase, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		request.Host = public.Host
		request.Header.Set("X-Representation-Phase", phase)
		if phase == "gzip" {
			request.Header.Set("Accept-Encoding", "gzip")
		}
		if invalidCredential {
			request.Header.Set("Proxy-Authorization", "Bearer fictional-invalid-ticket")
		}
		response, err := rt.RoundTrip(request)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		closeErr := response.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil {
			t.Fatalf("bounded public response Read/Close=%v/%v", readErr, closeErr)
		}
		if response.StatusCode != 200 || response.ProtoMajor != proto || response.TLS == nil || response.Uncompressed {
			t.Errorf("actual public status/protocol/TLS/auto-decoded=%d/%s/%t/%t", response.StatusCode, response.Proto, response.TLS != nil, response.Uncompressed)
		}
		wantBody, wantEncoding := identity, ""
		if phase == "gzip" {
			wantBody, wantEncoding = gzipBody, "gzip"
		}
		if !bytes.Equal(body, wantBody) {
			t.Errorf("%s wire representation differs: actual %d bytes, expected %d", phase, len(body), len(wantBody))
		}
		for field, want := range map[string]string{
			"Content-Encoding": wantEncoding,
			"Content-Digest":   webCoverRepresentationDigest(wantBody),
			"ETag":             webCoverRepresentationETag(wantBody),
			"Vary":             "Accept-Encoding",
			"Cache-Control":    "public, max-age=120, no-transform",
			"Content-Type":     "text/html; charset=utf-8",
			"Content-Length":   strconv.Itoa(len(wantBody)),
			"Alt-Svc":          webH3AltSvcValue(server.UDPAddr()),
		} {
			if got := response.Header.Get(field); got != want {
				t.Errorf("%s %s=%q, want %q", phase, field, got, want)
			}
		}
		if response.ContentLength != int64(len(wantBody)) || response.Header.Get(webAuthResponseHeader) != "" || response.Header.Get("Proxy-Authenticate") != "" {
			t.Errorf("%s representation length/private proof/challenge changed", phase)
		}
		gotOrigin := webCoverRepresentationReceive(t, originRequests)
		if gotOrigin.phase != phase || gotOrigin.encoding != wantEncoding || gotOrigin.host != target.Host || gotOrigin.method != http.MethodGet || gotOrigin.uri != "/page?phase="+phase || gotOrigin.credential != "" {
			t.Errorf("actual origin phase/AE/Host/method/URI/credential=%q/%q/%q/%q/%q/%q", gotOrigin.phase, gotOrigin.encoding, gotOrigin.host, gotOrigin.method, gotOrigin.uri, gotOrigin.credential)
		}
		webCoverRepresentationJoin(t, gotOrigin.joined, "origin handler")
		gotCover := webCoverRepresentationReceive(t, coverRequests)
		if gotCover.phase != phase || gotCover.credential != "" {
			t.Error("cover request phase changed or tunnel credential survived")
		}
		// Typed nils inside an interface are not a usable physical witness.
		switch physical := gotCover.physical.(type) {
		case *tls.Conn:
			if physical == nil {
				t.Fatal("cover did not observe its actual TLS connection")
			}
		case *quic.Conn:
			if physical == nil {
				t.Fatal("cover did not observe its actual QUIC connection")
			}
		default:
			t.Fatalf("cover physical identity has unexpected type %T", gotCover.physical)
		}
		if firstPhysical == nil {
			firstPhysical = gotCover.physical
		} else if firstPhysical != gotCover.physical {
			t.Error("second ordinary GET did not reuse the same physical frontend connection")
		}
		webCoverRepresentationJoin(t, gotCover.joined, "cover handler")
	}
	if dials.Load() != 0 || resolves.Load() != 0 || unexpected.Load() != 0 || len(originRequests) != 0 || len(coverRequests) != 0 {
		t.Errorf("tunnel dial/resolve/unexpected/remaining origin/cover=%d/%d/%d/%d/%d", dials.Load(), resolves.Load(), unexpected.Load(), len(originRequests), len(coverRequests))
	}
	t.Logf("actual two-GET identity/gzip exchange observed; tunnel dial/resolve counters=%d/%d; physical reuse oracle checked", dials.Load(), resolves.Load())
}

func webCoverRepresentationDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

func webCoverRepresentationETag(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("\"sha256-%x\"", sum)
}

func webCoverRepresentationReceive(t *testing.T, observations <-chan webCoverRepresentationObservation) webCoverRepresentationObservation {
	t.Helper()
	select {
	case observation := <-observations:
		return observation
	case <-time.After(time.Second):
		t.Fatal("completed public response has no actual handler observation")
		return webCoverRepresentationObservation{}
	}
}

func webCoverRepresentationJoin(t *testing.T, joined <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Errorf("%s did not return after its actual response", name)
	}
}
