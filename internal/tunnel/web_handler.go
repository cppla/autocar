package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/apernet/quic-go/http3"
)

// webTunnelHandler serves a real cover origin and only upgrades an
// authenticated HTTP/2 or HTTP/3 CONNECT request into a relay stream. Every
// authentication miss follows the exact same handler path as an ordinary web
// request; it never exposes a proxy authentication challenge or AutoCAR error.
type webTunnelHandler struct {
	auth  *webAuthVerifier
	core  *serverCore
	cover http.Handler
	udp   *serverUDPManager
}

func (h *webTunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wire := webRequestTransport(r)
	// QUIC always uses TLS 1.3. On the TCP side, TLS 1.2 is intentionally
	// available to the public website but can never enter the tunnel path.
	if wire == webAuthTransportH2 && webRequestTLSVersion(r) != tls.VersionTLS13 {
		h.serveCover(w, r)
		return
	}
	if isWebConnectUDPRequest(r, wire) {
		h.serveConnectUDP(w, r)
		return
	}
	if wire == "" || r.Method != http.MethodConnect || r.URL.Path != "" || r.URL.RawQuery != "" {
		h.serveCover(w, r)
		return
	}

	binding := webAuthBinding{
		transport: wire,
		method:    http.MethodConnect,
		authority: r.Host,
	}
	authentication, ok := h.authenticateWebRequest(r, binding)
	if !ok {
		h.serveAuthenticationMiss(w, r)
		return
	}
	defer authentication.closeIncompleteBootstrap()
	// Authentication precedes both admission and destination dialing. A random
	// web client therefore cannot consume the tunnel budget or turn this origin
	// into an SSRF oracle.
	if !h.core.acquire() {
		h.writeAuthenticatedError(w, &authentication, http.StatusServiceUnavailable)
		return
	}
	defer h.core.release()

	dialCtx, cancel := context.WithTimeout(r.Context(), h.core.dialTimeout)
	upstream, err := h.core.dialer.DialContext(dialCtx, "tcp", r.Host)
	cancel()
	if err != nil {
		h.writeAuthenticatedError(w, &authentication, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	switch wire {
	case webAuthTransportH3:
		h.serveH3Connect(w, r, upstream, &authentication)
	case webAuthTransportH2:
		h.serveH2Connect(w, r, upstream, &authentication)
	}
}

func webRequestTLSVersion(request *http.Request) uint16 {
	if request == nil {
		return 0
	}
	if request.TLS != nil {
		return request.TLS.Version
	}
	tlsConnection, _ := request.Context().Value(webTLSConnectionContextKey{}).(*tls.Conn)
	if tlsConnection == nil {
		return 0
	}
	return tlsConnection.ConnectionState().Version
}

func (h *webTunnelHandler) serveCover(w http.ResponseWriter, r *http.Request) {
	// Clone before removing the credential so other middleware cannot observe a
	// mutation of the caller's request. A cover reverse proxy must never forward
	// a tunnel credential to its upstream.
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Del("Proxy-Authorization")
	h.cover.ServeHTTP(w, clone)
}

func (h *webTunnelHandler) serveH3Connect(
	w http.ResponseWriter,
	r *http.Request,
	upstream net.Conn,
	authentication *webRequestAuthentication,
) {
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		h.writeAuthenticatedError(w, authentication, http.StatusBadGateway)
		return
	}
	proof, ok := h.authenticatedResponseProof(authentication, http.StatusOK)
	if !ok {
		abortWebAuthenticatedResponse(authentication)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set(webAuthResponseHeader, proof)
	w.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream() // writes and flushes the response headers
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	remote, _ := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr)
	conn := newWebH3Conn(stream, local, remote)
	_ = conn.SetDeadline(time.Time{})
	relay(conn, upstream)
}

func (h *webTunnelHandler) serveH2Connect(
	w http.ResponseWriter,
	r *http.Request,
	upstream net.Conn,
	authentication *webRequestAuthentication,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeAuthenticatedError(w, authentication, http.StatusBadGateway)
		return
	}
	proof, ok := h.authenticatedResponseProof(authentication, http.StatusOK)
	if !ok {
		abortWebAuthenticatedResponse(authentication)
		return
	}
	// Flush the success headers before reading the request body. Otherwise an
	// HTTP/2 client can wait for RoundTrip while the server waits for upload.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set(webAuthResponseHeader, proof)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	stream := &webResponseStream{body: r.Body, writer: w, flusher: flusher}
	relayWebH2(stream, upstream)
}

// relayWebH2 ends an EOF-delimited response when its destination stops sending.
// The HTTP handler API cannot send response END_STREAM independently of
// returning from ServeHTTP. Once the destination reaches EOF, stop the request
// upload as well and join both copies before returning: leaving it waiting for
// a client FIN would withhold the response EOF indefinitely. A client-side FIN
// still half-closes the destination writer and permits the full reply to drain.
// This limitation is local to H2; the H3 stream adapter supports both half-closes.
func relayWebH2(stream io.ReadWriteCloser, upstream net.Conn) {
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			_ = stream.Close()
			_ = upstream.Close()
		})
	}
	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(upstream, stream)
		if err != nil && !isBenignClose(err) {
			abort()
		} else {
			closeWrite(upstream)
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, upstream)
		// Close the destination too: the upload may already be blocked in a
		// destination Write rather than in the request-body Read.
		abort()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func webRequestTransport(r *http.Request) string {
	if r == nil {
		return ""
	}
	switch r.ProtoMajor {
	case 3:
		return webAuthTransportH3
	case 2:
		return webAuthTransportH2
	default:
		return ""
	}
}

func validateWebTunnelHandler(handler *webTunnelHandler) error {
	if handler == nil || handler.auth == nil || handler.core == nil || handler.cover == nil {
		return errors.New("tunnel: web-cover handler requires authentication, relay core, and cover origin")
	}
	return nil
}

var _ http.Handler = (*webTunnelHandler)(nil)
var _ io.ReadWriteCloser = (*webResponseStream)(nil)
