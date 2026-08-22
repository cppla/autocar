package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	proxyAuthorizationHeader = "Proxy-Authorization"
	proxyAuthenticateHeader  = "Proxy-Authenticate"
)

// HTTPServer is an HTTP/1.1 forward proxy. It supports absolute-form HTTP
// requests and CONNECT. To expose an HTTPS proxy, pass a tls.Listener to
// Serve. HTTPS destinations must use CONNECT, so target TLS is never
// intercepted or decrypted.
type HTTPServer struct {
	cfg       serverConfig
	lifecycle *serverLifecycle
	server    *http.Server
	transport *http.Transport
}

// NewHTTPServer validates cfg and creates an HTTP forward proxy.
func NewHTTPServer(cfg Config) (*HTTPServer, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	s := &HTTPServer{
		cfg:       normalized,
		lifecycle: newServerLifecycle(normalized.maxConnections),
	}
	s.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           s.dialContext,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          normalized.maxConnections,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       normalized.idleTimeout,
		TLSHandshakeTimeout:   normalized.dialTimeout,
		ExpectContinueTimeout: time.Second,
	}
	s.server = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: normalized.handshakeTimeout,
		IdleTimeout:       normalized.idleTimeout,
		MaxHeaderBytes:    64 << 10,
		ConnState: func(conn net.Conn, state http.ConnState) {
			tracked, ok := conn.(*trackedConn)
			if !ok {
				return
			}
			switch state {
			case http.StateActive, http.StateHijacked:
				tracked.setActivityTimeout(normalized.idleTimeout)
			case http.StateNew, http.StateIdle, http.StateClosed:
				tracked.setActivityTimeout(0)
			}
		},
	}
	return s, nil
}

// Serve accepts HTTP proxy connections. HTTPS proxy listeners are supported
// by wrapping listener with tls.NewListener before calling Serve.
func (s *HTTPServer) Serve(listener net.Listener) error {
	managed, err := s.lifecycle.manage(listener)
	if err != nil {
		return err
	}
	err = s.server.Serve(managed)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting clients and gracefully waits for both ordinary
// HTTP requests and hijacked CONNECT connections. Remaining connections are
// forcibly closed when ctx expires.
func (s *HTTPServer) Shutdown(ctx context.Context) error {
	closeErr := s.lifecycle.stopAccepting()
	if errors.Is(closeErr, net.ErrClosed) {
		closeErr = nil
	}
	httpErr := s.server.Shutdown(ctx)
	trackErr := s.lifecycle.shutdown(ctx)
	s.transport.CloseIdleConnections()
	return errors.Join(closeErr, httpErr, trackErr)
}

// ServeHTTP implements http.Handler.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set(proxyAuthenticateHeader, `Basic realm="autocar", charset="UTF-8"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		s.serveConnect(w, r)
		return
	}
	s.serveForward(w, r)
}

func (s *HTTPServer) authorized(r *http.Request) bool {
	if s.cfg.authenticator == nil {
		return true
	}
	username, password, ok := parseProxyBasicAuth(r.Header.Get(proxyAuthorizationHeader))
	if !ok {
		return false
	}
	return s.cfg.authenticator.Authenticate(r.Context(), username, password)
}

func parseProxyBasicAuth(value string) (username, password string, ok bool) {
	scheme, encoded, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	username, password, found = strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	return username, password, true
}

func (s *HTTPServer) serveConnect(w http.ResponseWriter, r *http.Request) {
	target, err := connectTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream, err := s.dialContext(r.Context(), "tcp", target)
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT is not supported by this HTTP server", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	// net/http may have read bytes following the CONNECT request into its
	// bufio.Reader. Forward those bytes first; otherwise the initial TLS record
	// can be silently discarded and the tunnel appears to hang.
	if count := buffered.Reader.Buffered(); count > 0 {
		prefix := make([]byte, count)
		if _, err := io.ReadFull(buffered.Reader, prefix); err != nil {
			return
		}
		if err := writeAll(upstream, prefix, s.cfg.idleTimeout); err != nil {
			return
		}
	}
	_ = relay(client, upstream, s.cfg.idleTimeout)
}

func connectTarget(r *http.Request) (string, error) {
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	if target == "" {
		return "", errors.New("missing CONNECT target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return "", errors.New("CONNECT target must be host:port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", errors.New("CONNECT target contains an invalid port")
	}
	if err := validateHTTPHost(host); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), nil
}

func validateHTTPHost(host string) error {
	if strings.ContainsAny(host, "\x00\r\n\t /\\") {
		return errors.New("target contains an invalid host")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return errors.New("target contains an invalid IPv6 address")
	}
	return nil
}

func (s *HTTPServer) serveForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "proxy requests must use an absolute URL", http.StatusBadRequest)
		return
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme == "https" {
		http.Error(w, "HTTPS targets must use CONNECT", http.StatusBadRequest)
		return
	}
	if scheme != "http" {
		http.Error(w, "unsupported URL scheme", http.StatusBadRequest)
		return
	}
	if r.URL.User != nil {
		http.Error(w, "userinfo in proxy target is not supported", http.StatusBadRequest)
		return
	}
	if err := validateAbsoluteTarget(r.URL); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	// For absolute-form requests the URI authority is authoritative. A proxy
	// must not let a conflicting inbound Host field select a different virtual
	// host at the destination.
	out.Host = out.URL.Host
	out.URL.Fragment = ""
	out.URL.RawFragment = ""
	out.Close = false
	removeHopByHopHeaders(out.Header)
	out.Header.Del(proxyAuthorizationHeader)
	out.Header.Del("Proxy-Connection")

	response, err := s.transport.RoundTrip(out)
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	for key := range response.Trailer {
		if !isHopByHopHeader(key) {
			w.Header().Add("Trailer", key)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
	for key, values := range response.Trailer {
		if isHopByHopHeader(key) {
			continue
		}
		w.Header()[textproto.CanonicalMIMEHeaderKey(key)] = append([]string(nil), values...)
	}
}

func validateAbsoluteTarget(target *url.URL) error {
	host := target.Hostname()
	if host == "" {
		return errors.New("proxy target is missing a host")
	}
	if err := validateHTTPHost(host); err != nil {
		return err
	}
	port := target.Port()
	if port == "" {
		return nil
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return errors.New("proxy target contains an invalid port")
	}
	return nil
}

func (s *HTTPServer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if s.cfg.dialTimeout <= 0 {
		conn, err = s.cfg.dialer.DialContext(ctx, network, address)
	} else {
		dialCtx, cancel := context.WithTimeout(ctx, s.cfg.dialTimeout)
		defer cancel()
		conn, err = s.cfg.dialer.DialContext(dialCtx, network, address)
	}
	if err != nil {
		return nil, err
	}
	return &activityConn{Conn: conn, timeout: s.cfg.idleTimeout}, nil
}

func writeGatewayError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		status = http.StatusGatewayTimeout
	}
	http.Error(w, http.StatusText(status), status)
}

func writeAll(conn net.Conn, payload []byte, timeout time.Duration) error {
	for len(payload) > 0 {
		if timeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		}
		written, err := conn.Write(payload)
		if written < 0 || written > len(payload) {
			return errors.New("proxy: invalid write count")
		}
		payload = payload[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

var staticHopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header http.Header) {
	for _, connectionValue := range header.Values("Connection") {
		for _, token := range strings.Split(connectionValue, ",") {
			if token = textproto.TrimString(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, key := range staticHopByHopHeaders {
		header.Del(key)
	}
}

func isHopByHopHeader(key string) bool {
	for _, hop := range staticHopByHopHeaders {
		if strings.EqualFold(key, hop) {
			return true
		}
	}
	return false
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
