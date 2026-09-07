package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/cppla/autocar/internal/transport"
)

// WebServerConfig configures one public web origin on a shared numeric port:
// HTTPS over TCP (HTTP/2 and HTTP/1.1) and HTTP/3 over UDP. TCPAddress is
// required unless UDPAddress is set, in which case it is also used for TCP.
// A missing UDPAddress inherits the bound TCP address.
//
// Both configured ports must be equal, except that either may be zero. TCP is
// always bound first, and the resulting numeric port is then used for UDP.
type WebServerConfig struct {
	TCPAddress string
	UDPAddress string
	Token      string
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	Cover      http.Handler
	Dialer     transport.Dialer

	HandshakeTimeout     time.Duration
	DialTimeout          time.Duration
	MaxConcurrentStreams int
	StreamAdmission      *StreamAdmission
	// MaxConnections and MaxClientConnections are shared by the HTTP/2 and
	// HTTP/3 listeners, preventing a source from multiplying its allowance by
	// switching transports.
	MaxConnections       int
	MaxClientConnections int
	MaxHeaderBytes       int
	ReplayEntries        int
	// RFC 9298 CONNECT-UDP is served only by the HTTP/3 listener.
	UDPResolver          UDPResolver
	MaxUDPSessions       int
	MaxClientUDPSessions int
	MaxUDPDestinations   int
	UDPReceiveQueue      int
}

// WebServer owns the TCP and UDP listeners for one dual-protocol web-cover
// origin. Both transports share authentication replay state, destination
// policy, timeouts, and one global active-stream budget.
type WebServer struct {
	h2 *WebH2Server
	h3 *WebH3Server

	serveMu sync.Mutex
	served  bool

	closeOnce sync.Once
	closeErr  error
}

// ListenWeb binds both sides of the web-cover origin. TCP is deliberately
// bound before UDP so a :0 configuration can use exactly the same numeric port
// for both protocols.
func ListenWeb(config WebServerConfig) (*WebServer, error) {
	var err error
	config.TCPAddress, config.UDPAddress, err = normalizeWebListenAddresses(config.TCPAddress, config.UDPAddress)
	if err != nil {
		return nil, err
	}
	if config.Cover == nil {
		return nil, errors.New("tunnel: web-cover requires a cover handler")
	}
	if config.Dialer == nil {
		return nil, errors.New("tunnel: web-cover requires an explicit safe destination dialer")
	}

	core, err := newServerCoreWithAdmission(
		config.Token,
		config.Dialer,
		config.HandshakeTimeout,
		config.DialTimeout,
		config.MaxConcurrentStreams,
		config.StreamAdmission,
	)
	if err != nil {
		return nil, err
	}
	key, err := deriveWebAuthKey(config.Token)
	if err != nil {
		return nil, err
	}
	verifier, err := newWebAuthVerifier(key, nil, config.ReplayEntries)
	if err != nil {
		return nil, err
	}
	connectionAdmission, err := newWebConnectionAdmission(config.MaxConnections, config.MaxClientConnections)
	if err != nil {
		return nil, err
	}

	// The value is populated before ListenWeb returns and before the HTTP
	// server can serve a request. A response-writer wrapper commits it at the
	// last moment, so a cover origin cannot accidentally advertise a stale or
	// unrelated alternative service.
	tcpCover := &webAltSvcCover{next: config.Cover}
	h2, err := listenWebH2WithCore(WebH2ServerConfig{
		Address:              config.TCPAddress,
		Token:                config.Token,
		TLSConfig:            config.TLSConfig,
		Cover:                tcpCover,
		Dialer:               config.Dialer,
		HandshakeTimeout:     config.HandshakeTimeout,
		DialTimeout:          config.DialTimeout,
		MaxConcurrentStreams: config.MaxConcurrentStreams,
		StreamAdmission:      config.StreamAdmission,
		ReplayEntries:        config.ReplayEntries,
		MaxConnections:       config.MaxConnections,
		MaxClientConnections: config.MaxClientConnections,
		MaxHeaderBytes:       config.MaxHeaderBytes,
		connectionAdmission:  connectionAdmission,
	}, core, verifier)
	if err != nil {
		return nil, err
	}

	udpAddress, err := webUDPAddressForTCP(config.UDPAddress, h2.Addr())
	if err != nil {
		_ = h2.Close()
		return nil, err
	}
	h3, err := listenWebH3WithCore(WebH3ServerConfig{
		Address:              udpAddress,
		Token:                config.Token,
		TLSConfig:            config.TLSConfig,
		QUICConfig:           config.QUICConfig,
		Dialer:               config.Dialer,
		Cover:                config.Cover,
		HandshakeTimeout:     config.HandshakeTimeout,
		DialTimeout:          config.DialTimeout,
		MaxConcurrentStreams: config.MaxConcurrentStreams,
		StreamAdmission:      config.StreamAdmission,
		MaxHeaderBytes:       config.MaxHeaderBytes,
		ReplayEntries:        config.ReplayEntries,
		MaxConnections:       config.MaxConnections,
		MaxClientConnections: config.MaxClientConnections,
		connectionAdmission:  connectionAdmission,
		UDPResolver:          config.UDPResolver,
		MaxUDPSessions:       config.MaxUDPSessions,
		MaxClientUDPSessions: config.MaxClientUDPSessions,
		MaxUDPDestinations:   config.MaxUDPDestinations,
		UDPReceiveQueue:      config.UDPReceiveQueue,
	}, core, verifier)
	if err != nil {
		closeErr := normalizeWebServerCloseError(h2.Close())
		if closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("tunnel: close web-cover TCP listener after UDP bind failure: %w", closeErr))
		}
		return nil, err
	}

	tcpCover.value = webH3AltSvcValue(h3.Addr())
	return &WebServer{h2: h2, h3: h3}, nil
}

func normalizeWebListenAddresses(tcpAddress, udpAddress string) (string, string, error) {
	if tcpAddress == "" {
		tcpAddress = udpAddress
	}
	if tcpAddress == "" {
		return "", "", errors.New("tunnel: web-cover TCP listen address is required")
	}
	if udpAddress == "" {
		udpAddress = tcpAddress
	}

	tcpHost, tcpPortText, err := net.SplitHostPort(tcpAddress)
	if err != nil {
		return "", "", fmt.Errorf("tunnel: parse web-cover TCP listen address: %w", err)
	}
	_, udpPortText, err := net.SplitHostPort(udpAddress)
	if err != nil {
		return "", "", fmt.Errorf("tunnel: parse web-cover UDP listen address: %w", err)
	}
	tcpPort, err := net.LookupPort("tcp", tcpPortText)
	if err != nil {
		return "", "", fmt.Errorf("tunnel: resolve web-cover TCP port %q: %w", tcpPortText, err)
	}
	udpPort, err := net.LookupPort("udp", udpPortText)
	if err != nil {
		return "", "", fmt.Errorf("tunnel: resolve web-cover UDP port %q: %w", udpPortText, err)
	}
	if tcpPort != 0 && udpPort != 0 && tcpPort != udpPort {
		return "", "", fmt.Errorf("tunnel: web-cover TCP and UDP ports must match (TCP %d, UDP %d)", tcpPort, udpPort)
	}
	// If only UDP names a fixed port, bind TCP to that port first. If both are
	// zero, the kernel-selected TCP port remains authoritative.
	if tcpPort == 0 && udpPort != 0 {
		tcpAddress = net.JoinHostPort(tcpHost, strconv.Itoa(udpPort))
	}
	return tcpAddress, udpAddress, nil
}

// TCPAddr returns the bound HTTPS address.
func (s *WebServer) TCPAddr() net.Addr {
	if s == nil || s.h2 == nil {
		return nil
	}
	return s.h2.Addr()
}

// UDPAddr returns the bound HTTP/3 address.
func (s *WebServer) UDPAddr() net.Addr {
	if s == nil || s.h3 == nil {
		return nil
	}
	return s.h3.Addr()
}

// Serve runs both protocol servers until ctx is canceled, Close is called, or
// either listener fails. A failure on one side stops the other side before
// Serve returns. Serve may be called exactly once.
func (s *WebServer) Serve(ctx context.Context) error {
	if s == nil || s.h2 == nil || s.h3 == nil {
		return errors.New("tunnel: invalid web-cover server")
	}
	if ctx == nil {
		return errors.New("tunnel: nil web-cover serve context")
	}
	s.serveMu.Lock()
	if s.served {
		s.serveMu.Unlock()
		return errors.New("tunnel: web-cover server already served")
	}
	s.served = true
	s.serveMu.Unlock()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type serveResult struct {
		name string
		err  error
	}
	results := make(chan serveResult, 2)
	go func() { results <- serveResult{name: "HTTPS", err: s.h2.Serve(serveCtx)} }()
	go func() { results <- serveResult{name: "HTTP/3", err: s.h3.Serve(serveCtx)} }()

	first := <-results
	closeErr := normalizeWebServerCloseError(s.Close())
	cancel()
	second := <-results

	var serveErrors []error
	for _, result := range []serveResult{first, second} {
		if result.err != nil {
			serveErrors = append(serveErrors, fmt.Errorf("tunnel: serve web-cover %s: %w", result.name, result.err))
		}
	}
	if closeErr != nil {
		serveErrors = append(serveErrors, closeErr)
	}
	return errors.Join(serveErrors...)
}

// Close stops both listeners and all active streams. It is safe to call from
// multiple goroutines and before or during Serve.
func (s *WebServer) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var h3Err, h2Err error
		if s.h3 != nil {
			h3Err = normalizeWebServerCloseError(s.h3.Close())
		}
		if s.h2 != nil {
			h2Err = normalizeWebServerCloseError(s.h2.Close())
		}
		s.closeErr = errors.Join(h3Err, h2Err)
	})
	return s.closeErr
}

// webUDPAddressForTCP resolves an optional UDP listen address onto the
// already-bound TCP port. The host may differ (for example, explicit IPv4 and
// IPv6 bind addresses), but the externally visible numeric port may not.
func webUDPAddressForTCP(configured string, tcpAddr net.Addr) (string, error) {
	if tcpAddr == nil {
		return "", errors.New("tunnel: missing bound web-cover TCP address")
	}
	_, tcpPortText, err := net.SplitHostPort(tcpAddr.String())
	if err != nil {
		return "", fmt.Errorf("tunnel: parse bound web-cover TCP address: %w", err)
	}
	tcpPort, err := strconv.Atoi(tcpPortText)
	if err != nil || tcpPort < 1 || tcpPort > 65535 {
		return "", fmt.Errorf("tunnel: invalid bound web-cover TCP port %q", tcpPortText)
	}
	if configured == "" {
		configured = tcpAddr.String()
	}
	udpHost, udpPortText, err := net.SplitHostPort(configured)
	if err != nil {
		return "", fmt.Errorf("tunnel: parse web-cover UDP listen address: %w", err)
	}
	udpPort, err := net.LookupPort("udp", udpPortText)
	if err != nil {
		return "", fmt.Errorf("tunnel: resolve web-cover UDP port %q: %w", udpPortText, err)
	}
	if udpPort != 0 && udpPort != tcpPort {
		return "", fmt.Errorf("tunnel: web-cover TCP and UDP ports must match (TCP %d, UDP %d)", tcpPort, udpPort)
	}
	return net.JoinHostPort(udpHost, tcpPortText), nil
}

func webH3AltSvcValue(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return `h3=":` + port + `"`
}

// webAltSvcCover adds Alt-Svc only to cover responses. Authenticated tunnel
// successes and their private capacity/destination failures are deliberately
// untouched. The bound server value wins over an upstream's stale Alt-Svc.
type webAltSvcCover struct {
	next  http.Handler
	value string
}

func (h *webAltSvcCover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writer := &webAltSvcResponseWriter{ResponseWriter: w, value: h.value}
	h.next.ServeHTTP(writer, r)
	// Returning without a final WriteHeader, Write or Flush implicitly sends
	// a 200 response. The handler may have cleared headers after a 1xx response.
	writer.commit()
}

type webAltSvcResponseWriter struct {
	http.ResponseWriter
	value     string
	committed bool
}

func (w *webAltSvcResponseWriter) commit() {
	if w.committed {
		return
	}
	w.committed = true
	w.Header().Set("Alt-Svc", w.value)
}

func (w *webAltSvcResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		// Informational responses do not commit final headers. A reverse proxy
		// can clear and replace them before sending the final response.
		w.Header().Set("Alt-Svc", w.value)
	} else {
		w.commit()
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *webAltSvcResponseWriter) Write(p []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(p)
}

func (w *webAltSvcResponseWriter) Flush() {
	w.commit()
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *webAltSvcResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	w.commit()
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
}

// Unwrap lets http.ResponseController retain the capabilities of the server's
// original response writer.
func (w *webAltSvcResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func normalizeWebServerCloseError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		parts := joined.Unwrap()
		normalized := make([]error, 0, len(parts))
		for _, part := range parts {
			if part = normalizeWebServerCloseError(part); part != nil {
				normalized = append(normalized, part)
			}
		}
		return errors.Join(normalized...)
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
