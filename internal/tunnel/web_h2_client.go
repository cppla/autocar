package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

// WebH2ClientConfig configures the HTTP/2 side of the web-cover transport.
type WebH2ClientConfig struct {
	ServerAddress string
	Token         string
	TLSConfig     *tls.Config
	// FingerprintProfile defaults to chrome-133, the fixed Chrome 133
	// reference implemented by uTLS v1.8.2. Native is for tests/debugging.
	FingerprintProfile FingerprintProfile
	HandshakeTimeout   time.Duration
	DialTimeout        time.Duration
}

// WebH2Client implements transport.Dialer with one standard HTTP/2 CONNECT
// stream per proxied TCP connection. Concurrent streams reuse a warm TLS 1.3
// connection whenever the peer still accepts new requests.
type WebH2Client struct {
	address          string
	tlsConfig        *tls.Config
	fingerprint      FingerprintProfile
	handshakeTimeout time.Duration
	dialer           transport.Dialer
	auth             *webAuthSigner
	claims           webAuthClaims
	transport        *http2.Transport
	utlsSessionCache utls.ClientSessionCache

	ctx    context.Context
	cancel context.CancelFunc

	dialGate chan struct{}
	mu       sync.Mutex
	closed   bool
	// selected becomes true only after an authenticated CONNECT succeeds.
	selected bool
	current  *webH2ClientSession
	sessions map[*webH2ClientSession]struct{}
}

type webH2ClientSession struct {
	raw       net.Conn
	conn      webH2TLSClientConn
	h2        *http2.ClientConn
	authState webH2ClientAuthState
	authReady chan struct{}
	auth      *webSessionClientAuth
	// opening protects a selected session while an authentication ticket waits
	// for replay-window capacity, before RoundTrip owns an HTTP/2 stream.
	opening int
	// active counts returned net.Conns until full close, including deadline
	// cancellation. Half-closes keep the opposite direction's ownership.
	active int
}

type webH2ClientAuthState uint8

const (
	webH2ClientAuthBootstrapping webH2ClientAuthState = iota
	webH2ClientAuthReady
	webH2ClientAuthFailed
)

type webH2SessionReservation struct {
	session   *webH2ClientSession
	bootstrap bool
	auth      *webSessionClientAuth
}

// NewWebH2Client creates a multiplexed HTTP/2 web-cover dialer.
func NewWebH2Client(config WebH2ClientConfig) (*WebH2Client, error) {
	key, err := deriveWebAuthKey(config.Token)
	if err != nil {
		return nil, err
	}
	return newWebH2ClientWithSigner(config, newWebAuthSigner(key, nil, nil), webAuthClaims{})
}

// newWebH2ClientWithSigner lets a combined client share web authentication
// configuration across HTTP/2 and HTTP/3 without reusing a native token key.
func newWebH2ClientWithSigner(config WebH2ClientConfig, auth *webAuthSigner, claims webAuthClaims) (*WebH2Client, error) {
	if config.ServerAddress == "" {
		return nil, errors.New("tunnel: web-cover HTTP/2 server address is required")
	}
	if auth == nil {
		return nil, errors.New("tunnel: web-cover HTTP/2 client requires authentication")
	}
	if err := validateWebAuthClaims(claims); err != nil {
		return nil, err
	}
	if config.HandshakeTimeout < 0 || config.DialTimeout < 0 {
		return nil, errors.New("tunnel: web-cover HTTP/2 timeouts cannot be negative")
	}
	tlsConfig, err := webClientTLSConfig(config.TLSConfig, config.ServerAddress, webH2ALPN)
	if err != nil {
		return nil, err
	}
	fingerprint, err := normalizeFingerprintProfile(config.FingerprintProfile)
	if err != nil {
		return nil, err
	}
	// Validate the conversion at construction time so unsupported security
	// callbacks never fail only after the first network dial.
	var utlsSessionCache utls.ClientSessionCache
	if fingerprint == FingerprintChrome133 {
		utlsSessionCache = newWebH2UTLSSessionCache(tlsConfig)
		if _, err := chrome133UTLSConfig(tlsConfig, utlsSessionCache); err != nil {
			return nil, err
		}
	}
	handshakeTimeout := config.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	dialTimeout := config.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = defaultDialTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WebH2Client{
		address:          config.ServerAddress,
		tlsConfig:        tlsConfig,
		fingerprint:      fingerprint,
		handshakeTimeout: handshakeTimeout,
		dialer:           &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second},
		auth:             auth,
		claims:           claims,
		transport: &http2.Transport{
			DisableCompression:         true,
			StrictMaxConcurrentStreams: true,
			MaxHeaderListSize:          defaultWebClientMaxResponseHeaderBytes,
		},
		utlsSessionCache: utlsSessionCache,
		ctx:              ctx,
		cancel:           cancel,
		dialGate:         make(chan struct{}, 1),
		sessions:         make(map[*webH2ClientSession]struct{}),
	}, nil
}

// SelectedTransport reports the authenticated path used by the most recent
// successful stream.
func (c *WebH2Client) SelectedTransport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.selected {
		return ""
	}
	return webH2ALPN
}

// DialContext opens one full-duplex, standard HTTP/2 CONNECT stream.
func (c *WebH2Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil dial context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if network != "tcp" {
		return nil, fmt.Errorf("tunnel: web-cover HTTP/2 transport does not support network %q", network)
	}
	authority, err := normalizeWebH2Authority(address)
	if err != nil {
		return nil, err
	}
	binding := webAuthBinding{
		transport: webAuthTransportH2,
		method:    http.MethodConnect,
		authority: authority,
	}
	// As with net.Dialer, ctx governs connection establishment only. Once the
	// CONNECT response succeeds, canceling the caller's context must not kill
	// the returned net.Conn. The client's lifetime remains the stream parent.
	streamCtx, streamCancelCause := context.WithCancelCause(c.ctx)
	streamCancel := func() { streamCancelCause(context.Canceled) }
	openTimeoutDone := make(chan struct{})
	openTimeout := time.AfterFunc(c.handshakeTimeout, func() {
		streamCancelCause(context.DeadlineExceeded)
		close(openTimeoutDone)
	})
	var stopOpenTimeoutOnce sync.Once
	openTimedOut := false
	stopOpenTimeout := func() bool {
		stopOpenTimeoutOnce.Do(func() {
			if !openTimeout.Stop() {
				<-openTimeoutDone
				openTimedOut = true
			}
		})
		return !openTimedOut
	}
	stopDial := context.AfterFunc(ctx, func() { streamCancelCause(context.Cause(ctx)) })
	cancelStream := func() {
		stopDial()
		stopOpenTimeout()
		streamCancel()
	}
	requestReader, requestWriter := io.Pipe()
	fail := func() {
		cancelStream()
		_ = requestWriter.Close()
		_ = requestReader.Close()
	}

	reservation, err := c.reserveSession(streamCtx)
	if err != nil {
		fail()
		return nil, err
	}
	session := reservation.session
	defer c.releaseSessionReservation(session)
	var (
		bearer     string
		authClaims webAuthClaims
		exchange   webSessionExchange
	)
	if reservation.bootstrap {
		bearer, authClaims, err = c.auth.authorization(binding, c.claims)
	} else {
		bearer, exchange, err = reservation.auth.authorization(streamCtx, binding)
		defer reservation.auth.complete(exchange)
	}
	if err != nil {
		fail()
		if reservation.bootstrap || errors.Is(err, errWebSessionSequenceExhausted) {
			c.failSessionAuthentication(session)
		}
		return nil, err
	}
	request := (&http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: authority},
		Host:          authority,
		Header:        webConnectRequestHeaders(bearer),
		Body:          requestReader,
		ContentLength: -1,
	}).WithContext(streamCtx)
	request.Header.Set("Content-Type", "application/octet-stream")

	response, err := session.h2.RoundTrip(request)
	if err != nil {
		cause := context.Cause(streamCtx)
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		} else {
			c.noteSessionFailure(session)
		}
		if cause != nil && !errors.Is(cause, context.Canceled) {
			return nil, cause
		}
		return nil, fmt.Errorf("tunnel: web-cover HTTP/2 CONNECT: %w", err)
	}
	if reservation.bootstrap {
		sessionAuth, ok := acceptWebSessionBootstrap(
			c.auth.key,
			response.Header.Values(webAuthResponseHeader),
			binding,
			authClaims,
			response.StatusCode,
		)
		if !ok || !c.completeSessionBootstrap(session, sessionAuth) {
			_ = response.Body.Close()
			fail()
			c.failSessionAuthentication(session)
			return nil, errors.New("tunnel: web-cover HTTP/2 server authentication failed")
		}
	} else if !reservation.auth.verifyResponseProof(
		response.Header.Values(webAuthResponseHeader),
		binding,
		exchange,
		response.StatusCode,
	) {
		_ = response.Body.Close()
		fail()
		c.failSessionAuthentication(session)
		return nil, errors.New("tunnel: web-cover HTTP/2 server authentication failed")
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		fail()
		return nil, &WebConnectError{Transport: webAuthTransportH2, StatusCode: response.StatusCode}
	}
	// Stop the establishment-only cancellation link before handing ownership
	// to the caller. If cancellation won the race with the response, fail the
	// dial instead of returning an already-canceled stream.
	if !stopOpenTimeout() {
		_ = response.Body.Close()
		fail()
		return nil, context.DeadlineExceeded
	}
	if !stopDial() && ctx.Err() != nil {
		_ = response.Body.Close()
		fail()
		return nil, ctx.Err()
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = response.Body.Close()
		fail()
		return nil, net.ErrClosed
	}
	c.selected = true
	session.active++
	c.mu.Unlock()
	conn := newWebH2Conn(
		response.Body,
		requestWriter,
		cancelStream,
		session.conn.LocalAddr(),
		session.conn.RemoteAddr(),
	)
	conn.onClose = func() { c.releaseSessionStream(session) }
	return conn, nil
}

func normalizeWebH2Authority(address string) (string, error) {
	if len(address) == 0 || len(address) > protocol.MaxAddressLength {
		return "", protocol.ErrBadAddress
	}
	authority, err := httpguts.PunycodeHostPort(address)
	if err != nil {
		return "", protocol.ErrBadAddress
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" || port == "" {
		return "", protocol.ErrBadAddress
	}
	if err := validateWebAuthBinding(webAuthBinding{
		transport: webAuthTransportH2,
		method:    http.MethodConnect,
		authority: authority,
	}); err != nil {
		return "", protocol.ErrBadAddress
	}
	return authority, nil
}

func (c *WebH2Client) reserveSession(ctx context.Context) (webH2SessionReservation, error) {
	if c.ctx.Err() != nil {
		return webH2SessionReservation{}, net.ErrClosed
	}
	for {
		select {
		case c.dialGate <- struct{}{}:
		case <-ctx.Done():
			return webH2SessionReservation{}, context.Cause(ctx)
		case <-c.ctx.Done():
			return webH2SessionReservation{}, net.ErrClosed
		}
		if c.ctx.Err() != nil {
			<-c.dialGate
			return webH2SessionReservation{}, net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			<-c.dialGate
			return webH2SessionReservation{}, context.Cause(ctx)
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			<-c.dialGate
			return webH2SessionReservation{}, net.ErrClosed
		}
		if session := c.current; session != nil {
			switch session.authState {
			case webH2ClientAuthReady:
				if session.h2.CanTakeNewRequest() {
					session.opening++
					auth := session.auth
					c.mu.Unlock()
					<-c.dialGate
					return webH2SessionReservation{session: session, auth: auth}, nil
				}
				c.current = nil
			case webH2ClientAuthBootstrapping:
				ready := session.authReady
				c.mu.Unlock()
				<-c.dialGate
				select {
				case <-ready:
					continue
				case <-ctx.Done():
					return webH2SessionReservation{}, context.Cause(ctx)
				case <-c.ctx.Done():
					return webH2SessionReservation{}, net.ErrClosed
				}
			case webH2ClientAuthFailed:
				c.current = nil
			}
		}
		retired := c.cleanupIdleSessionsLocked()
		c.mu.Unlock()
		closeWebH2Sessions(retired)

		session, err := c.openSession(ctx)
		if err != nil {
			<-c.dialGate
			return webH2SessionReservation{}, err
		}
		if !session.h2.CanTakeNewRequest() {
			<-c.dialGate
			_ = closeWebH2Session(session)
			return webH2SessionReservation{}, errors.New("tunnel: new web-cover HTTP/2 connection rejected its first stream")
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			<-c.dialGate
			_ = closeWebH2Session(session)
			return webH2SessionReservation{}, net.ErrClosed
		}
		c.current = session
		session.opening++
		c.sessions[session] = struct{}{}
		c.mu.Unlock()
		<-c.dialGate
		return webH2SessionReservation{session: session, bootstrap: true}, nil
	}
}

func (c *WebH2Client) releaseSessionReservation(session *webH2ClientSession) {
	c.mu.Lock()
	session.opening--
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	closeWebH2Sessions(retired)
}

func (c *WebH2Client) releaseSessionStream(session *webH2ClientSession) {
	c.mu.Lock()
	session.active--
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	closeWebH2Sessions(retired)
}

func (c *WebH2Client) openSession(ctx context.Context) (*webH2ClientSession, error) {
	dialCtx, dialCancel := context.WithCancel(ctx)
	stopClient := context.AfterFunc(c.ctx, dialCancel)
	defer func() {
		stopClient()
		dialCancel()
	}()

	raw, err := c.dialer.DialContext(dialCtx, "tcp", c.address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: dial web-cover HTTP/2 server: %w", err)
	}
	// NewClientConn synchronously writes the HTTP/2 preface and SETTINGS after
	// TLS succeeds. Until that finishes, the connection is not in c.sessions,
	// so Close cannot find it there. Keep raw I/O tied to both establishment
	// contexts through initialization, not just through the TLS handshake.
	initializationCtx, initializationCancel := context.WithTimeout(dialCtx, c.handshakeTimeout)
	defer initializationCancel()
	rawClosed := make(chan struct{})
	stopRawClose := context.AfterFunc(initializationCtx, func() {
		_ = raw.Close()
		close(rawClosed)
	})
	watcherDetached := false
	defer func() {
		if !watcherDetached && !stopRawClose() {
			<-rawClosed
		}
	}()
	tlsConn, err := newWebH2TLSClientConn(raw, c.tlsConfig, c.fingerprint, c.utlsSessionCache)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	err = tlsConn.HandshakeContext(initializationCtx)
	if err != nil {
		_ = raw.Close()
		if cause := context.Cause(initializationCtx); cause != nil {
			err = cause
		}
		return nil, fmt.Errorf("tunnel: web-cover HTTP/2 TLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		_ = raw.Close()
		return nil, errors.New("tunnel: web-cover HTTP/2 connection did not negotiate TLS 1.3")
	}
	if state.NegotiatedProtocol != webH2ALPN {
		_ = raw.Close()
		return nil, errors.New("tunnel: web-cover HTTP/2 connection did not negotiate h2")
	}
	clientConn, err := c.transport.NewClientConn(tlsConn)
	if err != nil {
		_ = raw.Close()
		if cause := context.Cause(initializationCtx); cause != nil {
			err = cause
		}
		return nil, fmt.Errorf("tunnel: initialize web-cover HTTP/2 connection: %w", err)
	}
	// Stop the watcher before the deferred initialization cancellation. If it
	// already started, join it and reject the connection instead of handing a
	// caller a session whose wire is concurrently being closed.
	watcherDetached = stopRawClose()
	if !watcherDetached {
		<-rawClosed
	}
	if cause := context.Cause(initializationCtx); cause != nil {
		_ = raw.Close()
		_ = clientConn.Close()
		return nil, fmt.Errorf("tunnel: initialize web-cover HTTP/2 connection: %w", cause)
	}
	return &webH2ClientSession{
		raw:       raw,
		conn:      tlsConn,
		h2:        clientConn,
		authState: webH2ClientAuthBootstrapping,
		authReady: make(chan struct{}),
	}, nil
}

func (c *WebH2Client) completeSessionBootstrap(session *webH2ClientSession, auth *webSessionClientAuth) bool {
	if auth == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.current != session || session.authState != webH2ClientAuthBootstrapping {
		return false
	}
	session.auth = auth
	session.authState = webH2ClientAuthReady
	close(session.authReady)
	return true
}

// failSessionAuthentication retires a physical connection whenever its
// connection-level authentication cannot be established or becomes
// ambiguous. In particular, it wakes bootstrap waiters before closing the
// HTTP/2 connection so they can select a new connection without deadlocking.
func (c *WebH2Client) failSessionAuthentication(session *webH2ClientSession) {
	if session == nil {
		return
	}
	c.mu.Lock()
	if session.authState == webH2ClientAuthBootstrapping {
		session.authState = webH2ClientAuthFailed
		close(session.authReady)
	} else {
		session.authState = webH2ClientAuthFailed
	}
	if c.current == session {
		c.current = nil
	}
	delete(c.sessions, session)
	c.mu.Unlock()
	_ = closeWebH2Session(session)
}

func (c *WebH2Client) noteSessionFailure(session *webH2ClientSession) {
	c.mu.Lock()
	if c.current == session && !session.h2.CanTakeNewRequest() {
		c.current = nil
	}
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	closeWebH2Sessions(retired)
}

// Only inspect ownership maintained under c.mu. http2.ClientConn.State takes
// the HTTP/2 write mutex and can wait indefinitely behind a stalled socket;
// using it here would prevent even client Close from interrupting that socket.
// Closing the detached sessions must also happen outside c.mu.
func (c *WebH2Client) cleanupIdleSessionsLocked() []*webH2ClientSession {
	var retired []*webH2ClientSession
	for session := range c.sessions {
		if session == c.current || session.opening != 0 || session.active != 0 {
			continue
		}
		delete(c.sessions, session)
		retired = append(retired, session)
	}
	return retired
}

func closeWebH2Sessions(sessions []*webH2ClientSession) {
	for _, session := range sessions {
		_ = closeWebH2Session(session)
	}
}

func closeWebH2Session(session *webH2ClientSession) error {
	session.auth.close()
	// Stop wire I/O first. Besides releasing HTTP/2 writers, this avoids a
	// synchronous TLS close_notify waiting on an unresponsive peer. Retired
	// sessions reach here only after all opening and returned streams drain.
	var rawErr error
	if session.raw != nil {
		rawErr = session.raw.Close()
		if errors.Is(rawErr, net.ErrClosed) {
			rawErr = nil
		}
	}
	return errors.Join(rawErr, session.h2.Close())
}

// Close prevents future dials, cancels active streams, and closes every pooled
// HTTP/2 connection.
func (c *WebH2Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	sessions := make([]*webH2ClientSession, 0, len(c.sessions))
	for session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.current = nil
	c.sessions = make(map[*webH2ClientSession]struct{})
	c.mu.Unlock()

	var result error
	for _, session := range sessions {
		result = errors.Join(result, closeWebH2Session(session))
	}
	return result
}

var _ transport.Dialer = (*WebH2Client)(nil)
