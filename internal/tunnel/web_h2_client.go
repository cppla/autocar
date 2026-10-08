package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

const defaultWebH2WriteByteTimeout = 30 * time.Second

// WebH2ClientConfig configures the HTTP/2 side of the web-cover transport.
type WebH2ClientConfig struct {
	ServerAddress string
	Token         string
	TLSConfig     *tls.Config
	// FingerprintProfile defaults to chrome-133, the fixed Chrome 133
	// explicit HelloChrome_133 reference originally shipped in uTLS v1.8.2.
	// Native is for tests/debugging.
	FingerprintProfile FingerprintProfile
	HandshakeTimeout   time.Duration
	// DialTimeout bounds each TCP connect, separately from TLS/H2 setup.
	// A cold physical attempt is client-owned; caller cancellation only stops
	// that caller's wait. Zero retains the default TCP dial budget.
	DialTimeout time.Duration
	// WriteByteTimeout limits stalled writes on the shared HTTP/2 connection.
	// Zero uses a conservative thirty-second default; negative values are
	// invalid. This is a TLS write-call budget, not a precise TCP byte-idle
	// timer: it can expire despite partial network progress. A timeout can
	// terminate all streams on that physical TLS connection; it is not a
	// stream deadline or an idle-connection timeout.
	WriteByteTimeout time.Duration
}

// WebH2Client implements transport.Dialer with one standard HTTP/2 CONNECT
// stream per proxied TCP connection. Concurrent streams reuse a warm TLS 1.3
// connection whenever the peer still accepts new requests.
type WebH2Client struct {
	address          string
	tlsConfig        *tls.Config
	fingerprint      FingerprintProfile
	dialTimeout      time.Duration
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
	selected  bool
	current   *webH2ClientSession
	sessions  map[*webH2ClientSession]struct{}
	dial      *webH2DialAttempt
	selection *webH2SelectionCohort
	// Additions are made under mu before the closed gate. Close joins both
	// unpublished physical setup and cleanup detached from sessions.
	workers   sync.WaitGroup
	closeDone chan struct{}
	closeErr  error
}

// One immutable physical result is shared by callers already waiting for it.
// A caller owns its wait and CONNECT, never this client-owned initialization.
type webH2DialAttempt struct {
	done chan struct{}
	err  error
}

// Register before queuing at dialGate, so a fast completed failure remains
// visible to already queued callers. The worker detaches this cohort when it
// publishes its result; later callers can retry without a failure cache.
// Both the current pointer and its attempt are protected by the client mu.
type webH2SelectionCohort struct {
	attempt *webH2DialAttempt
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
	active    int
	closeOnce sync.Once
	closeErr  error
}

type webH2ClientAuthState uint8

const (
	webH2ClientAuthFresh webH2ClientAuthState = iota
	webH2ClientAuthBootstrapping
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
	if config.HandshakeTimeout < 0 || config.DialTimeout < 0 || config.WriteByteTimeout < 0 {
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
	writeByteTimeout := config.WriteByteTimeout
	if writeByteTimeout == 0 {
		writeByteTimeout = defaultWebH2WriteByteTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WebH2Client{
		address:          config.ServerAddress,
		tlsConfig:        tlsConfig,
		fingerprint:      fingerprint,
		dialTimeout:      dialTimeout,
		handshakeTimeout: handshakeTimeout,
		dialer:           &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second},
		auth:             auth,
		claims:           claims,
		transport: &http2.Transport{
			DisableCompression:         true,
			StrictMaxConcurrentStreams: true,
			MaxHeaderListSize:          defaultWebClientMaxResponseHeaderBytes,
			WriteByteTimeout:           writeByteTimeout,
		},
		utlsSessionCache: utlsSessionCache,
		ctx:              ctx,
		cancel:           cancel,
		dialGate:         make(chan struct{}, 1),
		sessions:         make(map[*webH2ClientSession]struct{}),
		closeDone:        make(chan struct{}),
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
	if err := contextError(ctx); err != nil {
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
	openDeadline := time.Now().Add(c.handshakeTimeout)
	openTimeoutDone := make(chan struct{})
	openTimeout := time.AfterFunc(time.Until(openDeadline), func() {
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
	for attempt := 0; ; attempt++ {
		conn, err, unsent := c.dialStreamOnce(ctx, streamCtx, openDeadline, authority, binding, cancelStream, stopDial, stopOpenTimeout)
		if err == nil {
			return conn, nil
		}
		if attempt != 0 || !unsent {
			cancelStream()
			return nil, err
		}
		// A busy Go1.27 connection can also be draining: its public state
		// does not expose every native retirement reason. Retry once only
		// after RoundTrip rejected an entirely unencoded request. Keep the
		// SAME caller link and establishment budget across both attempts.
	}
}

// Each attempt owns its pipe, stream cancellation and authentication exchange.
// Returning before reselection releases its opening reservation and short-ticket
// window slot; a draining physical connection can keep its existing siblings.
func (c *WebH2Client) dialStreamOnce(
	ctx, streamCtx context.Context, openDeadline time.Time,
	authority string, binding webAuthBinding,
	cancelStream func(), stopDial func() bool, stopOpenTimeout func() bool,
) (net.Conn, error, bool) {
	requestCtx, requestCancel := context.WithCancel(streamCtx)
	requestReader, requestWriter := io.Pipe()
	fail := func() {
		requestCancel()
		_ = requestWriter.Close()
		_ = requestReader.Close()
	}

	reservation, err := c.reserveSession(requestCtx)
	if err != nil {
		fail()
		return nil, err, false
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
		bearer, exchange, err = reservation.auth.authorization(requestCtx, binding)
		defer reservation.auth.complete(exchange)
	}
	if err != nil {
		fail()
		if reservation.bootstrap || errors.Is(err, errWebSessionSequenceExhausted) {
			c.failSessionAuthentication(session)
		}
		return nil, err, false
	}
	var headersStarted atomic.Bool
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
		// WroteHeaders is too late: a partial wire write can already have
		// reached the peer. In the pinned HTTP/2 implementation this hook
		// runs while encoding the first field, BEFORE writing any HEADERS.
		WroteHeaderField: func(string, []string) { headersStarted.Store(true) },
	})
	request := (&http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: authority},
		Host:          authority,
		Header:        webConnectRequestHeaders(bearer),
		Body:          requestReader,
		ContentLength: -1,
	}).WithContext(requestCtx)
	request.Header.Set("Content-Type", "application/octet-stream")

	response, err := session.h2.RoundTrip(request)
	if err != nil {
		cause := contextError(requestCtx)
		// Direct ClientConn.RoundTrip joins its request writer on a
		// non-context error. With a live request context, no writer can
		// start encoding after this check. Request.Cancel is deliberately
		// nil. Never retry bootstrap, cancellation, or any encoded request.
		unsent := !reservation.bootstrap && cause == nil && contextError(ctx) == nil && time.Now().Before(openDeadline) &&
			!headersStarted.Load() && !session.h2.CanTakeNewRequest()
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		} else if unsent {
			c.retireSessionSelection(session)
		} else {
			c.noteSessionFailure(session)
		}
		if cause != nil && !errors.Is(cause, context.Canceled) {
			return nil, cause, false
		}
		return nil, fmt.Errorf("tunnel: web-cover HTTP/2 CONNECT: %w", err), unsent
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
			return nil, errors.New("tunnel: web-cover HTTP/2 server authentication failed"), false
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
		return nil, errors.New("tunnel: web-cover HTTP/2 server authentication failed"), false
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		fail()
		return nil, &WebConnectError{Transport: webAuthTransportH2, StatusCode: response.StatusCode}, false
	}
	// Stop the establishment-only cancellation link before handing ownership
	// to the caller. If cancellation won the race with the response, fail the
	// dial instead of returning an already-canceled stream.
	if !stopOpenTimeout() {
		_ = response.Body.Close()
		fail()
		return nil, context.DeadlineExceeded, false
	}
	stopDial()
	if err := contextError(ctx); err != nil {
		_ = response.Body.Close()
		fail()
		return nil, err, false
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = response.Body.Close()
		fail()
		return nil, net.ErrClosed, false
	}
	// Detaching the opening watcher is not the ownership handoff. A caller
	// canceled while queued on mu still owns only this request, not its session.
	if err := contextError(ctx); err != nil {
		c.mu.Unlock()
		_ = response.Body.Close()
		fail()
		return nil, err, false
	}
	c.selected = true
	session.active++
	c.mu.Unlock()
	conn := newWebH2Conn(
		response.Body,
		requestWriter,
		func() { requestCancel(); cancelStream() },
		session.conn.LocalAddr(),
		session.conn.RemoteAddr(),
	)
	conn.onClose = func() { c.releaseSessionStream(session) }
	return conn, nil, false
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
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return webH2SessionReservation{}, net.ErrClosed
		}
		if err := contextError(ctx); err != nil {
			c.mu.Unlock()
			return webH2SessionReservation{}, err
		}
		cohort := c.selection
		if cohort == nil {
			cohort = &webH2SelectionCohort{}
			c.selection = cohort
		}
		c.mu.Unlock()
		select {
		case c.dialGate <- struct{}{}:
		case <-ctx.Done():
			if c.ctx.Err() != nil {
				return webH2SessionReservation{}, net.ErrClosed
			}
			return webH2SessionReservation{}, context.Cause(ctx)
		case <-c.ctx.Done():
			return webH2SessionReservation{}, net.ErrClosed
		}
		if c.ctx.Err() != nil {
			<-c.dialGate
			return webH2SessionReservation{}, net.ErrClosed
		}
		if err := contextError(ctx); err != nil {
			<-c.dialGate
			return webH2SessionReservation{}, err
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			<-c.dialGate
			return webH2SessionReservation{}, net.ErrClosed
		}
		if err := contextError(ctx); err != nil {
			c.mu.Unlock()
			<-c.dialGate
			return webH2SessionReservation{}, err
		}
		if attempt := cohort.attempt; attempt != nil {
			c.mu.Unlock()
			<-c.dialGate
			if err := c.waitSessionDial(ctx, attempt); err != nil {
				return webH2SessionReservation{}, err
			}
			continue
		}
		if session := c.current; session != nil {
			state := session.authState
			canTake := false
			if state == webH2ClientAuthFresh || state == webH2ClientAuthReady {
				// Even legacy State can wait behind a wire write. Keep every
				// transport inspection outside mu so Close can release I/O.
				c.mu.Unlock()
				if state == webH2ClientAuthReady {
					canTake = webH2CanTakeRequest(session.h2)
				} else {
					canTake = session.h2.CanTakeNewRequest()
				}
				c.mu.Lock()
				if c.closed || contextError(ctx) != nil || c.current != session || session.authState != state {
					c.mu.Unlock()
					<-c.dialGate
					continue
				}
			}
			switch session.authState {
			case webH2ClientAuthFresh:
				if canTake {
					// Claim bootstrap only when a live caller reserves a stream,
					// not when a background worker publishes a cold connection.
					session.authState = webH2ClientAuthBootstrapping
					session.opening++
					c.mu.Unlock()
					<-c.dialGate
					return webH2SessionReservation{session: session, bootstrap: true}, nil
				}
				c.current = nil
			case webH2ClientAuthReady:
				if canTake {
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
					if c.ctx.Err() != nil {
						return webH2SessionReservation{}, net.ErrClosed
					}
					return webH2SessionReservation{}, context.Cause(ctx)
				case <-c.ctx.Done():
					return webH2SessionReservation{}, net.ErrClosed
				}
			case webH2ClientAuthFailed:
				c.current = nil
			}
		}
		retired := c.cleanupIdleSessionsLocked()
		attempt := c.dial
		if attempt == nil {
			attempt = &webH2DialAttempt{done: make(chan struct{})}
			c.dial = attempt
			c.workers.Add(1)
			cohort.attempt = attempt
			go c.runSessionDial(attempt)
		} else {
			cohort.attempt = attempt
		}
		c.mu.Unlock()
		<-c.dialGate
		c.closeRetiredSessions(retired)
		if err := c.waitSessionDial(ctx, attempt); err != nil {
			return webH2SessionReservation{}, err
		}
	}
}

func (c *WebH2Client) waitSessionDial(ctx context.Context, attempt *webH2DialAttempt) error {
	select {
	case <-attempt.done:
	case <-c.ctx.Done():
		return net.ErrClosed
	case <-ctx.Done():
		if c.ctx.Err() != nil {
			return net.ErrClosed
		}
		return context.Cause(ctx)
	}
	if c.ctx.Err() != nil {
		return net.ErrClosed
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	return attempt.err
}

func (c *WebH2Client) runSessionDial(attempt *webH2DialAttempt) {
	defer c.workers.Done()
	session, err := c.openSession(c.ctx)
	if err == nil && !session.h2.CanTakeNewRequest() {
		err = errors.New("tunnel: new web-cover HTTP/2 connection rejected its first stream")
	}
	c.mu.Lock()
	accepted := !c.closed && err == nil
	if c.closed {
		err = net.ErrClosed
	}
	if accepted {
		c.current = session
		c.sessions[session] = struct{}{}
	}
	c.mu.Unlock()
	// Join late-result cleanup before either publishing failure or allowing
	// Close to return. No session can register after the closed gate.
	if session != nil && !accepted {
		_ = closeWebH2Session(session)
	}
	c.mu.Lock()
	attempt.err = err
	c.dial = nil
	if c.selection != nil && c.selection.attempt == attempt {
		c.selection = nil
	}
	close(attempt.done)
	c.mu.Unlock()
}

func (c *WebH2Client) releaseSessionReservation(session *webH2ClientSession) {
	c.mu.Lock()
	session.opening--
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	c.closeRetiredSessions(retired)
}

func (c *WebH2Client) releaseSessionStream(session *webH2ClientSession) {
	c.mu.Lock()
	session.active--
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	c.closeRetiredSessions(retired)
}

func (c *WebH2Client) openSession(ctx context.Context) (*webH2ClientSession, error) {
	dialCtx, dialCancel := context.WithCancel(ctx)
	stopClient := context.AfterFunc(c.ctx, dialCancel)
	defer func() {
		stopClient()
		dialCancel()
	}()

	raw, err := c.dialRaw(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: dial web-cover HTTP/2 server: %w", err)
	}
	// NewClientConn synchronously writes the HTTP/2 preface and SETTINGS after
	// TLS succeeds. Until that finishes, the connection is not in c.sessions,
	// so pooled-session closure cannot find it there. The setup worker joins
	// this watcher too; keep raw I/O tied to both establishment contexts
	// through initialization, not just through the TLS handshake.
	initializationCtx, initializationCancel := context.WithTimeout(dialCtx, c.handshakeTimeout)
	defer initializationCancel()
	return c.initializeSession(initializationCtx, raw, c.utlsSessionCache)
}

// The TCP budget stays separate from the existing TLS/H2 initialization
// budget, which covers the complete TLS handshake including any HRR.
func (c *WebH2Client) dialRaw(ctx context.Context) (net.Conn, error) {
	timeout := c.dialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := c.dialer.DialContext(dialCtx, "tcp", c.address)
	if cause := contextError(dialCtx); cause != nil {
		err = cause
	}
	if raw == nil && err == nil {
		err = errors.New("tunnel: HTTP/2 physical dial returned no connection")
	}
	if err != nil {
		if raw != nil {
			err = errors.Join(err, raw.Close())
		}
		return nil, err
	}
	return raw, nil
}

// initializeSession owns one physical attempt. Its immutable raw parameter
// prevents a retired watcher's closure from affecting a replacement socket.
func (c *WebH2Client) initializeSession(initializationCtx context.Context, raw net.Conn, sessionCache utls.ClientSessionCache) (*webH2ClientSession, error) {
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
	tlsConn, err := newWebH2TLSClientConn(raw, c.tlsConfig, c.fingerprint, sessionCache)
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
		authState: webH2ClientAuthFresh,
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
	tracked := !c.closed
	if tracked {
		c.workers.Add(1)
	}
	c.mu.Unlock()
	if tracked {
		defer c.workers.Done()
	}
	_ = closeWebH2Session(session)
}

func (c *WebH2Client) noteSessionFailure(session *webH2ClientSession) {
	canTake := webH2CanTakeRequest(session.h2)
	c.mu.Lock()
	if c.current == session && !canTake {
		c.current = nil
	}
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	c.closeRetiredSessions(retired)
}

// A request rejected before encoding may select a new physical connection,
// but must not abort streams already accepted on the draining connection.
func (c *WebH2Client) retireSessionSelection(session *webH2ClientSession) {
	c.mu.Lock()
	if c.current == session {
		c.current = nil
	}
	retired := c.cleanupIdleSessionsLocked()
	c.mu.Unlock()
	c.closeRetiredSessions(retired)
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
	c.workers.Add(len(retired))
	return retired
}

func (c *WebH2Client) closeRetiredSessions(sessions []*webH2ClientSession) {
	for _, session := range sessions {
		_ = closeWebH2Session(session)
		c.workers.Done()
	}
}

func closeWebH2Session(session *webH2ClientSession) error {
	if session == nil {
		return nil
	}
	session.closeOnce.Do(func() {
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
		var h2Err error
		if session.h2 != nil {
			h2Err = session.h2.Close()
		}
		session.closeErr = errors.Join(rawErr, h2Err)
	})
	return session.closeErr
}

// Close prevents future dials, cancels active streams, and closes every pooled
// HTTP/2 connection. It joins owned setup and detached cleanup; concurrent
// callers observe the same completed closure and error.
func (c *WebH2Client) Close() error {
	c.mu.Lock()
	if c.closeDone == nil {
		c.closeDone = make(chan struct{})
	}
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		return c.closeErr
	}
	c.closed = true
	sessions := make([]*webH2ClientSession, 0, len(c.sessions))
	for session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.current = nil
	c.sessions = make(map[*webH2ClientSession]struct{})
	c.mu.Unlock()
	c.cancel()

	var result error
	for _, session := range sessions {
		result = errors.Join(result, closeWebH2Session(session))
	}
	c.workers.Wait()
	c.closeErr = result
	close(c.closeDone)
	return c.closeErr
}

var _ transport.Dialer = (*WebH2Client)(nil)
