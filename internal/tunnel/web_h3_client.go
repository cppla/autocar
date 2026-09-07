package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

const webH3HappyEyeballsDelay = 250 * time.Millisecond

// WebH3ClientConfig configures the HTTP/3 cover transport.
type WebH3ClientConfig struct {
	ServerAddress string
	Token         string
	TLSConfig     *tls.Config
	QUICConfig    *quic.Config
	// FingerprintProfile defaults to chrome-2026-08, a fixed full QUIC
	// handshake profile. Native is retained for interoperability and rollback.
	FingerprintProfile H3FingerprintProfile
	DialTimeout        time.Duration
	HandshakeTimeout   time.Duration
	// MaxUDPSessions bounds live one-target RFC 9298 request streams across
	// all PacketConns. MaxUDPDestinations bounds target streams in one
	// PacketConn. UDPReceiveQueue bounds complete responses awaiting Receive.
	MaxUDPSessions     int
	MaxUDPDestinations int
	UDPReceiveQueue    int
}

// WebH3Client multiplexes standard CONNECT requests over one warm HTTP/3
// connection. No native AutoCAR ALPN or stream preface appears on the wire.
type WebH3Client struct {
	address          string
	originAuthority  string
	tlsConfig        *tls.Config
	quicConfig       *quic.Config
	fingerprint      H3FingerprintProfile
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	signer           *webAuthSigner
	transport        *http3.Transport
	udpSlots         chan struct{}
	udpMaxTargets    int
	udpReceiveQueue  int

	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	selected bool
	conn     *quic.Conn
	client   *http3.ClientConn
	conns    map[*quic.Conn]*webH3ClientSession
	dial     chan struct{}
}

// webH3ClientSession owns one UDP socket because the Chrome profile uses a
// zero-length source connection ID. QUIC cannot safely multiplex another
// connection on that socket in that mode.
type webH3ClientSession struct {
	conn      *quic.Conn
	client    *http3.ClientConn
	transport *quic.Transport
	packet    net.PacketConn
	authState webH3ClientAuthState
	authReady chan struct{}
	auth      *webSessionClientAuth

	closeOnce sync.Once
	closeErr  error
}

type webH3ClientAuthState uint8

const (
	webH3ClientAuthFresh webH3ClientAuthState = iota
	webH3ClientAuthBootstrapping
	webH3ClientAuthReady
	webH3ClientAuthFailed
)

type webH3SessionReservation struct {
	session   *webH3ClientSession
	bootstrap bool
	auth      *webSessionClientAuth
}

func (s *webH3ClientSession) closeResources() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.transport != nil {
			s.closeErr = errors.Join(s.closeErr, s.transport.Close())
		}
		if s.packet != nil {
			s.closeErr = errors.Join(s.closeErr, s.packet.Close())
		}
	})
	return s.closeErr
}

func NewWebH3Client(config WebH3ClientConfig) (*WebH3Client, error) {
	if config.ServerAddress == "" {
		return nil, errors.New("tunnel: web-cover H3 server address is required")
	}
	if _, _, err := net.SplitHostPort(config.ServerAddress); err != nil {
		return nil, fmt.Errorf("tunnel: invalid web-cover H3 server address: %w", err)
	}
	originAuthority, err := normalizeWebH2Authority(config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("tunnel: invalid web-cover H3 origin authority: %w", err)
	}
	key, err := deriveWebAuthKey(config.Token)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := webClientTLSConfig(config.TLSConfig, config.ServerAddress, http3.NextProtoH3)
	if err != nil {
		return nil, err
	}
	fingerprint, err := normalizeH3FingerprintProfile(config.FingerprintProfile)
	if err != nil {
		return nil, err
	}
	if err := validateWebH3FingerprintTLSConfig(tlsConfig, fingerprint); err != nil {
		return nil, err
	}
	dialTimeout := config.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	if dialTimeout < 0 || config.HandshakeTimeout < 0 {
		return nil, errors.New("tunnel: web-cover H3 timeouts cannot be negative")
	}
	handshakeTimeout := config.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	quicConfig := hardenedWebH3ClientConfig(config.QUICConfig, handshakeTimeout, fingerprint)
	maxUDPSessions, err := normalizedUDPCount(config.MaxUDPSessions, defaultClientMaxUDPSessions, "maximum web-cover UDP sessions")
	if err != nil {
		return nil, err
	}
	defaultMaxTargets := min(defaultMaxUDPDestinations, maxUDPSessions)
	maxUDPTargets, err := normalizedUDPCount(config.MaxUDPDestinations, defaultMaxTargets, "maximum web-cover UDP destinations")
	if err != nil {
		return nil, err
	}
	if maxUDPTargets > maxUDPSessions {
		return nil, fmt.Errorf("tunnel: maximum web-cover UDP destinations (%d) exceeds maximum UDP sessions (%d)", maxUDPTargets, maxUDPSessions)
	}
	udpReceiveQueue, err := normalizedUDPCount(config.UDPReceiveQueue, defaultUDPReceiveQueue, "web-cover UDP receive queue")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WebH3Client{
		address:          config.ServerAddress,
		originAuthority:  originAuthority,
		tlsConfig:        tlsConfig,
		quicConfig:       quicConfig,
		fingerprint:      fingerprint,
		dialTimeout:      dialTimeout,
		handshakeTimeout: handshakeTimeout,
		signer:           newWebAuthSigner(key, nil, nil),
		transport: &http3.Transport{
			EnableDatagrams:        true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: defaultWebClientMaxResponseHeaderBytes,
		},
		udpSlots:        make(chan struct{}, maxUDPSessions),
		udpMaxTargets:   maxUDPTargets,
		udpReceiveQueue: udpReceiveQueue,
		ctx:             ctx,
		cancel:          cancel,
		conns:           make(map[*quic.Conn]*webH3ClientSession),
	}, nil
}

func validateWebH3FingerprintTLSConfig(config *tls.Config, profile H3FingerprintProfile) error {
	if profile != H3FingerprintChrome202608 {
		return nil
	}
	if config.VerifyConnection != nil {
		return errors.New("tunnel: chrome-2026-08 HTTP/3 fingerprint profile does not support crypto/tls VerifyConnection; use VerifyPeerCertificate or the native rollback profile")
	}
	if config.GetConfigForClient != nil || config.GetCertificate != nil || len(config.Certificates) > 0 {
		return errors.New("tunnel: chrome-2026-08 HTTP/3 fingerprint profile does not support server-side TLS fields or static client certificates")
	}
	return nil
}

func (c *WebH3Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil web-cover H3 dial context")
	}
	parsed, err := protocol.ParseNetwork(network)
	if err != nil {
		return nil, err
	}
	if parsed != protocol.NetworkTCP {
		return nil, errors.New("tunnel: web-cover H3 CONNECT requires tcp")
	}
	authority, err := normalizeWebH2Authority(address)
	if err != nil {
		return nil, err
	}
	binding := webAuthBinding{
		transport: webAuthTransportH3,
		method:    http.MethodConnect,
		authority: authority,
	}
	reservation, err := c.reserveAuthenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	session := reservation.session
	conn, client := session.conn, session.client
	openContext, cancelOpen := context.WithTimeout(ctx, c.handshakeTimeout)
	stopClient := context.AfterFunc(c.ctx, cancelOpen)
	stopConnection := context.AfterFunc(conn.Context(), cancelOpen)
	defer func() {
		stopClient()
		stopConnection()
		cancelOpen()
	}()
	var (
		bearer     string
		authClaims webAuthClaims
		exchange   webSessionExchange
	)
	if reservation.bootstrap {
		bearer, authClaims, err = c.signer.authorization(binding, webAuthClaims{})
	} else {
		bearer, exchange, err = reservation.auth.authorization(openContext, binding)
		defer reservation.auth.complete(exchange)
	}
	if err != nil {
		if reservation.bootstrap || errors.Is(err, errWebSessionSequenceExhausted) {
			c.failSessionAuthentication(session)
		}
		return nil, err
	}
	stream, err := client.OpenRequestStream(openContext)
	stopClient()
	stopConnection()
	cancelOpen()
	if err != nil {
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		// GOAWAY and caller cancellation are local to opening this request.
		// Retire the connection for new work without aborting sibling streams.
		if ctx.Err() == nil {
			c.retire(conn)
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if c.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		return nil, fmt.Errorf("tunnel: open web-cover H3 request stream: %w", err)
	}
	cancelStream := func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	stopDial := context.AfterFunc(ctx, cancelStream)
	fail := func() {
		stopDial()
		cancelStream()
	}
	openDeadline := time.Now().Add(c.handshakeTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(openDeadline) {
		openDeadline = deadline
	}
	if err := stream.SetDeadline(openDeadline); err != nil {
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: authority},
		Host:   authority,
		Header: webConnectRequestHeaders(bearer),
	}
	if err := stream.SendRequestHeader(req); err != nil {
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if conn.Context().Err() != nil {
			c.retire(conn)
		}
		return nil, fmt.Errorf("tunnel: send web-cover H3 CONNECT: %w", err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if conn.Context().Err() != nil {
			c.retire(conn)
		}
		return nil, fmt.Errorf("tunnel: read web-cover H3 CONNECT response: %w", err)
	}
	if reservation.bootstrap {
		sessionAuth, ok := acceptWebSessionBootstrap(
			c.signer.key,
			response.Header.Values(webAuthResponseHeader),
			binding,
			authClaims,
			response.StatusCode,
		)
		if !ok || !c.completeSessionBootstrap(session, sessionAuth) {
			fail()
			c.failSessionAuthentication(session)
			return nil, errors.New("tunnel: web-cover H3 server authentication failed")
		}
	} else if !reservation.auth.verifyResponseProof(
		response.Header.Values(webAuthResponseHeader),
		binding,
		exchange,
		response.StatusCode,
	) {
		fail()
		c.failSessionAuthentication(session)
		return nil, errors.New("tunnel: web-cover H3 server authentication failed")
	}
	if response.StatusCode != http.StatusOK {
		fail()
		return nil, &WebConnectError{Transport: webAuthTransportH3, StatusCode: response.StatusCode}
	}
	if !stopDial() && ctx.Err() != nil {
		cancelStream()
		return nil, ctx.Err()
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		cancelStream()
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancelStream()
		return nil, net.ErrClosed
	}
	c.selected = true
	c.mu.Unlock()
	return newWebH3Conn(stream, conn.LocalAddr(), conn.RemoteAddr()), nil
}

// reserveAuthenticatedSession assigns exactly one bootstrap request to a new
// physical QUIC connection. Concurrent callers wait for that response before
// allocating their own request streams, so only one padded full credential is
// ever sent on the connection.
func (c *WebH3Client) reserveAuthenticatedSession(ctx context.Context) (webH3SessionReservation, error) {
	for {
		conn, _, err := c.connection(ctx)
		if err != nil {
			return webH3SessionReservation{}, err
		}
		c.mu.Lock()
		session := c.conns[conn]
		if c.closed {
			c.mu.Unlock()
			return webH3SessionReservation{}, net.ErrClosed
		}
		if session == nil || conn.Context().Err() != nil {
			c.mu.Unlock()
			continue
		}
		switch session.authState {
		case webH3ClientAuthFresh:
			session.authState = webH3ClientAuthBootstrapping
			c.mu.Unlock()
			return webH3SessionReservation{session: session, bootstrap: true}, nil
		case webH3ClientAuthReady:
			auth := session.auth
			c.mu.Unlock()
			return webH3SessionReservation{session: session, auth: auth}, nil
		case webH3ClientAuthBootstrapping:
			ready := session.authReady
			c.mu.Unlock()
			select {
			case <-ready:
				continue
			case <-ctx.Done():
				return webH3SessionReservation{}, context.Cause(ctx)
			case <-c.ctx.Done():
				return webH3SessionReservation{}, net.ErrClosed
			}
		case webH3ClientAuthFailed:
			c.mu.Unlock()
			continue
		default:
			c.mu.Unlock()
			return webH3SessionReservation{}, errors.New("tunnel: invalid web-cover H3 authentication state")
		}
	}
}

func (c *WebH3Client) connection(ctx context.Context) (*quic.Conn, *http3.ClientConn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, context.Cause(ctx)
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, nil, net.ErrClosed
		}
		if c.conn != nil && c.client != nil && c.conn.Context().Err() == nil {
			conn, client := c.conn, c.client
			c.mu.Unlock()
			return conn, client, nil
		}
		if waiting := c.dial; waiting != nil {
			c.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-c.ctx.Done():
				return nil, nil, net.ErrClosed
			}
		}
		waiting := make(chan struct{})
		c.dial = waiting
		c.mu.Unlock()

		dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
		stop := context.AfterFunc(c.ctx, cancel)
		session, err := c.dialSession(dialCtx)
		stop()
		cancel()
		var conn *quic.Conn
		var client *http3.ClientConn
		if session != nil {
			conn = session.conn
			client = session.client
		}

		c.mu.Lock()
		if c.closed && session != nil {
			_ = conn.CloseWithError(0, "")
			_ = session.closeResources()
			conn = nil
			client = nil
			err = net.ErrClosed
		} else if err == nil {
			c.conn = conn
			c.client = client
			c.conns[conn] = session
			go c.watchConnection(session)
		}
		c.dial = nil
		close(waiting)
		c.mu.Unlock()
		if err != nil {
			return nil, nil, fmt.Errorf("tunnel: dial web-cover H3: %w", err)
		}
		return conn, client, nil
	}
}

func (c *WebH3Client) dialSession(ctx context.Context) (*webH3ClientSession, error) {
	host, service, err := net.SplitHostPort(c.address)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP/3 relay address: %w", err)
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, fmt.Errorf("resolve HTTP/3 relay port %q: %w", service, err)
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve HTTP/3 relay host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve HTTP/3 relay host %q: no addresses", host)
	}
	return c.dialSessionAddresses(ctx, interleaveWebH3Addresses(addresses), port)
}

type webH3DialResult struct {
	session *webH3ClientSession
	err     error
}

func (c *WebH3Client) dialSessionAddresses(ctx context.Context, addresses []net.IPAddr, port int) (*webH3ClientSession, error) {
	if len(addresses) == 0 {
		return nil, errors.New("no HTTP/3 relay addresses")
	}
	raceContext, cancelRace := context.WithCancel(ctx)
	defer cancelRace()
	results := make(chan webH3DialResult, len(addresses))
	for index, address := range addresses {
		go func(index int, address net.IPAddr) {
			if index > 0 {
				timer := time.NewTimer(time.Duration(index) * webH3HappyEyeballsDelay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-raceContext.Done():
					results <- webH3DialResult{err: context.Cause(raceContext)}
					return
				}
			}
			session, err := c.dialSessionAddress(raceContext, address, port)
			results <- webH3DialResult{session: session, err: err}
		}(index, address)
	}

	var winner *webH3ClientSession
	var dialErr error
	for range addresses {
		result := <-results
		if result.err == nil && result.session != nil && winner == nil {
			winner = result.session
			cancelRace()
			continue
		}
		if result.session != nil {
			_ = result.session.conn.CloseWithError(0, "superseded address candidate")
			_ = result.session.closeResources()
		}
		if result.err != nil && winner == nil {
			dialErr = errors.Join(dialErr, result.err)
		}
	}
	if winner != nil {
		winner.client = c.transport.NewClientConn(winner.conn)
		winner.authState = webH3ClientAuthFresh
		winner.authReady = make(chan struct{})
		return winner, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if dialErr == nil {
		dialErr = errors.New("no usable HTTP/3 relay address")
	}
	return nil, dialErr
}

func (c *WebH3Client) dialSessionAddress(ctx context.Context, address net.IPAddr, port int) (*webH3ClientSession, error) {
	network, localAddress := "udp6", "[::]:0"
	if address.IP.To4() != nil {
		network, localAddress = "udp4", "0.0.0.0:0"
	}
	var listenConfig net.ListenConfig
	packet, err := listenConfig.ListenPacket(ctx, network, localAddress)
	if err != nil {
		return nil, fmt.Errorf("listen %s for %s: %w", network, address.String(), err)
	}
	quicTransport := &quic.Transport{Conn: packet}
	if c.fingerprint == H3FingerprintChrome202608 {
		quicTransport.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
	}
	remote := &net.UDPAddr{IP: address.IP, Port: port, Zone: address.Zone}
	conn, err := quicTransport.Dial(ctx, remote, c.tlsConfig.Clone(), c.quicConfig.Clone())
	if err != nil {
		_ = quicTransport.Close()
		_ = packet.Close()
		return nil, fmt.Errorf("dial %s: %w", remote, err)
	}
	return &webH3ClientSession{conn: conn, transport: quicTransport, packet: packet}, nil
}

func interleaveWebH3Addresses(addresses []net.IPAddr) []net.IPAddr {
	if len(addresses) < 2 {
		return append([]net.IPAddr(nil), addresses...)
	}
	var ipv4, ipv6 []net.IPAddr
	for _, address := range addresses {
		if address.IP.To4() != nil {
			ipv4 = append(ipv4, address)
		} else {
			ipv6 = append(ipv6, address)
		}
	}
	first, second := ipv6, ipv4
	if addresses[0].IP.To4() != nil {
		first, second = ipv4, ipv6
	}
	result := make([]net.IPAddr, 0, len(addresses))
	for index := 0; index < len(first) || index < len(second); index++ {
		if index < len(first) {
			result = append(result, first[index])
		}
		if index < len(second) {
			result = append(result, second[index])
		}
	}
	return result
}

func (c *WebH3Client) watchConnection(session *webH3ClientSession) {
	<-session.conn.Context().Done()
	c.mu.Lock()
	if session.authState == webH3ClientAuthBootstrapping {
		session.authState = webH3ClientAuthFailed
		close(session.authReady)
	} else if session.authState == webH3ClientAuthFresh {
		session.authState = webH3ClientAuthFailed
	}
	delete(c.conns, session.conn)
	session.auth.close()
	if c.conn == session.conn {
		c.conn = nil
		c.client = nil
	}
	c.mu.Unlock()
	_ = session.closeResources()
}

func (c *WebH3Client) completeSessionBootstrap(session *webH3ClientSession, auth *webSessionClientAuth) bool {
	if session == nil || auth == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.conns[session.conn] != session || session.authState != webH3ClientAuthBootstrapping {
		return false
	}
	session.auth = auth
	session.authState = webH3ClientAuthReady
	close(session.authReady)
	return true
}

// failSessionAuthentication makes an ambiguous or invalid authentication
// result fatal to the physical QUIC connection. Continuation credentials must
// never be reused on a replacement connection, and bootstrap waiters must not
// race ahead on state whose server half is unknown.
func (c *WebH3Client) failSessionAuthentication(session *webH3ClientSession) {
	if session == nil {
		return
	}
	c.mu.Lock()
	if session.authState == webH3ClientAuthBootstrapping {
		session.authState = webH3ClientAuthFailed
		close(session.authReady)
	} else {
		session.authState = webH3ClientAuthFailed
	}
	if c.conn == session.conn {
		c.conn = nil
		c.client = nil
	}
	session.auth.close()
	c.mu.Unlock()
	_ = session.conn.CloseWithError(quic.ApplicationErrorCode(applicationShutdown), "connection authentication failed")
}

// retire prevents new request streams from selecting conn while allowing its
// already-established sibling streams to drain. The connection remains
// tracked so Close still terminates it.
func (c *WebH3Client) retire(conn *quic.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
		c.client = nil
	}
	c.mu.Unlock()
}

func (c *WebH3Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	sessions := make([]*webH3ClientSession, 0, len(c.conns))
	for _, session := range c.conns {
		session.auth.close()
		sessions = append(sessions, session)
	}
	c.conn = nil
	c.client = nil
	c.conns = make(map[*quic.Conn]*webH3ClientSession)
	c.mu.Unlock()
	var connErr error
	for _, session := range sessions {
		connErr = errors.Join(connErr, session.conn.CloseWithError(0, ""))
		connErr = errors.Join(connErr, session.closeResources())
	}
	return errors.Join(connErr, c.transport.Close())
}

func (c *WebH3Client) SelectedTransport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.selected {
		return ""
	}
	return webAuthTransportH3
}

// WebConnectError is an authenticated HTTP tunnel rejection. An auto dialer
// must not reinterpret it as a broken transport and retry the same target over
// another path.
type WebConnectError struct {
	Transport  string
	StatusCode int
}

func (e *WebConnectError) Error() string {
	return fmt.Sprintf("tunnel: %s cover CONNECT rejected with HTTP status %d", e.Transport, e.StatusCode)
}

var _ transport.Dialer = (*WebH3Client)(nil)
