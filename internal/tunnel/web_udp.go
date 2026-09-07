package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http/httpguts"
)

const (
	webConnectUDPProtocol    = "connect-udp"
	webConnectUDPPathPrefix  = "/.well-known/masque/udp/"
	webCapsuleProtocolHeader = "Capsule-Protocol"
	webCapsuleProtocolValue  = "?1"
	webConnectUDPContextID   = uint64(0)
	webDatagramShutdownGrace = time.Second
	// 1,150 bytes fits the mandatory 1,200-byte QUIC path even after the
	// conservative short-header estimate, DATAGRAM framing, the worst-case
	// eight-byte HTTP quarter-stream ID, and Context ID 0. Advertising the
	// larger logical UDP limit would make a valid SOCKS datagram fail only at
	// SendDatagram on minimum-MTU paths.
	webConnectUDPMaxPayloadSize = 1150
)

type webH3ConnectionContextKey struct{}

// connectUDPPath expands the default RFC 9298 URI template:
//
//	/.well-known/masque/udp/{target_host}/{target_port}/
//
// URI-template simple string expansion percent-encodes every byte outside the
// RFC 3986 unreserved set. In particular, an IPv6 address is emitted as
// "2001%3Adb8%3A%3A1", without URI authority brackets.
func connectUDPPath(address string) (path, canonicalAddress string, err error) {
	canonicalAddress, host, port, err := normalizeConnectUDPTarget(address)
	if err != nil {
		return "", "", err
	}
	return webConnectUDPPathPrefix + escapeURITemplateValue(host) + "/" + port + "/", canonicalAddress, nil
}

func parseConnectUDPPath(escapedPath string) (string, error) {
	if !strings.HasPrefix(escapedPath, webConnectUDPPathPrefix) || !strings.HasSuffix(escapedPath, "/") {
		return "", protocol.ErrBadAddress
	}
	remainder := strings.TrimSuffix(strings.TrimPrefix(escapedPath, webConnectUDPPathPrefix), "/")
	hostPart, portPart, ok := strings.Cut(remainder, "/")
	if !ok || hostPart == "" || portPart == "" || strings.Contains(portPart, "/") {
		return "", protocol.ErrBadAddress
	}
	host, err := url.PathUnescape(hostPart)
	if err != nil || host == "" || strings.Contains(host, "/") {
		return "", protocol.ErrBadAddress
	}
	port, err := url.PathUnescape(portPart)
	if err != nil || port == "" || strings.Contains(port, "/") {
		return "", protocol.ErrBadAddress
	}
	canonical, _, _, err := normalizeConnectUDPTarget(net.JoinHostPort(host, port))
	return canonical, err
}

func normalizeConnectUDPTarget(address string) (canonical, host, port string, err error) {
	if len(address) == 0 || len(address) > protocol.MaxAddressLength {
		return "", "", "", protocol.ErrBadAddress
	}
	authority, err := httpguts.PunycodeHostPort(address)
	if err != nil || !httpguts.ValidHostHeader(authority) {
		return "", "", "", protocol.ErrBadAddress
	}
	host, port, err = net.SplitHostPort(authority)
	if err != nil || host == "" || port == "" {
		return "", "", "", protocol.ErrBadAddress
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", "", "", protocol.ErrBadAddress
	}
	port = strconv.FormatUint(portNumber, 10)
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		// Zone identifiers are link-local interface state, not an interoperable
		// MASQUE target_host value. They are also unsafe to reinterpret on the
		// relay, where interface names have unrelated meaning.
		if ip.Zone() != "" {
			return "", "", "", protocol.ErrBadAddress
		}
		host = ip.Unmap().String()
	} else {
		if strings.Contains(host, ":") {
			return "", "", "", protocol.ErrBadAddress
		}
		host = strings.ToLower(host)
	}
	canonical = net.JoinHostPort(host, port)
	if len(canonical) > protocol.MaxAddressLength {
		return "", "", "", protocol.ErrBadAddress
	}
	return canonical, host, port, nil
}

func escapeURITemplateValue(value string) string {
	var escaped strings.Builder
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || strings.ContainsRune("-._~", rune(char)) {
			escaped.WriteByte(char)
			continue
		}
		const hex = "0123456789ABCDEF"
		escaped.WriteByte('%')
		escaped.WriteByte(hex[char>>4])
		escaped.WriteByte(hex[char&0xf])
	}
	return escaped.String()
}

func webConnectUDPRequestPath(request *http.Request) string {
	if request == nil || request.URL == nil {
		return ""
	}
	path := request.URL.EscapedPath()
	if request.URL.ForceQuery || request.URL.RawQuery != "" {
		path += "?" + request.URL.RawQuery
	}
	return path
}

func isWebConnectUDPRequest(request *http.Request, wire string) bool {
	return request != nil && wire == webAuthTransportH3 && request.Method == http.MethodConnect && request.Proto == webConnectUDPProtocol
}

// serveConnectUDP authenticates the complete raw request binding before it
// parses the MASQUE path or invokes the policy-enforcing resolver. Invalid
// credentials therefore have exactly the configured cover behavior and cannot
// use target parsing or DNS as an oracle.
func (h *webTunnelHandler) serveConnectUDP(writer http.ResponseWriter, request *http.Request) {
	binding := webAuthBinding{
		transport: webAuthTransportH3,
		method:    http.MethodConnect,
		protocol:  webConnectUDPProtocol,
		authority: request.Host,
		path:      webConnectUDPRequestPath(request),
	}
	authentication, ok := h.authenticateWebRequest(request, binding)
	if !ok {
		h.serveAuthenticationMiss(writer, request)
		return
	}
	defer authentication.closeIncompleteBootstrap()

	if request.URL == nil || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.Header.Get(webCapsuleProtocolHeader) != webCapsuleProtocolValue {
		h.writeAuthenticatedError(writer, &authentication, http.StatusBadRequest)
		return
	}
	target, err := parseConnectUDPPath(request.URL.EscapedPath())
	if err != nil {
		h.writeAuthenticatedError(writer, &authentication, http.StatusBadRequest)
		return
	}
	if h.udp == nil {
		h.writeAuthenticatedError(writer, &authentication, http.StatusServiceUnavailable)
		return
	}
	streamer, streamOK := writer.(http3.HTTPStreamer)
	settingser, settingsOK := writer.(http3.Settingser)
	if !streamOK || !settingsOK {
		h.writeAuthenticatedError(writer, &authentication, http.StatusBadRequest)
		return
	}
	select {
	case <-settingser.ReceivedSettings():
		settings := settingser.Settings()
		if settings == nil || !settings.EnableDatagrams {
			h.writeAuthenticatedError(writer, &authentication, http.StatusBadRequest)
			return
		}
	case <-request.Context().Done():
		return
	}

	// The shared stream budget and the UDP-specific global/per-source budget
	// are both acquired only after authentication and target parsing.
	if !h.core.acquire() {
		h.writeAuthenticatedError(writer, &authentication, http.StatusServiceUnavailable)
		return
	}
	defer h.core.release()
	remote, _ := request.Context().Value(http3.RemoteAddrContextKey).(net.Addr)
	sourceKey := tlsSourceKey(remote)
	if !h.udp.acquire(sourceKey) {
		h.writeAuthenticatedError(writer, &authentication, http.StatusServiceUnavailable)
		return
	}
	defer h.udp.release(sourceKey)

	resolveContext, cancelResolve := context.WithTimeout(request.Context(), h.udp.config.resolveTimeout)
	destinations, err := resolveUDPDestinations(resolveContext, h.udp.config.resolver, target)
	cancelResolve()
	if err != nil || len(destinations) > h.udp.config.maxDestinations {
		h.writeAuthenticatedError(writer, &authentication, http.StatusBadGateway)
		return
	}
	socket, destination, err := dialResolvedUDPTarget(destinations)
	if err != nil {
		h.writeAuthenticatedError(writer, &authentication, http.StatusBadGateway)
		return
	}
	defer socket.Close()

	proof, ok := h.authenticatedResponseProof(&authentication, http.StatusOK)
	if !ok {
		abortWebAuthenticatedResponse(&authentication)
		return
	}
	writer.Header().Set(webCapsuleProtocolHeader, webCapsuleProtocolValue)
	writer.Header().Set(webAuthResponseHeader, proof)
	writer.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream()
	connection, _ := request.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn)
	session := newWebUDPServerSession(request.Context(), connection, stream, socket, destination, h.udp.config.receiveQueue)
	session.run()
}

func dialResolvedUDPTarget(destinations []netip.AddrPort) (*net.UDPConn, netip.AddrPort, error) {
	var combined error
	for _, destination := range destinations {
		network := "udp6"
		if destination.Addr().Is4() {
			network = "udp4"
		}
		socket, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(destination))
		if err == nil {
			return socket, destination, nil
		}
		combined = errors.Join(combined, err)
	}
	if combined == nil {
		combined = errors.New("no resolved UDP destinations")
	}
	return nil, netip.AddrPort{}, combined
}

type webUDPServerSession struct {
	connection  *quic.Conn
	stream      *http3.Stream
	socket      *net.UDPConn
	destination netip.AddrPort
	requests    chan []byte
	responses   chan []byte

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	senderDone chan struct{}
}

func newWebUDPServerSession(parent context.Context, connection *quic.Conn, stream *http3.Stream, socket *net.UDPConn, destination netip.AddrPort, queue int) *webUDPServerSession {
	ctx, cancel := context.WithCancel(parent)
	return &webUDPServerSession{
		connection:  connection,
		stream:      stream,
		socket:      socket,
		destination: destination,
		requests:    make(chan []byte, queue),
		responses:   make(chan []byte, queue),
		ctx:         ctx,
		cancel:      cancel,
		senderDone:  make(chan struct{}),
	}
}

func (s *webUDPServerSession) run() {
	s.wg.Add(5)
	go s.receiveHTTPDatagrams()
	go s.forwardRequests()
	go s.receiveUDPResponses()
	go s.sendHTTPDatagrams()
	go s.drainCapsules()

	<-s.ctx.Done()
	s.cancel()
	_ = s.socket.Close()
	// The request direction carries only optional Capsules. STOP_SENDING is
	// needed when another terminal path (socket, datagram, or server context)
	// wins, so the drain goroutine cannot leak.
	s.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	s.unblockDatagramSender()
	s.wg.Wait()
	_ = s.stream.Close()
}

func (s *webUDPServerSession) receiveHTTPDatagrams() {
	defer s.wg.Done()
	defer s.cancel()
	for {
		frame, err := s.stream.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		payload, ok := parseConnectUDPDatagram(frame)
		if !ok || len(payload) > webConnectUDPMaxPayloadSize {
			continue
		}
		payload = append([]byte(nil), payload...)
		select {
		case s.requests <- payload:
		case <-s.ctx.Done():
			return
		default:
			// HTTP Datagrams are unreliable. A full bounded queue drops the
			// newest packet without stalling unrelated streams.
		}
	}
}

func (s *webUDPServerSession) forwardRequests() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case payload := <-s.requests:
			_, _ = s.socket.Write(payload)
		}
	}
}

func (s *webUDPServerSession) receiveUDPResponses() {
	defer s.wg.Done()
	defer s.cancel()
	buffer := make([]byte, webConnectUDPMaxPayloadSize+1)
	for {
		count, err := s.socket.Read(buffer)
		if err != nil {
			return
		}
		if count > webConnectUDPMaxPayloadSize {
			continue
		}
		payload := append([]byte(nil), buffer[:count]...)
		select {
		case s.responses <- payload:
		case <-s.ctx.Done():
			return
		default:
		}
	}
}

func (s *webUDPServerSession) sendHTTPDatagrams() {
	defer s.wg.Done()
	defer close(s.senderDone)
	defer s.cancel()
	for {
		select {
		case <-s.ctx.Done():
			return
		case payload := <-s.responses:
			if err := s.stream.SendDatagram(encodeConnectUDPDatagram(payload)); err != nil {
				return
			}
		}
	}
}

func (s *webUDPServerSession) unblockDatagramSender() {
	select {
	case <-s.senderDone:
		return
	case <-time.After(webDatagramShutdownGrace):
	}
	// quic-go's connection-wide DATAGRAM queue can block SendDatagram and a
	// stream reset cannot wake it. Closing the shared connection is the bounded
	// fail-safe used only after the session has already been canceled.
	if s.connection != nil {
		_ = s.connection.CloseWithError(quic.ApplicationErrorCode(applicationShutdown), "blocked CONNECT-UDP sender")
	}
	<-s.senderDone
}

func (s *webUDPServerSession) drainCapsules() {
	defer s.wg.Done()
	defer s.cancel()
	_, _ = io.Copy(io.Discard, s.stream)
}

func encodeConnectUDPDatagram(payload []byte) []byte {
	result := make([]byte, 0, quicvarint.Len(webConnectUDPContextID)+len(payload))
	result = quicvarint.Append(result, webConnectUDPContextID)
	return append(result, payload...)
}

func parseConnectUDPDatagram(frame []byte) ([]byte, bool) {
	contextID, consumed, err := quicvarint.Parse(frame)
	if err != nil || contextID != webConnectUDPContextID {
		return nil, false
	}
	return frame[consumed:], true
}

type webUDPPendingSession struct {
	done    chan struct{}
	session *webUDPClientSession
	err     error
}

// webUDPPacketConn presents the existing multi-target PacketConn API while
// using the RFC 9298 one-target-per-request-stream model on the wire. Target
// streams are opened lazily, bounded per PacketConn and globally per client,
// and reused for later datagrams to the same canonical target.
type webUDPPacketConn struct {
	client     *WebH3Client
	maxTargets int
	receive    chan packetResult

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	closed   bool
	sessions map[string]*webUDPClientSession
	pending  map[string]*webUDPPendingSession
	once     sync.Once
}

func newWebUDPPacketConn(client *WebH3Client) *webUDPPacketConn {
	ctx, cancel := context.WithCancel(client.ctx)
	packet := &webUDPPacketConn{
		client:     client,
		maxTargets: client.udpMaxTargets,
		receive:    make(chan packetResult, client.udpReceiveQueue),
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
		sessions:   make(map[string]*webUDPClientSession),
		pending:    make(map[string]*webUDPPendingSession),
	}
	go func() {
		<-ctx.Done()
		packet.shutdown()
	}()
	return packet
}

func (p *webUDPPacketConn) Send(payload []byte, address string) error {
	if len(payload) > webConnectUDPMaxPayloadSize {
		return fmt.Errorf("tunnel: CONNECT-UDP payload exceeds %d bytes", webConnectUDPMaxPayloadSize)
	}
	_, canonical, err := connectUDPPath(address)
	if err != nil {
		return err
	}
	session, err := p.session(canonical)
	if err != nil {
		return err
	}
	return session.send(payload)
}

func (p *webUDPPacketConn) session(target string) (*webUDPClientSession, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if session := p.sessions[target]; session != nil {
			p.mu.Unlock()
			return session, nil
		}
		if pending := p.pending[target]; pending != nil {
			p.mu.Unlock()
			select {
			case <-pending.done:
				if pending.err != nil {
					return nil, pending.err
				}
				return pending.session, nil
			case <-p.done:
				return nil, net.ErrClosed
			}
		}
		if len(p.sessions)+len(p.pending) >= p.maxTargets {
			p.mu.Unlock()
			return nil, ErrUDPDestinationCapacity
		}
		pending := &webUDPPendingSession{done: make(chan struct{})}
		p.pending[target] = pending
		p.mu.Unlock()

		session, err := p.openSession(target)
		openedSession := session
		terminate := false
		p.mu.Lock()
		delete(p.pending, target)
		if p.closed && session != nil {
			terminate = true
			session = nil
			err = net.ErrClosed
		} else if err == nil {
			p.sessions[target] = session
			// Start while holding p.mu so Close can never observe an inserted
			// session before its WaitGroup has been initialized. A terminal
			// goroutine may block briefly in removeSession until this unlocks.
			session.start()
		}
		pending.session = session
		pending.err = err
		close(pending.done)
		p.mu.Unlock()
		if terminate {
			openedSession.terminate()
		}
		if err != nil {
			return nil, err
		}
		return session, nil
	}
}

func (p *webUDPPacketConn) openSession(target string) (*webUDPClientSession, error) {
	if err := p.client.reserveWebUDPSession(p.ctx); err != nil {
		return nil, err
	}
	reserved := true
	defer func() {
		if reserved {
			p.client.releaseWebUDPSession()
		}
	}()

	openTimeout := p.client.dialTimeout + p.client.handshakeTimeout
	if openTimeout <= 0 || openTimeout < p.client.dialTimeout {
		openTimeout = p.client.handshakeTimeout
	}
	openContext, cancelOpen := context.WithTimeout(p.ctx, openTimeout)
	defer cancelOpen()
	opened, err := p.client.openConnectUDPSession(openContext, target)
	if err != nil {
		return nil, err
	}
	sessionContext, cancelSession := context.WithCancel(p.ctx)
	session := &webUDPClientSession{
		packet:     p,
		target:     target,
		connection: opened.connection,
		stream:     opened.stream,
		outbound:   make(chan []byte, p.client.udpReceiveQueue),
		ctx:        sessionContext,
		cancel:     cancelSession,
		done:       make(chan struct{}),
		senderDone: make(chan struct{}),
	}
	reserved = false
	return session, nil
}

func (p *webUDPPacketConn) Receive() ([]byte, string, error) {
	select {
	case <-p.done:
		return nil, "", net.ErrClosed
	default:
	}
	select {
	case <-p.done:
		return nil, "", net.ErrClosed
	case result := <-p.receive:
		select {
		case <-p.done:
			return nil, "", net.ErrClosed
		default:
			return result.payload, result.address, nil
		}
	}
}

func (p *webUDPPacketConn) deliver(target string, payload []byte) {
	result := packetResult{payload: append([]byte(nil), payload...), address: target}
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.receive <- result:
	case <-p.done:
	default:
	}
}

func (p *webUDPPacketConn) removeSession(target string, session *webUDPClientSession) {
	p.mu.Lock()
	if p.sessions[target] == session {
		delete(p.sessions, target)
	}
	p.mu.Unlock()
}

func (p *webUDPPacketConn) shutdown() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		close(p.done)
		sessions := make([]*webUDPClientSession, 0, len(p.sessions))
		for _, session := range p.sessions {
			sessions = append(sessions, session)
		}
		pending := make([]<-chan struct{}, 0, len(p.pending))
		for _, opening := range p.pending {
			pending = append(pending, opening.done)
		}
		p.mu.Unlock()

		for _, session := range sessions {
			session.closeAndWait()
		}
		for _, done := range pending {
			<-done
		}
	})
}

func (p *webUDPPacketConn) Close() error {
	p.shutdown()
	return nil
}

func (p *webUDPPacketConn) MaxPayloadSize() int { return webConnectUDPMaxPayloadSize }

type webUDPClientSession struct {
	packet     *webUDPPacketConn
	target     string
	connection *quic.Conn
	stream     *http3.RequestStream
	outbound   chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	senderDone chan struct{}
	once       sync.Once
	wg         sync.WaitGroup
}

func (s *webUDPClientSession) start() {
	s.wg.Add(4)
	go s.receiveDatagrams()
	go s.drainCapsules()
	go s.sendDatagrams()
	go s.watchDatagramSender()
}

func (s *webUDPClientSession) send(payload []byte) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	frame := encodeConnectUDPDatagram(append([]byte(nil), payload...))
	select {
	case <-s.done:
		return net.ErrClosed
	case s.outbound <- frame:
		return nil
	default:
		return transport.ErrPacketQueueFull
	}
}

func (s *webUDPClientSession) sendDatagrams() {
	defer s.wg.Done()
	defer close(s.senderDone)
	defer s.terminate()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case frame := <-s.outbound:
			if err := s.stream.SendDatagram(frame); err != nil {
				return
			}
		}
	}
}

func (s *webUDPClientSession) watchDatagramSender() {
	defer s.wg.Done()
	<-s.ctx.Done()
	select {
	case <-s.senderDone:
		return
	case <-time.After(webDatagramShutdownGrace):
	}
	if s.connection != nil {
		_ = s.connection.CloseWithError(quic.ApplicationErrorCode(applicationShutdown), "blocked CONNECT-UDP sender")
	}
	<-s.senderDone
}

func (s *webUDPClientSession) receiveDatagrams() {
	defer s.wg.Done()
	defer s.terminate()
	for {
		frame, err := s.stream.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		payload, ok := parseConnectUDPDatagram(frame)
		if !ok || len(payload) > webConnectUDPMaxPayloadSize {
			continue
		}
		s.packet.deliver(s.target, payload)
	}
}

func (s *webUDPClientSession) drainCapsules() {
	defer s.wg.Done()
	defer s.terminate()
	_, _ = io.Copy(io.Discard, s.stream)
}

func (s *webUDPClientSession) terminate() {
	s.once.Do(func() {
		s.cancel()
		s.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		s.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = s.stream.Close()
		s.packet.removeSession(s.target, s)
		s.packet.client.releaseWebUDPSession()
		close(s.done)
	})
}

func (s *webUDPClientSession) closeAndWait() {
	s.terminate()
	s.wg.Wait()
}

func (c *WebH3Client) reserveWebUDPSession(ctx context.Context) error {
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	case <-ctx.Done():
		return context.Cause(ctx)
	default:
	}
	select {
	case c.udpSlots <- struct{}{}:
		return nil
	case <-c.ctx.Done():
		return net.ErrClosed
	case <-ctx.Done():
		return context.Cause(ctx)
	default:
		return ErrUDPSessionCapacity
	}
}

func (c *WebH3Client) releaseWebUDPSession() { <-c.udpSlots }

type webConnectUDPStream struct {
	stream     *http3.RequestStream
	connection *quic.Conn
}

func (c *WebH3Client) openConnectUDPSession(ctx context.Context, target string) (*webConnectUDPStream, error) {
	path, canonicalTarget, err := connectUDPPath(target)
	if err != nil {
		return nil, err
	}
	binding := webAuthBinding{
		transport: webAuthTransportH3,
		method:    http.MethodConnect,
		protocol:  webConnectUDPProtocol,
		authority: c.originAuthority,
		path:      path,
	}
	reservation, err := c.reserveAuthenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	session := reservation.session
	conn, client := session.conn, session.client
	var (
		bearer     string
		authClaims webAuthClaims
		exchange   webSessionExchange
	)
	if reservation.bootstrap {
		bearer, authClaims, err = c.signer.authorization(binding, webAuthClaims{})
	} else {
		bearer, exchange, err = reservation.auth.authorization(ctx, binding)
		defer reservation.auth.complete(exchange)
	}
	if err != nil {
		if reservation.bootstrap || errors.Is(err, errWebSessionSequenceExhausted) {
			c.failSessionAuthentication(session)
		}
		return nil, err
	}
	if err := waitWebH3DatagramSettings(ctx, client); err != nil {
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		return nil, err
	}
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		if ctx.Err() == nil {
			c.retire(conn)
		}
		return nil, fmt.Errorf("tunnel: open CONNECT-UDP request stream: %w", err)
	}
	cancelStream := func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = stream.Close()
	}
	stopOpen := context.AfterFunc(ctx, cancelStream)
	fail := func() {
		stopOpen()
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

	requestURL, err := url.Parse("https://" + c.originAuthority + path)
	if err != nil {
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		return nil, protocol.ErrBadAddress
	}
	request := (&http.Request{
		Method: http.MethodConnect,
		URL:    requestURL,
		Host:   c.originAuthority,
		Proto:  webConnectUDPProtocol,
		Header: webConnectRequestHeaders(bearer),
	}).WithContext(ctx)
	request.Header.Set(webCapsuleProtocolHeader, webCapsuleProtocolValue)
	if err := stream.SendRequestHeader(request); err != nil {
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		return nil, fmt.Errorf("tunnel: send CONNECT-UDP request for %s: %w", canonicalTarget, err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		fail()
		if reservation.bootstrap {
			c.failSessionAuthentication(session)
		}
		if conn.Context().Err() != nil {
			c.retire(conn)
		}
		return nil, fmt.Errorf("tunnel: read CONNECT-UDP response: %w", err)
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
			return nil, errors.New("tunnel: CONNECT-UDP server authentication failed")
		}
	} else if !reservation.auth.verifyResponseProof(
		response.Header.Values(webAuthResponseHeader),
		binding,
		exchange,
		response.StatusCode,
	) {
		fail()
		c.failSessionAuthentication(session)
		return nil, errors.New("tunnel: CONNECT-UDP server authentication failed")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fail()
		return nil, &WebConnectError{Transport: webAuthTransportH3, StatusCode: response.StatusCode}
	}
	if response.Header.Get(webCapsuleProtocolHeader) != webCapsuleProtocolValue {
		fail()
		return nil, errors.New("tunnel: CONNECT-UDP response did not negotiate the Capsule Protocol")
	}
	if !stopOpen() && ctx.Err() != nil {
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
	return &webConnectUDPStream{stream: stream, connection: conn}, nil
}

func waitWebH3DatagramSettings(ctx context.Context, client *http3.ClientConn) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	select {
	case <-client.ReceivedSettings():
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		settings := client.Settings()
		if settings == nil || !settings.EnableExtendedConnect {
			return errors.New("tunnel: web-cover H3 server did not enable Extended CONNECT")
		}
		if !settings.EnableDatagrams {
			return errors.New("tunnel: web-cover H3 server did not enable HTTP Datagrams")
		}
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-client.Context().Done():
		return fmt.Errorf("tunnel: web-cover H3 connection closed before SETTINGS: %w", context.Cause(client.Context()))
	}
}

// DialPacket opens an RFC 9298-capable logical PacketConn. Individual
// CONNECT-UDP request streams are created lazily by Send, one per target.
func (c *WebH3Client) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil CONNECT-UDP dial context")
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	_, client, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	settingsContext, cancelSettings := context.WithTimeout(ctx, c.handshakeTimeout)
	err = waitWebH3DatagramSettings(settingsContext, client)
	cancelSettings()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, context.Cause(ctx)
	}
	packet := newWebUDPPacketConn(c)
	c.mu.Unlock()
	return packet, nil
}

var _ transport.PacketDialer = (*WebH3Client)(nil)
var _ transport.PacketConn = (*webUDPPacketConn)(nil)
var _ transport.PacketPayloadSizer = (*webUDPPacketConn)(nil)
