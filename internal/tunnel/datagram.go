package tunnel

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	autodatagram "github.com/cppla/autocar/internal/datagram"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	quic "github.com/quic-go/quic-go"
)

const (
	defaultUDPFrameSize          = 1200
	defaultMaxUDPSessions        = 256
	defaultMaxClientUDPSessions  = 32
	defaultClientMaxUDPSessions  = 64
	defaultMaxUDPDestinations    = 64
	defaultUDPReceiveQueue       = 32
	defaultUDPReassemblyTTL      = 5 * time.Second
	defaultUDPReassemblyMessages = 64
	defaultUDPReassemblyBytes    = 256 << 10
)

var (
	ErrUDPSessionCapacity     = errors.New("tunnel: UDP session capacity exhausted")
	ErrUDPDestinationCapacity = errors.New("tunnel: UDP destination capacity exhausted")
	ErrUDPQueueFull           = transport.ErrPacketQueueFull
)

// UDPResolver resolves a requested host:port into frozen numeric endpoints.
// SafeDialer satisfies this interface, so its destination policy and DNS
// rebinding protection are automatically retained by the QUIC UDP relay.
type UDPResolver interface {
	ResolveUDPContext(context.Context, string) ([]netip.AddrPort, error)
}

// UDPResolverFunc adapts a function to UDPResolver.
type UDPResolverFunc func(context.Context, string) ([]netip.AddrPort, error)

func (f UDPResolverFunc) ResolveUDPContext(ctx context.Context, address string) ([]netip.AddrPort, error) {
	return f(ctx, address)
}

type serverUDPConfig struct {
	resolver           UDPResolver
	resolveTimeout     time.Duration
	maxDestinations    int
	receiveQueue       int
	reassemblyTTL      time.Duration
	reassemblyMessages int
	reassemblyBytes    int
}

type clientUDPConfig struct {
	maxSessions        int
	receiveQueue       int
	reassemblyTTL      time.Duration
	reassemblyMessages int
	reassemblyBytes    int
}

type serverUDPManager struct {
	config  serverUDPConfig
	slots   chan struct{}
	clients *sourceConnectionLimiter
}

func newServerUDPManager(config QUICServerConfig, dialer transport.Dialer, resolveTimeout time.Duration) (*serverUDPManager, error) {
	maxSessions, err := normalizedUDPCount(config.MaxUDPSessions, defaultMaxUDPSessions, "maximum UDP sessions")
	if err != nil {
		return nil, err
	}
	maxClientSessions, err := normalizedUDPCount(config.MaxClientUDPSessions, min(defaultMaxClientUDPSessions, maxSessions), "maximum client UDP sessions")
	if err != nil {
		return nil, err
	}
	if maxClientSessions > maxSessions {
		return nil, fmt.Errorf("tunnel: maximum client UDP sessions (%d) exceeds maximum UDP sessions (%d)", maxClientSessions, maxSessions)
	}
	maxDestinations, err := normalizedUDPCount(config.MaxUDPDestinations, defaultMaxUDPDestinations, "maximum UDP destinations")
	if err != nil {
		return nil, err
	}
	receiveQueue, err := normalizedUDPCount(config.UDPReceiveQueue, defaultUDPReceiveQueue, "UDP receive queue")
	if err != nil {
		return nil, err
	}
	reassemblyMessages, err := normalizedUDPCount(config.MaxUDPReassemblyMessages, defaultUDPReassemblyMessages, "maximum UDP reassembly messages")
	if err != nil {
		return nil, err
	}
	reassemblyBytes, err := normalizedUDPCount(config.MaxUDPReassemblyBytes, defaultUDPReassemblyBytes, "maximum UDP reassembly bytes")
	if err != nil {
		return nil, err
	}
	reassemblyTTL, err := normalizedUDPDuration(config.UDPReassemblyTTL, defaultUDPReassemblyTTL, "UDP reassembly TTL")
	if err != nil {
		return nil, err
	}
	resolver := config.UDPResolver
	if resolver == nil {
		if candidate, ok := dialer.(UDPResolver); ok {
			resolver = candidate
		} else {
			resolver = systemUDPResolver{}
		}
	}
	if resolveTimeout <= 0 {
		resolveTimeout = defaultDialTimeout
	}
	return &serverUDPManager{
		config: serverUDPConfig{
			resolver:           resolver,
			resolveTimeout:     resolveTimeout,
			maxDestinations:    maxDestinations,
			receiveQueue:       receiveQueue,
			reassemblyTTL:      reassemblyTTL,
			reassemblyMessages: reassemblyMessages,
			reassemblyBytes:    reassemblyBytes,
		},
		slots:   make(chan struct{}, maxSessions),
		clients: newSourceConnectionLimiter(maxClientSessions),
	}, nil
}

func normalizeClientUDPConfig(config ClientConfig) (clientUDPConfig, error) {
	maxSessions, err := normalizedUDPCount(config.MaxUDPSessions, defaultClientMaxUDPSessions, "maximum UDP sessions")
	if err != nil {
		return clientUDPConfig{}, err
	}
	receiveQueue, err := normalizedUDPCount(config.UDPReceiveQueue, defaultUDPReceiveQueue, "UDP receive queue")
	if err != nil {
		return clientUDPConfig{}, err
	}
	reassemblyMessages, err := normalizedUDPCount(config.MaxUDPReassemblyMessages, defaultUDPReassemblyMessages, "maximum UDP reassembly messages")
	if err != nil {
		return clientUDPConfig{}, err
	}
	reassemblyBytes, err := normalizedUDPCount(config.MaxUDPReassemblyBytes, defaultUDPReassemblyBytes, "maximum UDP reassembly bytes")
	if err != nil {
		return clientUDPConfig{}, err
	}
	reassemblyTTL, err := normalizedUDPDuration(config.UDPReassemblyTTL, defaultUDPReassemblyTTL, "UDP reassembly TTL")
	if err != nil {
		return clientUDPConfig{}, err
	}
	return clientUDPConfig{
		maxSessions:        maxSessions,
		receiveQueue:       receiveQueue,
		reassemblyTTL:      reassemblyTTL,
		reassemblyMessages: reassemblyMessages,
		reassemblyBytes:    reassemblyBytes,
	}, nil
}

func normalizedUDPCount(value, defaultValue int, name string) (int, error) {
	if value < 0 {
		return 0, fmt.Errorf("tunnel: %s cannot be negative", name)
	}
	if value == 0 {
		return defaultValue, nil
	}
	return value, nil
}

func normalizedUDPDuration(value, defaultValue time.Duration, name string) (time.Duration, error) {
	if value < 0 {
		return 0, fmt.Errorf("tunnel: %s cannot be negative", name)
	}
	if value == 0 {
		return defaultValue, nil
	}
	return value, nil
}

func (m *serverUDPManager) acquire(sourceKey string) bool {
	select {
	case m.slots <- struct{}{}:
	default:
		return false
	}
	if !m.clients.acquire(sourceKey) {
		<-m.slots
		return false
	}
	return true
}

func (m *serverUDPManager) release(sourceKey string) {
	m.clients.release(sourceKey)
	<-m.slots
}

type serverDatagramDispatcher struct {
	conn      *quic.Conn
	manager   *serverUDPManager
	sourceKey string
	pacer     *connectionPacer

	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	sendDone chan struct{}
	once     sync.Once

	reassembler *autodatagram.Reassembler
	outbound    chan queuedDatagram
	mu          sync.RWMutex
	sessions    map[uint32]*serverUDPSession
	nextSession uint32
}

func newServerDatagramDispatcher(conn *quic.Conn, manager *serverUDPManager, sourceKey string, pacer *connectionPacer) (*serverDatagramDispatcher, error) {
	reassembler, err := autodatagram.NewReassembler(autodatagram.ReassemblerConfig{
		MaxMessages:      manager.config.reassemblyMessages,
		MaxBufferedBytes: manager.config.reassemblyBytes,
		TTL:              manager.config.reassemblyTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("tunnel: configure server UDP reassembly: %w", err)
	}
	seed, err := randomNonZeroUint32()
	if err != nil {
		return nil, fmt.Errorf("tunnel: seed server UDP session IDs: %w", err)
	}
	ctx, cancel := context.WithCancel(conn.Context())
	dispatcher := &serverDatagramDispatcher{
		conn:        conn,
		manager:     manager,
		sourceKey:   sourceKey,
		pacer:       pacer,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
		sendDone:    make(chan struct{}),
		reassembler: reassembler,
		outbound:    make(chan queuedDatagram, manager.config.receiveQueue),
		sessions:    make(map[uint32]*serverUDPSession),
		nextSession: seed,
	}
	go dispatcher.sendLoop()
	go dispatcher.receiveLoop()
	return dispatcher, nil
}

func (d *serverDatagramDispatcher) receiveLoop() {
	defer close(d.done)
	defer d.shutdown()
	for {
		frame, err := d.conn.ReceiveDatagram(d.ctx)
		if err != nil {
			return
		}
		fragment, err := autodatagram.Parse(frame)
		if err != nil || fragment.Flags&autodatagram.FlagResponse != 0 {
			continue
		}
		d.mu.RLock()
		session := d.sessions[fragment.SessionID]
		if session == nil {
			d.mu.RUnlock()
			continue
		}
		message, complete, err := d.reassembler.Add(fragment)
		if err == nil && complete {
			session.enqueue(message)
		}
		d.mu.RUnlock()
	}
}

func (d *serverDatagramDispatcher) handleRequest(ctx context.Context, stream deadlineConn, request protocol.Request, response protocol.Response) streamRequestOptions {
	if request.Network != protocol.NetworkUDP {
		return streamRequestOptions{Relay: stream}
	}
	if !d.manager.acquire(d.sourceKey) {
		_ = protocol.WriteResponse(stream, protocol.Response{Status: protocol.StatusBusy, Message: "UDP session limit reached"})
		return streamRequestOptions{Handled: true}
	}

	socket, err := net.ListenUDP("udp", nil)
	if err != nil {
		d.manager.release(d.sourceKey)
		_ = protocol.WriteResponse(stream, protocol.Response{Status: protocol.StatusInternal, Message: "UDP session unavailable"})
		return streamRequestOptions{Handled: true}
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &serverUDPSession{
		dispatcher: d,
		manager:    d.manager,
		sourceKey:  d.sourceKey,
		conn:       socket,
		ctx:        sessionCtx,
		cancel:     cancel,
		requests:   make(chan autodatagram.Message, d.manager.config.receiveQueue),
		allowed:    make(map[netip.AddrPort]struct{}),
	}
	sessionID, err := d.register(session)
	if err != nil {
		_ = socket.Close()
		cancel()
		d.manager.release(d.sourceKey)
		_ = protocol.WriteResponse(stream, protocol.Response{Status: protocol.StatusBusy, Message: "UDP dispatcher unavailable"})
		return streamRequestOptions{Handled: true}
	}
	session.start()
	response.SessionID = sessionID
	if err := protocol.WriteResponse(stream, response); err != nil {
		_ = session.Close()
		return streamRequestOptions{Handled: true}
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		_ = session.Close()
		return streamRequestOptions{Handled: true}
	}

	// The authenticated stream is the association lease. The client sends no
	// body; FIN, RESET or connection closure tears down the socket and releases
	// every session resource.
	var unexpected [1]byte
	_, _ = stream.Read(unexpected[:])
	_ = session.Close()
	return streamRequestOptions{Handled: true}
}

func (d *serverDatagramDispatcher) register(session *serverUDPSession) (uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	for {
		d.nextSession++
		if d.nextSession == 0 {
			continue
		}
		if _, exists := d.sessions[d.nextSession]; exists {
			continue
		}
		session.id = d.nextSession
		d.sessions[session.id] = session
		return session.id, nil
	}
}

func (d *serverDatagramDispatcher) unregister(id uint32, session *serverUDPSession) {
	d.mu.Lock()
	if d.sessions[id] == session {
		delete(d.sessions, id)
		d.reassembler.DiscardSession(id)
	}
	d.mu.Unlock()
}

func (d *serverDatagramDispatcher) send(ctx context.Context, message autodatagram.Message) error {
	select {
	case <-d.ctx.Done():
		return net.ErrClosed
	default:
	}
	queued, err := prepareQueuedDatagram(ctx, message)
	if err != nil {
		return err
	}
	select {
	case d.outbound <- queued:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-d.ctx.Done():
		return net.ErrClosed
	default:
		return ErrUDPQueueFull
	}
}

func (d *serverDatagramDispatcher) sendLoop() {
	defer close(d.sendDone)
	for {
		select {
		case <-d.ctx.Done():
			return
		case queued := <-d.outbound:
			if queued.ctx.Err() == nil {
				_ = sendQUICDatagram(d.conn, d.pacer, queued)
			}
		}
	}
}

func (d *serverDatagramDispatcher) shutdown() {
	d.once.Do(func() {
		d.cancel()
		d.mu.RLock()
		sessions := make([]*serverUDPSession, 0, len(d.sessions))
		for _, session := range d.sessions {
			sessions = append(sessions, session)
		}
		d.mu.RUnlock()
		for _, session := range sessions {
			_ = session.Close()
		}
	})
}

func (d *serverDatagramDispatcher) Close() {
	d.shutdown()
	<-d.done
	<-d.sendDone
}

type serverUDPSession struct {
	id         uint32
	dispatcher *serverDatagramDispatcher
	manager    *serverUDPManager
	sourceKey  string
	conn       *net.UDPConn
	ctx        context.Context
	cancel     context.CancelFunc
	requests   chan autodatagram.Message

	allowedMu sync.RWMutex
	allowed   map[netip.AddrPort]struct{}
	nextID    atomic.Uint32
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func (s *serverUDPSession) start() {
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.forwardRequests()
	}()
	go func() {
		defer s.wg.Done()
		s.forwardResponses()
	}()
}

func (s *serverUDPSession) enqueue(message autodatagram.Message) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}
	select {
	case s.requests <- message:
	case <-s.ctx.Done():
	default:
		// QUIC DATAGRAM is intentionally unreliable. Dropping one overloaded
		// session must not block the connection-wide receive dispatcher.
	}
}

func (s *serverUDPSession) forwardRequests() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case message := <-s.requests:
			s.forwardRequest(message)
		}
	}
}

func (s *serverUDPSession) forwardRequest(message autodatagram.Message) {
	ctx, cancel := context.WithTimeout(s.ctx, s.manager.config.resolveTimeout)
	destinations, err := resolveUDPDestinations(ctx, s.manager.config.resolver, message.Address)
	cancel()
	if err != nil {
		return
	}
	for _, destination := range destinations {
		if _, err := s.writeToDestination(message.Payload, destination); err == nil {
			return
		}
	}
}

func (s *serverUDPSession) writeToDestination(payload []byte, destination netip.AddrPort) (int, error) {
	if s.destinationAllowed(destination) {
		return s.conn.WriteToUDPAddrPort(payload, destination)
	}

	// Keep the admission lock across the first write. A fast response then
	// waits until the exact source endpoint is authorized instead of being
	// misclassified as unsolicited in the write/record interval.
	s.allowedMu.Lock()
	defer s.allowedMu.Unlock()
	if _, ok := s.allowed[destination]; ok {
		return s.conn.WriteToUDPAddrPort(payload, destination)
	}
	if len(s.allowed) >= s.manager.config.maxDestinations {
		return 0, ErrUDPDestinationCapacity
	}
	n, err := s.conn.WriteToUDPAddrPort(payload, destination)
	if err != nil {
		return n, err
	}
	s.allowed[destination] = struct{}{}
	return n, nil
}

func (s *serverUDPSession) destinationAllowed(destination netip.AddrPort) bool {
	s.allowedMu.RLock()
	_, ok := s.allowed[destination]
	s.allowedMu.RUnlock()
	return ok
}

func (s *serverUDPSession) forwardResponses() {
	buffer := make([]byte, autodatagram.MaxPayloadSize+1)
	for {
		n, source, err := s.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		if n > autodatagram.MaxPayloadSize {
			continue
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		if !s.destinationAllowed(source) {
			continue
		}
		messageID := s.nextID.Add(1) - 1
		_ = s.dispatcher.send(s.ctx, autodatagram.Message{
			Flags:     autodatagram.FlagResponse,
			SessionID: s.id,
			MessageID: messageID,
			Address:   source.String(),
			Payload:   buffer[:n],
		})
	}
}

func (s *serverUDPSession) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.closeErr = s.conn.Close()
		s.wg.Wait()
		s.dispatcher.unregister(s.id, s)
		s.manager.release(s.sourceKey)
	})
	return s.closeErr
}

type clientDatagramDispatcher struct {
	conn   *quic.Conn
	config clientUDPConfig
	pacer  *connectionPacer

	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	sendDone chan struct{}
	once     sync.Once
	onDone   func()

	reassembler *autodatagram.Reassembler
	outbound    chan queuedDatagram
	mu          sync.RWMutex
	sessions    map[uint32]*quicPacketConn
	pending     int
}

func newClientDatagramDispatcher(conn *quic.Conn, config clientUDPConfig, pacer *connectionPacer) (*clientDatagramDispatcher, error) {
	reassembler, err := autodatagram.NewReassembler(autodatagram.ReassemblerConfig{
		MaxMessages:      config.reassemblyMessages,
		MaxBufferedBytes: config.reassemblyBytes,
		TTL:              config.reassemblyTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("tunnel: configure client UDP reassembly: %w", err)
	}
	ctx, cancel := context.WithCancel(conn.Context())
	return &clientDatagramDispatcher{
		conn:        conn,
		config:      config,
		pacer:       pacer,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
		sendDone:    make(chan struct{}),
		reassembler: reassembler,
		outbound:    make(chan queuedDatagram, config.receiveQueue),
		sessions:    make(map[uint32]*quicPacketConn),
	}, nil
}

func (d *clientDatagramDispatcher) start() {
	go d.sendLoop()
	go d.receiveLoop()
}

func (d *clientDatagramDispatcher) receiveLoop() {
	defer func() {
		d.shutdown()
		if d.onDone != nil {
			d.onDone()
		}
		close(d.done)
	}()
	for {
		frame, err := d.conn.ReceiveDatagram(d.ctx)
		if err != nil {
			return
		}
		fragment, err := autodatagram.Parse(frame)
		if err != nil || fragment.Flags&autodatagram.FlagResponse == 0 {
			continue
		}
		d.mu.RLock()
		session := d.sessions[fragment.SessionID]
		if session == nil {
			d.mu.RUnlock()
			continue
		}
		message, complete, err := d.reassembler.Add(fragment)
		if err == nil && complete {
			session.deliver(packetResult{payload: message.Payload, address: message.Address})
		}
		d.mu.RUnlock()
	}
}

func (d *clientDatagramDispatcher) reserveSession() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.ctx.Done():
		return net.ErrClosed
	default:
	}
	if len(d.sessions)+d.pending >= d.config.maxSessions {
		return ErrUDPSessionCapacity
	}
	d.pending++
	return nil
}

func (d *clientDatagramDispatcher) releaseReservation() {
	d.mu.Lock()
	if d.pending > 0 {
		d.pending--
	}
	d.mu.Unlock()
}

func (d *clientDatagramDispatcher) registerAssigned(session *quicPacketConn, id uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == 0 {
		return errors.New("tunnel: UDP session was not reserved")
	}
	d.pending--
	select {
	case <-d.ctx.Done():
		return net.ErrClosed
	default:
	}
	if id == 0 {
		return errors.New("tunnel: relay assigned a zero UDP session ID")
	}
	if _, exists := d.sessions[id]; exists {
		return errors.New("tunnel: relay reused an active UDP session ID")
	}
	session.sessionID = id
	d.sessions[id] = session
	return nil
}

func (d *clientDatagramDispatcher) unregister(id uint32, session *quicPacketConn) {
	d.mu.Lock()
	if d.sessions[id] == session {
		delete(d.sessions, id)
		d.reassembler.DiscardSession(id)
	}
	d.mu.Unlock()
}

func (d *clientDatagramDispatcher) send(ctx context.Context, message autodatagram.Message) error {
	select {
	case <-d.ctx.Done():
		return net.ErrClosed
	default:
	}
	queued, err := prepareQueuedDatagram(ctx, message)
	if err != nil {
		return err
	}
	select {
	case d.outbound <- queued:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-d.ctx.Done():
		return net.ErrClosed
	default:
		return ErrUDPQueueFull
	}
}

func (d *clientDatagramDispatcher) sendLoop() {
	defer close(d.sendDone)
	for {
		select {
		case <-d.ctx.Done():
			return
		case queued := <-d.outbound:
			if queued.ctx.Err() == nil {
				_ = sendQUICDatagram(d.conn, d.pacer, queued)
			}
		}
	}
}

func (d *clientDatagramDispatcher) shutdown() {
	d.once.Do(func() {
		d.cancel()
		d.mu.RLock()
		sessions := make([]*quicPacketConn, 0, len(d.sessions))
		for _, session := range d.sessions {
			sessions = append(sessions, session)
		}
		d.mu.RUnlock()
		for _, session := range sessions {
			session.terminate()
		}
	})
}

func (d *clientDatagramDispatcher) Close() {
	d.shutdown()
	<-d.done
	<-d.sendDone
}

func (c *Client) datagramDispatcher(conn *quic.Conn) (*clientDatagramDispatcher, error) {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if dispatcher := c.udpDispatchers[conn]; dispatcher != nil {
		return dispatcher, nil
	}
	dispatcher, err := newClientDatagramDispatcher(conn, c.udpConfig, c.connectionPacer(conn))
	if err != nil {
		return nil, err
	}
	dispatcher.onDone = func() {
		c.udpMu.Lock()
		if c.udpDispatchers[conn] == dispatcher {
			delete(c.udpDispatchers, conn)
		}
		c.udpMu.Unlock()
	}
	c.udpDispatchers[conn] = dispatcher
	dispatcher.start()
	return dispatcher, nil
}

func (c *Client) closeDatagramDispatchers() {
	c.udpMu.Lock()
	dispatchers := make([]*clientDatagramDispatcher, 0, len(c.udpDispatchers))
	for _, dispatcher := range c.udpDispatchers {
		dispatchers = append(dispatchers, dispatcher)
	}
	c.udpMu.Unlock()
	for _, dispatcher := range dispatchers {
		dispatcher.Close()
	}
}

// DialPacket implements transport.PacketDialer by opening an authenticated
// NetworkUDP control stream on the shared QUIC connection.
func (c *Client) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil packet dial context")
	}
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.connection(ctx)
		if err != nil {
			return nil, err
		}
		dispatcher, err := c.datagramDispatcher(conn)
		if err != nil {
			return nil, err
		}
		if err := dispatcher.reserveSession(); err != nil {
			return nil, err
		}
		reservationHeld := true
		releaseReservation := func() {
			if reservationHeld {
				dispatcher.releaseReservation()
				reservationHeld = false
			}
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			releaseReservation()
			if contextError(ctx) != nil {
				return nil, contextError(ctx)
			}
			if conn.Context().Err() != nil {
				c.invalidate(conn)
				continue
			}
			return nil, fmt.Errorf("tunnel: open UDP control stream: %w", err)
		}
		control := newQUICStreamConn(stream, conn, c.connectionPacer(conn))
		sessionCtx, sessionCancel := context.WithCancel(dispatcher.ctx)
		session := &quicPacketConn{
			dispatcher: dispatcher,
			control:    control,
			ctx:        sessionCtx,
			cancel:     sessionCancel,
			receive:    make(chan packetResult, c.udpConfig.receiveQueue),
			done:       make(chan struct{}),
		}
		requestNonce, err := randomNonZeroUint32()
		if err != nil {
			releaseReservation()
			session.terminate()
			return nil, fmt.Errorf("tunnel: generate UDP request nonce: %w", err)
		}
		response, err := openProtocolRequest(ctx, control, protocol.Request{
			Network:   protocol.NetworkUDP,
			Token:     []byte(c.token),
			SessionID: requestNonce,
			MaxTx:     c.maxTx,
			MaxRx:     c.maxRx,
			TxMode:    c.txMode,
			TxProfile: c.txProfile,
		}, c.handshakeTimeout)
		if err != nil {
			releaseReservation()
			session.terminate()
			var remoteErr *RemoteError
			if errors.As(err, &remoteErr) {
				c.primarySucceeded()
				return nil, err
			}
			if contextError(ctx) != nil {
				return nil, contextError(ctx)
			}
			if conn.Context().Err() != nil {
				c.invalidate(conn)
				continue
			}
			return nil, fmt.Errorf("tunnel: UDP control handshake: %w", err)
		}
		if err := c.acceptPacingResponse(conn, response, requestNonce, true); err != nil {
			releaseReservation()
			session.terminate()
			return nil, fmt.Errorf("tunnel: invalid UDP pacing response: %w", err)
		}
		err = dispatcher.registerAssigned(session, response.SessionID)
		reservationHeld = false
		if err != nil {
			session.terminate()
			return nil, err
		}
		c.primarySucceeded()
		go session.watchControl()
		return session, nil
	}
	return nil, errors.New("tunnel: UDP connection unavailable")
}

type packetResult struct {
	payload []byte
	address string
}

type quicPacketConn struct {
	dispatcher *clientDatagramDispatcher
	control    *quicStreamConn
	ctx        context.Context
	cancel     context.CancelFunc
	sessionID  uint32
	nextID     atomic.Uint32
	receive    chan packetResult
	done       chan struct{}
	closeOnce  sync.Once
}

func (c *quicPacketConn) Send(payload []byte, address string) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	messageID := c.nextID.Add(1) - 1
	return c.dispatcher.send(c.ctx, autodatagram.Message{
		SessionID: c.sessionID,
		MessageID: messageID,
		Address:   address,
		Payload:   payload,
	})
}

func (c *quicPacketConn) Receive() ([]byte, string, error) {
	select {
	case <-c.done:
		return nil, "", net.ErrClosed
	default:
	}
	select {
	case <-c.done:
		return nil, "", net.ErrClosed
	case result := <-c.receive:
		select {
		case <-c.done:
			return nil, "", net.ErrClosed
		default:
			return result.payload, result.address, nil
		}
	}
}

func (c *quicPacketConn) deliver(result packetResult) {
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case c.receive <- result:
	case <-c.done:
	default:
	}
}

func (c *quicPacketConn) watchControl() {
	var unexpected [1]byte
	_, _ = c.control.Read(unexpected[:])
	c.terminate()
}

func (c *quicPacketConn) terminate() {
	c.closeOnce.Do(func() {
		c.cancel()
		c.dispatcher.unregister(c.sessionID, c)
		close(c.done)
		finishStream(c.control)
	})
}

func (c *quicPacketConn) Close() error {
	c.terminate()
	return nil
}

func (c *quicPacketConn) MaxPayloadSize() int { return autodatagram.MaxPayloadSize }

type queuedDatagram struct {
	ctx     context.Context
	message autodatagram.Message
	frames  [][]byte
}

func prepareQueuedDatagram(ctx context.Context, message autodatagram.Message) (queuedDatagram, error) {
	if err := context.Cause(ctx); err != nil {
		return queuedDatagram{}, err
	}
	message.Payload = append([]byte(nil), message.Payload...)
	frames, err := autodatagram.Encode(message, defaultUDPFrameSize)
	if err != nil {
		return queuedDatagram{}, err
	}
	return queuedDatagram{ctx: ctx, message: message, frames: frames}, nil
}

func sendQUICDatagram(
	conn *quic.Conn,
	pacer *connectionPacer,
	queued queuedDatagram,
) error {
	frameSize := defaultUDPFrameSize
	frames := queued.frames
	for attempt := 0; attempt < 2; attempt++ {
		var err error
		for index, frame := range frames {
			if err := context.Cause(queued.ctx); err != nil {
				return err
			}
			if pacer != nil {
				if err = pacer.wait(queued.ctx, len(frame), conn); err != nil {
					return err
				}
			}
			err = conn.SendDatagram(frame)
			if err == nil {
				continue
			}
			var tooLarge *quic.DatagramTooLargeError
			if index == 0 && errors.As(err, &tooLarge) && tooLarge.MaxDatagramPayloadSize >= autodatagram.MinFrameSize && int64(frameSize) > tooLarge.MaxDatagramPayloadSize {
				frameSize = int(tooLarge.MaxDatagramPayloadSize)
				resizedFrames, encodeErr := autodatagram.Encode(queued.message, frameSize)
				if encodeErr != nil {
					return encodeErr
				}
				frames = resizedFrames
				break
			}
			return err
		}
		if err == nil {
			return nil
		}
	}
	return errors.New("tunnel: QUIC DATAGRAM path size is unstable")
}

func randomNonZeroUint32() (uint32, error) {
	var raw [4]byte
	for {
		if _, err := io.ReadFull(cryptorand.Reader, raw[:]); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint32(raw[:])
		if value != 0 {
			return value, nil
		}
	}
}

func resolveUDPDestinations(ctx context.Context, resolver UDPResolver, address string) ([]netip.AddrPort, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: invalid UDP destination: %w", err)
	}
	portNumber, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, errors.New("tunnel: invalid UDP destination port")
	}
	resolved, err := resolver.ResolveUDPContext(ctx, address)
	if err != nil {
		return nil, err
	}
	wantPort := uint16(portNumber)
	seen := make(map[netip.AddrPort]struct{}, len(resolved))
	destinations := make([]netip.AddrPort, 0, len(resolved))
	for _, destination := range resolved {
		if !destination.IsValid() || destination.Port() != wantPort {
			continue
		}
		destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
		if _, duplicate := seen[destination]; duplicate {
			continue
		}
		seen[destination] = struct{}{}
		destinations = append(destinations, destination)
	}
	if len(destinations) == 0 {
		return nil, errors.New("tunnel: UDP destination has no usable addresses")
	}
	return destinations, nil
}

type systemUDPResolver struct{}

func (systemUDPResolver) ResolveUDPContext(ctx context.Context, address string) ([]netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("tunnel: invalid UDP destination %q", address)
	}
	portNumber, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, fmt.Errorf("tunnel: invalid UDP destination port %q", portText)
	}
	port := uint16(portNumber)
	if literal, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(literal.Unmap(), port)}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	resolved := make([]netip.AddrPort, 0, len(addresses))
	for _, address := range addresses {
		resolved = append(resolved, netip.AddrPortFrom(address.Unmap(), port))
	}
	return resolved, nil
}

var _ transport.PacketDialer = (*Client)(nil)
var _ transport.PacketConn = (*quicPacketConn)(nil)
var _ transport.PacketPayloadSizer = (*quicPacketConn)(nil)
