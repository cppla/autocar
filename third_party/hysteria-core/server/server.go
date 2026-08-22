package server

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
)

type Server interface {
	Serve() error
	Close() error
}

func convertToStdTLSConfig(config *Config) *tls.Config {
	var clientAuth tls.ClientAuthType
	if config.TLSConfig.ClientCAs != nil {
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		clientAuth = tls.NoClientCert
	}
	return http3.ConfigureTLSConfig(&tls.Config{
		Certificates:                config.TLSConfig.Certificates,
		GetCertificate:              config.TLSConfig.GetCertificate,
		ClientCAs:                   config.TLSConfig.ClientCAs,
		ClientAuth:                  clientAuth,
		EncryptedClientHelloKeys:    config.TLSConfig.ECHKeys,
		GetEncryptedClientHelloKeys: config.TLSConfig.GetECHKeys,
	})
}

func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}
	tlsConfig := convertToStdTLSConfig(config)
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 config.QUICConfig.MaxIdleTimeout,
		MaxIncomingStreams:             config.QUICConfig.MaxIncomingStreams,
		MaxIncomingUniStreams:          config.QUICConfig.MaxIncomingUniStreams,
		DisablePathMTUDiscovery:        config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           protocol.MaxDatagramFrameSize,
		AssumePeerMaxDatagramFrameSize: protocol.MaxDatagramFrameSize,
		DisablePathManager:             true,
	}
	srk := config.StatelessResetKey
	if srk == nil {
		var k quic.StatelessResetKey
		if _, err := crand.Read(k[:]); err != nil {
			return nil, err
		}
		srk = &k
	}
	tr := &quic.Transport{
		Conn:              config.Conn,
		DisableGSO:        config.QUICConfig.DisableGSO,
		StatelessResetKey: srk,
		// Always require QUIC Retry before allocating a connection. This proves
		// return-path reachability and prevents spoofed Initial packets from
		// creating handshake state.
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	connSlots := make(chan struct{}, config.MaxConnections)
	connClientSlots := newKeyedLimiter(config.MaxClientConnections)
	tr.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		return admitConnection(ctx, connSlots, connClientSlots, sourceIPKey(info.RemoteAddr))
	}
	listener, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		err = errors.Join(err, tr.Close(), config.Conn.Close())
		if config.Cleanup != nil {
			err = errors.Join(err, config.Cleanup.Close())
		}
		return nil, err
	}
	return &serverImpl{
		config:         config,
		tr:             tr,
		listener:       listener,
		tcpSlots:       make(chan struct{}, config.MaxTCPHandlers),
		tcpClientSlots: newKeyedLimiter(config.MaxClientTCPHandlers),
		udpSlots:       make(chan struct{}, config.MaxUDPSessions),
		udpClientSlots: newKeyedLimiter(config.MaxClientUDPSessions),
	}, nil
}

type serverImpl struct {
	config         *Config
	tr             *quic.Transport
	listener       *quic.Listener
	tcpSlots       chan struct{}
	tcpClientSlots *keyedLimiter
	udpSlots       chan struct{}
	udpClientSlots *keyedLimiter
}

func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

var errConnectionCapacity = errors.New("connection capacity reached")

// admitConnection acquires capacity after Retry has validated the source but
// before quic-go allocates handshake state. The connection context is canceled
// on every handshake failure or established-connection close, which releases
// the slot for the complete lifecycle.
func admitConnection(ctx context.Context, slots chan struct{}, clientSlots *keyedLimiter, clientKey string) (context.Context, error) {
	if !clientSlots.tryAcquire(clientKey) {
		return nil, errConnectionCapacity
	}
	select {
	case slots <- struct{}{}:
		go func() {
			<-ctx.Done()
			<-slots
			clientSlots.release(clientKey)
		}()
		return ctx, nil
	default:
		clientSlots.release(clientKey)
		return nil, errConnectionCapacity
	}
}

func (s *serverImpl) Close() error {
	err := errors.Join(s.listener.Close(), s.tr.Close(), s.config.Conn.Close())
	if s.config.Cleanup != nil {
		err = errors.Join(err, s.config.Cleanup.Close())
	}
	return err
}

func (s *serverImpl) handleClient(conn *quic.Conn) {
	handler := newH3sHandler(s.config, conn, s.tcpSlots, s.tcpClientSlots, s.udpSlots, s.udpClientSlots)
	authTimer := time.AfterFunc(s.config.AuthenticationTimeout, func() {
		if handler.expireAuthentication() {
			_ = conn.CloseWithError(closeErrCodeOK, "authentication timeout")
		}
	})
	h3s := http3.Server{
		Handler:          handler,
		MaxHeaderBytes:   s.config.MaxHTTPHeaderBytes,
		StreamAdmission:  handler.AdmitStream,
		StreamDispatcher: handler.ProxyStreamHijacker,
	}
	err := h3s.ServeQUICConn(conn)
	authTimer.Stop()
	// If the client is authenticated, we need to log the disconnect event
	if authID, authenticated := handler.authState(); authenticated {
		if tl := s.config.TrafficLogger; tl != nil {
			tl.LogOnlineState(authID, false)
		}
		if el := s.config.EventLogger; el != nil {
			el.Disconnect(conn.RemoteAddr(), authID, err)
		}
	}
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

type h3sHandler struct {
	config *Config
	conn   *quic.Conn

	authenticated  bool
	authExpired    bool
	authMutex      sync.RWMutex
	authID         string
	connID         uint32 // a random id for dump streams
	clientKey      string
	tcpSlots       chan struct{}
	tcpClientSlots *keyedLimiter
	udpSlots       chan struct{}
	udpClientSlots *keyedLimiter
}

func newH3sHandler(
	config *Config,
	conn *quic.Conn,
	tcpSlots chan struct{},
	tcpClientSlots *keyedLimiter,
	udpSlots chan struct{},
	udpClientSlots *keyedLimiter,
) *h3sHandler {
	return &h3sHandler{
		config:         config,
		conn:           conn,
		connID:         rand.Uint32(),
		clientKey:      sourceIPKey(conn.RemoteAddr()),
		tcpSlots:       tcpSlots,
		tcpClientSlots: tcpClientSlots,
		udpSlots:       udpSlots,
		udpClientSlots: udpClientSlots,
	}
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		h.authMutex.Lock()
		defer h.authMutex.Unlock()
		if h.authExpired {
			h.masqHandler(w, r)
			return
		}
		if h.authenticated {
			// Already authenticated
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		authReq := protocol.AuthRequestFromHeader(r.Header)
		actualTx := authReq.Rx
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			// Set authenticated flag
			h.authenticated = true
			h.authID = id
			if h.config.IgnoreClientBandwidth {
				// Ignore client bandwidth and use the configured congestion controller.
				congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				actualTx = 0
			} else {
				// actualTx = min(serverTx, clientRx)
				if h.config.BandwidthConfig.MaxTx > 0 && actualTx > h.config.BandwidthConfig.MaxTx {
					// We have a maxTx limit and the client is asking for more than that,
					// return and use the limit instead
					actualTx = h.config.BandwidthConfig.MaxTx
				}
				if actualTx > 0 {
					congestion.UseBrutal(h.conn, actualTx, h.config.BandwidthConfig.DisableLossCompensation)
				} else {
					// Client doesn't know its own bandwidth, use the configured congestion controller.
					congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				}
			}
			// Auth OK, send response
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			// Call event logger
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// Initialize UDP session manager (if UDP is enabled)
			// We use sync.Once to make sure that only one goroutine is started,
			// as ServeHTTP may be called by multiple goroutines simultaneously
			if !h.config.DisableUDP {
				sm := newUDPSessionManager(
					&udpIOImpl{h.conn, id, h.config.TrafficLogger, h.config.RequestHook, h.config.Outbound},
					&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
					h.config.UDPIdleTimeout,
					h.config.MaxClientUDPSessions,
					h.udpSlots,
					h.clientKey,
					h.udpClientSlots,
				)
				go sm.Run()
			}
		} else {
			// Auth failed, pretend to be a normal HTTP server
			h.masqHandler(w, r)
		}
	} else {
		// Not an auth request, pretend to be a normal HTTP server
		h.masqHandler(w, r)
	}
}

func sourceIPKey(address net.Addr) string {
	if udpAddress, ok := address.(*net.UDPAddr); ok {
		if ip, valid := netip.AddrFromSlice(udpAddress.IP); valid {
			return sourcePrefixKey(ip)
		}
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			return sourcePrefixKey(ip)
		}
		return host
	}
	return address.String()
}

// sourcePrefixKey prevents a client with an ordinary IPv6 /64 from evading
// every per-source budget by rotating interface identifiers. IPv4 remains
// keyed by the individual address. The complete remote address is still used
// for logging; only resource admission uses this normalized key.
func sourcePrefixKey(address netip.Addr) string {
	address = address.Unmap().WithZone("")
	if address.Is4() {
		return address.String()
	}
	return netip.PrefixFrom(address, 64).Masked().String()
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	authID, authenticated := h.authState()
	if err != nil || !authenticated {
		return false, nil
	}

	switch ft {
	case protocol.FrameTypeTCPRequest:
		// StreamDispatcher only peeks the frame type. Consume it so ReadTCPRequest
		// starts at address length, matching pre-upgrade StreamHijacker behavior.
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		// Wraps the stream with QStream, which handles Close() properly
		qStream := &utils.QStream{Stream: stream}
		// Run synchronously in quic-go's per-stream worker. StreamAdmission's
		// release callback is deferred by that worker, so the global TCP slot
		// remains held for the complete proxy lifetime, not merely until the
		// request frame has been dispatched.
		h.handleTCPRequest(qStream, authID)
		return true, nil
	default:
		return false, nil
	}
}

// authState synchronizes HTTP authentication with stream dispatch and
// disconnect accounting. In particular, a stream arriving concurrently with
// the authentication response cannot observe authenticated=true with a stale
// or empty authID.
func (h *h3sHandler) authState() (string, bool) {
	h.authMutex.RLock()
	defer h.authMutex.RUnlock()
	return h.authID, h.authenticated
}

// expireAuthentication atomically prevents late authentication. It returns
// true exactly once when an unauthenticated connection crosses its deadline.
func (h *h3sHandler) expireAuthentication() bool {
	h.authMutex.Lock()
	defer h.authMutex.Unlock()
	if h.authenticated || h.authExpired {
		return false
	}
	h.authExpired = true
	return true
}

// AdmitStream applies listener-wide capacity and a first-byte deadline before
// the HTTP/3 layer peeks a frame type. The local quic-go fork guarantees that
// release runs once after dispatch or ordinary HTTP handling completes.
func (h *h3sHandler) AdmitStream(stream *quic.Stream) (func(), bool) {
	return h.admitStream(stream)
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

func (h *h3sHandler) admitStream(stream readDeadlineSetter) (func(), bool) {
	if !h.tcpClientSlots.tryAcquire(h.clientKey) {
		return nil, false
	}
	select {
	case h.tcpSlots <- struct{}{}:
	default:
		h.tcpClientSlots.release(h.clientKey)
		return nil, false
	}
	if err := stream.SetReadDeadline(time.Now().Add(h.config.TCPRequestTimeout)); err != nil {
		<-h.tcpSlots
		h.tcpClientSlots.release(h.clientKey)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-h.tcpSlots
			h.tcpClientSlots.release(h.clientKey)
		})
	}, true
}

func (h *h3sHandler) handleTCPRequest(stream HyStream, authID string) {
	trafficLogger := h.config.TrafficLogger
	streamStats := &StreamStats{
		AuthID:      authID,
		ConnID:      h.connID,
		InitialTime: time.Now(),
	}
	streamStats.State.Store(StreamStateInitial)
	streamStats.LastActiveTime.Store(time.Now())
	defer func() {
		streamStats.State.Store(StreamStateClosed)
	}()
	if trafficLogger != nil {
		trafficLogger.TraceStream(stream, streamStats)
		defer trafficLogger.UntraceStream(stream)
	}

	// Read request
	_ = stream.SetReadDeadline(time.Now().Add(h.config.TCPRequestTimeout))
	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	streamStats.ReqAddr.Store(reqAddr)
	// Call the hook if set
	var putback []byte
	var hooked bool
	if h.config.RequestHook != nil {
		hooked = h.config.RequestHook.Check(false, reqAddr)
		// When the hook is enabled, the server should always accept a connection
		// so that the client will send whatever request the hook wants to see.
		// This is essentially a server-side fast-open.
		if hooked {
			streamStats.State.Store(StreamStateHooking)
			_ = protocol.WriteTCPResponse(stream, true, "RequestHook enabled")
			putback, err = h.config.RequestHook.TCP(stream, &reqAddr)
			if err != nil {
				_ = stream.Close()
				return
			}
			streamStats.setHookedReqAddr(reqAddr)
		}
	}
	// Log the event
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), authID, reqAddr)
	}
	// Dial target
	streamStats.State.Store(StreamStateConnecting)
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, err.Error())
		}
		_ = stream.Close()
		// Log the error
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), authID, reqAddr, err)
		}
		return
	}
	if !hooked {
		_ = protocol.WriteTCPResponse(stream, true, "Connected")
	}
	streamStats.State.Store(StreamStateEstablished)
	// Put back the data if the hook requested
	if len(putback) > 0 {
		n, _ := tConn.Write(putback)
		streamStats.Tx.Add(uint64(n))
	}
	// Start proxying
	if trafficLogger != nil {
		err = copyTwoWayEx(authID, stream, tConn, trafficLogger, streamStats)
	} else {
		// Use the fast path if no traffic logger is set
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), authID, reqAddr, err)
	}
	// Cleanup
	_ = tConn.Close()
	_ = stream.Close()
	// Disconnect the client if TrafficLogger requested
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// Return 404 for everything
		http.NotFound(w, r)
	}
}

// udpIOImpl is the IO implementation for udpSessionManager with TrafficLogger support
type udpIOImpl struct {
	Conn          *quic.Conn
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
				// TrafficLogger requested to disconnect the client
				_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return nil, errDisconnect
			}
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	if io.TrafficLogger != nil {
		ok := io.TrafficLogger.LogTraffic(io.AuthID, 0, uint64(len(msg.Data)))
		if !ok {
			// TrafficLogger requested to disconnect the client
			_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return errDisconnect
		}
	}
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		return coreErrs.ProtocolError{Message: "UDP message exceeds serialization limit"}
	}
	return io.Conn.SendDatagram(buf[:msgN])
}

func (io *udpIOImpl) Hook(data []byte, reqAddr *string) error {
	if io.RequestHook != nil && io.RequestHook.Check(true, *reqAddr) {
		return io.RequestHook.UDP(data, reqAddr)
	} else {
		return nil
	}
}

func (io *udpIOImpl) UDP(reqAddr string) (UDPConn, error) {
	return io.Outbound.UDP(reqAddr)
}

func (io *udpIOImpl) CheckUDP(reqAddr string) error {
	return io.Outbound.CheckUDP(reqAddr)
}

type udpEventLoggerImpl struct {
	Conn        *quic.Conn
	AuthID      string
	EventLogger EventLogger
}

func (l *udpEventLoggerImpl) New(sessionID uint32, reqAddr string) {
	if l.EventLogger != nil {
		l.EventLogger.UDPRequest(l.Conn.RemoteAddr(), l.AuthID, sessionID, reqAddr)
	}
}

func (l *udpEventLoggerImpl) Close(sessionID uint32, err error) {
	if l.EventLogger != nil {
		l.EventLogger.UDPError(l.Conn.RemoteAddr(), l.AuthID, sessionID, err)
	}
}
