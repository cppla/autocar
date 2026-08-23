package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError

	// MaxUDPSize is the largest logical UDP payload carried by one Hysteria
	// message. Larger messages must be rejected before serialization.
	MaxUDPSize = protocol.MaxUDPSize
)

type Client interface {
	TCP(addr string) (net.Conn, error)
	UDP() (HyUDPConn, error)
	Close() error
}

// ContextualTCPClient is implemented by clients that can cancel an in-flight
// TCP request without closing the shared QUIC connection.
type ContextualTCPClient interface {
	TCPContext(ctx context.Context, addr string) (net.Conn, error)
}

type HyUDPConn interface {
	Receive() ([]byte, string, error)
	Send([]byte, string) error
	Close() error
}

type HandshakeInfo struct {
	UDPEnabled  bool
	Tx          uint64 // 0 if using BBR
	ServerAddr  net.Addr
	ECHAccepted bool
}

func NewClient(config *Config) (Client, *HandshakeInfo, error) {
	return NewClientContext(context.Background(), config)
}

// NewClientContext establishes an authenticated session bounded by ctx.
func NewClientContext(ctx context.Context, config *Config) (Client, *HandshakeInfo, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil client context")
	}
	if err := config.verifyAndFill(); err != nil {
		return nil, nil, err
	}
	c := &clientImpl{
		config: config,
	}
	info, err := c.connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	return c, info, nil
}

type clientImpl struct {
	config *Config

	pktConn net.PacketConn
	tr      *quic.Transport
	conn    *quic.Conn

	udpSM *udpSessionManager
}

func (c *clientImpl) connect(ctx context.Context) (*HandshakeInfo, error) {
	pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:                     c.config.TLSConfig.ServerName,
		InsecureSkipVerify:             c.config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate:          c.config.TLSConfig.VerifyPeerCertificate,
		RootCAs:                        c.config.TLSConfig.RootCAs,
		GetClientCertificate:           c.config.TLSConfig.GetClientCertificate,
		EncryptedClientHelloConfigList: c.config.TLSConfig.ECHConfigList,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           protocol.MaxDatagramFrameSize,
		OmitMaxDatagramFrameSize:       true,
		DisablePathManager:             true,
		ChromeParrot:                   !c.config.QUICConfig.DisableChromeParrot,
	}
	tr := &quic.Transport{Conn: pktConn, DisableGSO: c.config.QUICConfig.DisableGSO}
	if !c.config.QUICConfig.DisableChromeParrot {
		// Chrome uses a zero-length source connection ID. This has to be set on the
		// Transport, since it fixes the length at which incoming packets' connection
		// IDs are parsed; leaving it default yields 4-byte IDs, visible on the wire.
		tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
	}
	// Prepare RoundTripper
	var connMu sync.Mutex
	var conn *quic.Conn
	abandoned := false
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(dialCtx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := tr.DialEarly(dialCtx, c.config.ServerAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			connMu.Lock()
			if abandoned {
				connMu.Unlock()
				_ = qc.CloseWithError(closeErrCodeProtocolError, "")
				if cause := context.Cause(dialCtx); cause != nil {
					return nil, cause
				}
				return nil, net.ErrClosed
			}
			conn = qc
			connMu.Unlock()
			return qc, nil
		},
	}
	// Send auth HTTP request
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	req = req.WithContext(ctx)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		connMu.Lock()
		abandoned = true
		activeConn := conn
		connMu.Unlock()
		if activeConn != nil {
			_ = activeConn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: err}
	}
	connMu.Lock()
	activeConn := conn
	connMu.Unlock()
	if activeConn == nil {
		_ = resp.Body.Close()
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: errors.New("HTTP/3 authentication completed without a QUIC connection")}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = resp.Body.Close()
		_ = activeConn.CloseWithError(closeErrCodeProtocolError, "")
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use the configured congestion controller.
		congestion.UseConfigured(activeConn, c.config.CongestionConfig.Type, c.config.CongestionConfig.BBRProfile)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(activeConn, actualTx, c.config.BandwidthConfig.DisableLossCompensation)
		} else {
			// We don't know our own bandwidth either, use the configured congestion controller.
			congestion.UseConfigured(activeConn, c.config.CongestionConfig.Type, c.config.CongestionConfig.BBRProfile)
		}
	}
	_ = resp.Body.Close()

	c.pktConn = pktConn
	c.tr = tr
	c.conn = activeConn
	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: activeConn})
	}
	return &HandshakeInfo{
		UDPEnabled:  authResp.UDPEnabled,
		Tx:          actualTx,
		ServerAddr:  c.config.ServerAddr,
		ECHAccepted: activeConn.ConnectionState().TLS.ECHAccepted,
	}, nil
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *clientImpl) openStream() (*utils.QStream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string) (net.Conn, error) {
	return c.TCPContext(context.Background(), addr)
}

// TCPContext opens a stream and cancels it if ctx expires while the relay is
// still resolving or dialing the requested target.
func (c *clientImpl) TCPContext(ctx context.Context, addr string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("nil TCP context")
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	stream, err := c.openStream()
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		return nil, wrapIfConnectionClosed(err)
	}
	cancelDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		close(cancelDone)
	})
	watchingContext := true
	defer func() {
		if watchingContext {
			stopCancellation()
		}
	}()
	finishContextWatch := func() error {
		if !stopCancellation() {
			<-cancelDone
		}
		watchingContext = false
		cause := context.Cause(ctx)
		if cause != nil {
			// stopCancellation may win after ctx is canceled but before the
			// callback starts. Take ownership and cancel both directions here
			// as well; these operations are idempotent.
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
		return cause
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		if cause := finishContextWatch(); cause != nil {
			return nil, cause
		}
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		if cause := finishContextWatch(); cause != nil {
			return nil, cause
		}
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		if cause := finishContextWatch(); cause != nil {
			return nil, cause
		}
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if cause := finishContextWatch(); cause != nil {
		return nil, cause
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		established:      true,
	}, nil
}

func (c *clientImpl) UDP() (HyUDPConn, error) {
	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return c.udpSM.NewUDP()
}

func (c *clientImpl) Close() error {
	_ = c.conn.CloseWithError(closeErrCodeOK, "")
	_ = c.tr.Close()
	_ = c.pktConn.Close()
	return nil
}

var _ ContextualTCPClient = (*clientImpl)(nil)

var nonPermanentErrors = []error{
	quic.StreamLimitReachedError{},
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// is recoverable (listed in nonPermanentErrors) or permanent.
// Recoverable errors are returned as-is,
// permanent ones are wrapped as ClosedError.
func wrapIfConnectionClosed(err error) error {
	for _, e := range nonPermanentErrors {
		if errors.Is(err, e) {
			return err
		}
	}
	return coreErrs.ClosedError{Err: err}
}

type tcpStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type tcpConn struct {
	Orig             tcpStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr

	establishMu  sync.Mutex
	established  bool
	establishErr error
	closeMu      sync.Mutex
	closed       bool
	closeErr     error
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if err := c.ensureEstablished(); err != nil {
		return 0, err
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) ensureEstablished() error {
	c.establishMu.Lock()
	defer c.establishMu.Unlock()
	if c.established {
		return nil
	}
	if c.establishErr != nil {
		return c.establishErr
	}
	ok, msg, err := protocol.ReadTCPResponse(c.Orig)
	if err != nil {
		c.establishErr = err
	} else if !ok {
		c.establishErr = coreErrs.DialError{Message: msg}
	} else {
		c.established = true
		return nil
	}
	_ = c.closeOrig()
	return c.establishErr
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.closeOrig()
}

func (c *tcpConn) closeOrig() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if !c.closed {
		c.closeErr = c.Orig.Close()
		c.closed = true
	}
	return c.closeErr
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

type udpIOImpl struct {
	Conn *quic.Conn
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
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		return coreErrs.ProtocolError{Message: "UDP message exceeds serialization limit"}
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
