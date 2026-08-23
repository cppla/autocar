// Package tunnel provides the encrypted, authenticated transport between an
// AutoCAR ingress and exit. Each proxied TCP connection is one independent
// QUIC stream. A TCP+TLS transport using the same protocol is available when
// UDP is unavailable.
package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

const (
	defaultHandshakeTimeout     = 10 * time.Second
	defaultDialTimeout          = 10 * time.Second
	defaultMaxStreams           = 1024
	defaultMaxConnections       = 256
	defaultMaxClientConnections = 32
)

// RemoteError is returned when the authenticated exit rejects a CONNECT
// request. It is distinct from a transport failure, so callers don't retry a
// refused destination through the fallback transport.
type RemoteError struct {
	Status  protocol.Status
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("tunnel: remote error (status %d)", e.Status)
	}
	return fmt.Sprintf("tunnel: remote error: %s (status %d)", e.Message, e.Status)
}

type serverCore struct {
	tokenHash        [sha256.Size]byte
	dialer           transport.Dialer
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	sem              chan struct{}
}

func newServerCore(token string, dialer transport.Dialer, handshakeTimeout, dialTimeout time.Duration, maxStreams int) (*serverCore, error) {
	if len(token) < protocol.MinTokenLength || len(token) > protocol.MaxTokenLength {
		return nil, fmt.Errorf("tunnel: token length must be between %d and %d bytes", protocol.MinTokenLength, protocol.MaxTokenLength)
	}
	if dialer == nil {
		netDialer := &net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}
		dialer = netDialer
	}
	if handshakeTimeout < 0 || dialTimeout < 0 || maxStreams < 0 {
		return nil, errors.New("tunnel: timeout and concurrency limits cannot be negative")
	}
	if handshakeTimeout == 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	if dialTimeout == 0 {
		dialTimeout = defaultDialTimeout
	}
	if maxStreams == 0 {
		maxStreams = defaultMaxStreams
	}
	return &serverCore{
		tokenHash:        sha256.Sum256([]byte(token)),
		dialer:           dialer,
		handshakeTimeout: handshakeTimeout,
		dialTimeout:      dialTimeout,
		sem:              make(chan struct{}, maxStreams),
	}, nil
}

func (s *serverCore) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *serverCore) release() { <-s.sem }

func (s *serverCore) authenticate(token []byte) bool {
	// Hashing first makes the comparison duration independent of the presented
	// token's length. The parser has already bounded the hashing work.
	presented := sha256.Sum256(token)
	return subtle.ConstantTimeCompare(presented[:], s.tokenHash[:]) == 1
}

// streamRequestOptions let a transport attach negotiated metadata and a
// sender wrapper after authentication. Handled is reserved for requests such
// as a QUIC DATAGRAM association that don't create a TCP relay. A handler that
// sets Handled owns the complete response and association lifetime before it
// returns; handleStream then performs the final stream close.
type streamRequestOptions struct {
	Response protocol.Response
	Relay    deadlineConn
	Handled  bool
}

type streamRequestHandler func(context.Context, deadlineConn, protocol.Request) streamRequestOptions

// handleStream owns stream and closes it before returning. The deadline is
// used only for the request / response handshake and is cleared before relay.
func (s *serverCore) handleStream(
	ctx context.Context,
	stream deadlineConn,
	authenticated func(),
	handler streamRequestHandler,
) {
	defer finishStream(stream)
	if err := stream.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return
	}
	req, err := protocol.ReadRequest(stream)
	if err != nil {
		_ = protocol.WriteResponse(stream, protocol.Response{Status: protocol.StatusBadRequest, Message: "invalid request"})
		return
	}
	if !s.authenticate(req.Token) {
		_ = protocol.WriteResponse(stream, protocol.Response{Status: protocol.StatusUnauthorized, Message: "authentication failed"})
		return
	}
	if authenticated != nil {
		authenticated()
	}
	options := streamRequestOptions{Relay: stream}
	if handler != nil {
		options = handler(ctx, stream, req)
		if options.Handled {
			return
		}
		if options.Relay == nil {
			options.Relay = stream
		}
	}
	if req.Network == protocol.NetworkUDP {
		_ = protocol.WriteResponse(stream, protocol.Response{
			Status:  protocol.StatusBadRequest,
			Message: "datagrams unavailable on this transport",
		})
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout)
	upstream, err := s.dialer.DialContext(dialCtx, req.Network.String(), req.Address)
	cancel()
	if err != nil {
		// Do not expose resolver, topology or operating-system details to the
		// peer. The ingress only needs a stable typed failure.
		_ = protocol.WriteResponse(stream, protocol.Response{Status: protocol.StatusDialFailed, Message: "destination unavailable"})
		return
	}
	defer upstream.Close()
	options.Response.Status = protocol.StatusOK
	if err := protocol.WriteResponse(stream, options.Response); err != nil {
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return
	}
	relay(options.Relay, upstream)
}

type deadlineConn interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// relay copies in both directions with no userspace queue. io.Copy provides
// natural backpressure. An orderly EOF half-closes only the opposite writer;
// a hard error aborts both sides so the other goroutine cannot leak.
func relay(a, b io.ReadWriteCloser) {
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	done := make(chan struct{}, 2)
	copyOne := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		if err != nil && !isBenignClose(err) {
			abort()
		} else {
			closeWrite(dst)
		}
		done <- struct{}{}
	}
	go copyOne(b, a)
	go copyOne(a, b)
	<-done
	<-done
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(w io.Writer) {
	if cw, ok := w.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

type closeReader interface{ CloseRead() error }

// finishStream sends an orderly FIN before releasing a successfully handled
// protocol stream. QUIC's Close method below intentionally performs an abort
// (as net.Conn.Close must unblock concurrent operations), so the QUIC-specific
// CloseRead path avoids aborting reliable delivery after CloseWrite.
func finishStream(stream io.ReadWriteCloser) {
	closeWrite(stream)
	if cr, ok := stream.(closeReader); ok {
		_ = cr.CloseRead()
		return
	}
	_ = stream.Close()
}

func isBenignClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

func clientTLSConfig(input *tls.Config, address string) (*tls.Config, error) {
	if input == nil {
		return nil, errors.New("tunnel: a verifying client TLS config is required")
	}
	if input.InsecureSkipVerify {
		return nil, errors.New("tunnel: InsecureSkipVerify is forbidden")
	}
	cfg := input.Clone()
	if err := requireTLS13(cfg); err != nil {
		return nil, err
	}
	cfg.NextProtos = []string{protocol.ALPN}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host == "" {
			return nil, fmt.Errorf("tunnel: invalid server address %q", address)
		}
		cfg.ServerName = host
	}
	return cfg, nil
}

func serverTLSConfig(input *tls.Config) (*tls.Config, error) {
	if input == nil {
		return nil, errors.New("tunnel: a server TLS config is required")
	}
	cfg := input.Clone()
	if err := requireTLS13(cfg); err != nil {
		return nil, err
	}
	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil && cfg.GetConfigForClient == nil {
		return nil, errors.New("tunnel: server TLS config has no certificate")
	}
	cfg.NextProtos = []string{protocol.ALPN}
	getConfigForClient := cfg.GetConfigForClient
	if getConfigForClient != nil {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := getConfigForClient(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			// crypto/tls replaces the listener Config with the callback result
			// before version and ALPN negotiation. Clone and reapply AutoCAR's
			// policy so a dynamic certificate selector cannot weaken the hardened
			// parent configuration. Clearing the nested callback also prevents a
			// returned Config from reintroducing an unwrapped policy path.
			selected = selected.Clone()
			selected.GetConfigForClient = nil
			if err := requireTLS13(selected); err != nil {
				return nil, err
			}
			selected.NextProtos = []string{protocol.ALPN}
			return selected, nil
		}
	}
	return cfg, nil
}

func requireTLS13(cfg *tls.Config) error {
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return errors.New("tunnel: TLS 1.3 is required")
	}
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return nil
}

func openProtocol(ctx context.Context, conn deadlineConn, token, network, address string, timeout time.Duration) error {
	n, err := protocol.ParseNetwork(network)
	if err != nil {
		return err
	}
	_, err = openProtocolRequest(ctx, conn, protocol.Request{
		Network: n,
		Token:   []byte(token),
		Address: address,
	}, timeout)
	return err
}

// openProtocolRequest performs the bounded request/response exchange and
// returns the responder's negotiated metadata. The caller owns conn on every
// return path.
func openProtocolRequest(ctx context.Context, conn deadlineConn, request protocol.Request, timeout time.Duration) (protocol.Response, error) {
	if err := context.Cause(ctx); err != nil {
		return protocol.Response{}, err
	}
	if timeout > 0 {
		deadline := time.Now().Add(timeout)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return protocol.Response{}, err
		}
	}
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(cancelDone)
	})
	cancelWatcherStopped := false
	stopCancelWatcher := func() {
		if cancelWatcherStopped {
			return
		}
		if !stopCancel() {
			<-cancelDone
		}
		cancelWatcherStopped = true
	}
	defer stopCancelWatcher()
	if err := protocol.WriteRequest(conn, request); err != nil {
		return protocol.Response{}, preferContextError(ctx, err)
	}
	response, err := protocol.ReadResponse(conn)
	if err != nil {
		return protocol.Response{}, preferContextError(ctx, err)
	}
	if response.Status != protocol.StatusOK {
		return protocol.Response{}, &RemoteError{Status: response.Status, Message: response.Message}
	}
	stopCancelWatcher()
	if err := context.Cause(ctx); err != nil {
		return protocol.Response{}, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return protocol.Response{}, err
	}
	return response, nil
}

func preferContextError(ctx context.Context, fallback error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return fallback
}

// contextError also recognizes a deadline that has elapsed just before the
// context timer goroutine publishes Done. Socket pollers frequently win that
// narrow race; callers should still observe the context contract.
func contextError(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
