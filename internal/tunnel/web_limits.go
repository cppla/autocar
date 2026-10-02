package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// webConnectionAdmission bounds public web-cover connections before they can
// consume HTTP/2 or HTTP/3 server resources. A combined WebServer shares one
// admission object across TCP and UDP so switching transport cannot multiply
// either the global or per-source allowance.
type webConnectionAdmission struct {
	slots   chan struct{}
	clients *sourceConnectionLimiter
}

func newWebConnectionAdmission(maxConnections, maxClientConnections int) (*webConnectionAdmission, error) {
	if maxConnections < 0 {
		return nil, errors.New("tunnel: maximum web-cover connections cannot be negative")
	}
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	if maxClientConnections < 0 {
		return nil, errors.New("tunnel: maximum web-cover client connections cannot be negative")
	}
	if maxClientConnections == 0 {
		maxClientConnections = min(defaultMaxClientConnections, maxConnections)
	}
	if maxClientConnections > maxConnections {
		return nil, fmt.Errorf(
			"tunnel: maximum web-cover client connections (%d) exceeds maximum connections (%d)",
			maxClientConnections,
			maxConnections,
		)
	}
	return &webConnectionAdmission{
		slots:   make(chan struct{}, maxConnections),
		clients: newSourceConnectionLimiter(maxClientConnections),
	}, nil
}

func (a *webConnectionAdmission) acquire(remote net.Addr) (func(), bool) {
	select {
	case a.slots <- struct{}{}:
	default:
		return nil, false
	}
	sourceKey := tlsSourceKey(remote)
	if !a.clients.acquire(sourceKey) {
		<-a.slots
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			a.clients.release(sourceKey)
			<-a.slots
		})
	}, true
}

type webAdmissionListener struct {
	net.Listener
	admission *webConnectionAdmission
	owner     *webTCPConnectionOwner
}

func (l *webAdmissionListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, ok := l.admission.acquire(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			continue
		}
		owned := &webAdmissionConn{Conn: conn, release: release, owner: l.owner}
		if l.owner != nil && !l.owner.register(owned) {
			_ = owned.Close()
			return nil, net.ErrClosed
		}
		return owned, nil
	}
}

type webAdmissionConn struct {
	net.Conn
	release  func()
	owner    *webTCPConnectionOwner
	once     sync.Once
	closeErr error
}

func (c *webAdmissionConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.release()
		if c.owner != nil {
			c.owner.remove(c)
		}
	})
	return c.closeErr
}

// webAdmissionQUICListener adapts a quic.Listener to http3.QUICListener while
// releasing capacity only when the accepted QUIC connection actually ends.
type webAdmissionQUICListener struct {
	listener  *quic.Listener
	admission *webConnectionAdmission
}

func (l *webAdmissionQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	for {
		conn, err := l.listener.Accept(ctx)
		if err != nil {
			return nil, err
		}
		release, ok := l.admission.acquire(conn.RemoteAddr())
		if !ok {
			// This listener speaks HTTP/3, not the native relay protocol. Its
			// connection limit is an overload condition, not an internal error.
			_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "connection unavailable")
			continue
		}
		go func() {
			<-conn.Context().Done()
			release()
		}()
		return conn, nil
	}
}

func (l *webAdmissionQUICListener) Addr() net.Addr { return l.listener.Addr() }
func (l *webAdmissionQUICListener) Close() error   { return l.listener.Close() }
