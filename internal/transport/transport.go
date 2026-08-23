// Package transport defines the protocol-neutral interfaces used by proxy
// frontends. Implementations terminate the local connection and create a new
// connection at the authenticated remote endpoint.
package transport

import (
	"context"
	"errors"
	"net"
)

// ErrPacketQueueFull means a best-effort datagram was not accepted because a
// bounded local transport queue is full. Datagram frontends may drop that
// packet and keep the association alive; other send errors are terminal.
var ErrPacketQueueFull = errors.New("transport: packet send queue is full")

// Dialer creates remote TCP connections through an authenticated tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// PacketDialer is an optional capability implemented by transports that can
// carry datagrams. Proxy frontends must continue to work with a plain Dialer;
// datagram commands are advertised only when this interface is available.
type PacketDialer interface {
	DialPacket(ctx context.Context) (PacketConn, error)
}

// PacketConn carries independent datagrams through an authenticated tunnel.
// Send consumes payload before returning. Close must unblock a concurrent
// Receive call so proxy shutdown cannot leak goroutines.
type PacketConn interface {
	Send(payload []byte, address string) error
	Receive() (payload []byte, address string, err error)
	Close() error
}

// PacketPayloadSizer is an optional capability for packet transports with a
// logical-message limit below the UDP protocol maximum. Frontends use it to
// reject an oversized payload without tearing down an otherwise healthy
// association.
type PacketPayloadSizer interface {
	MaxPayloadSize() int
}

// DialFunc adapts a function to Dialer.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// DialContext implements Dialer.
func (f DialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
