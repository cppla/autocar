// Package transport defines the protocol-neutral interfaces used by proxy
// frontends. Implementations terminate the local connection and create a new
// connection at the authenticated remote endpoint.
package transport

import (
	"context"
	"net"
)

// Dialer creates remote TCP connections through an authenticated tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialFunc adapts a function to Dialer.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// DialContext implements Dialer.
func (f DialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
