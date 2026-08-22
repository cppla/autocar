// Package proxy implements the local, protocol-facing side of autocar.
//
// Both frontends terminate the user's local TCP connection and use a
// transport.Dialer to create the corresponding connection at the other end of
// the encrypted tunnel.  SOCKS5 UDP is deliberately not implemented here: it
// needs a datagram-capable transport rather than pretending UDP is a TCP
// stream.
package proxy
