# AutoCAR wire protocol v1

This document describes the protocol implemented by `internal/protocol`. It is
intended to make compatibility and security review possible; it is not a
promise that every internal Go API is stable.

## Transport binding

Protocol v1 is carried over either:

- one bidirectional stream in a QUIC v1 or v2 connection, as negotiated by
  the pinned quic-go transport, or
- one TLS-over-TCP connection dedicated to a single proxied stream.

Both transports require TLS 1.3 and negotiate the ALPN value `autocar/1`.
Normal X.509 chain and DNS/IP SAN verification is mandatory on the client.
The server can additionally require an mTLS client certificate. QUIC 0-RTT
and QUIC DATAGRAM are disabled, so a CONNECT request is not sent as replayable
early data.

Each QUIC stream or fallback TLS connection contains exactly one CONNECT
exchange followed by an unframed TCP byte stream. Integers are unsigned and
encoded in network byte order (big endian).

## Common header

Every request and response starts with this 12-byte header:

| Offset | Size | Field | Value |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `AUTO` (`0x4155544f`) |
| 4 | 1 | Version | `1` |
| 5 | 1 | Kind | `1` for CONNECT, `2` for response |
| 6 | 2 | Flags | Kind-specific value |
| 8 | 2 | Length 1 | Kind-specific body length |
| 10 | 2 | Length 2 | Kind-specific body length or zero |

Readers reject a bad magic value, unsupported version or unexpected kind.
Every length is checked against its semantic limit before allocation.

## CONNECT request

A request uses kind `1` and this layout:

| Header field | Meaning |
| --- | --- |
| Flags | Network: `1` = `tcp`, `2` = `tcp4`, `3` = `tcp6` |
| Length 1 | Shared-token byte length, from 16 through 1024 |
| Length 2 | destination byte length, from 1 through 1024 |
| Body | token bytes followed immediately by destination bytes |

The destination is a Go `net.SplitHostPort`-compatible `host:port` value.
IPv6 literals therefore use brackets, for example `[2001:db8::1]:443`. NUL
bytes are forbidden. Protocol framing does not separately validate UTF-8. A
hostname is preserved for resolution by the relay.

The token is transported only after the encrypted channel has been
established. The relay compares a SHA-256 digest of the presented token with
the configured token digest using a constant-time comparison. The token is an
authorization factor, not a replacement for certificate verification.

## Response

A response uses kind `2` and this layout:

| Header field | Meaning |
| --- | --- |
| Flags | Status code |
| Length 1 | Optional human-readable message length, 0 through 1024 |
| Length 2 | Reserved; must be zero |
| Body | message bytes |

Status values are:

| Value | Name | Meaning |
| ---: | --- | --- |
| 0 | OK | Destination connection established |
| 1 | Bad request | Request framing or fields were invalid |
| 2 | Unauthorized | Shared-token authentication failed |
| 3 | Dial failed | Destination was unavailable or blocked by egress policy |
| 4 | Busy | Concurrent-stream capacity was exhausted |
| 5 | Internal | Reserved for a relay-side internal failure |

Relay errors deliberately avoid returning resolver, host-topology or operating
system details. Clients treat a valid non-OK response as a remote error, not a
transport outage; it therefore does not trigger a retry through the TCP/TLS
fallback.

## Relay phase and shutdown

After an OK response, both sides clear the protocol-handshake deadline and
copy bytes without further application framing. Backpressure comes from the
underlying stream. An orderly EOF is propagated as a half-close in the other
direction, while a hard error aborts both directions.

On QUIC, many independent TCP flows share one authenticated QUIC connection,
with one bidirectional QUIC stream per flow. On the TCP fallback, each flow
gets a separate TLS 1.3 connection; protocol v1 does not implement a custom
multiplexer over TCP.

## Versioning

Any incompatible change requires a new version and a new ALPN value. A v1
implementation must not silently reinterpret unknown kinds, networks,
statuses or non-zero reserved fields.

This protocol carries TCP only. SOCKS5 UDP ASSOCIATE and QUIC DATAGRAM are not
implemented in v1.
