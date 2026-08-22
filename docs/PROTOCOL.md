# AutoCAR transports and wire protocols

AutoCAR currently has two UDP wire protocols plus one TCP fallback protocol.
The CLI transport name and the bytes on the wire must not be confused.

## Compatibility matrix

| Client selection | Server selection | Carrier | Wire protocol | Datagram proxying |
| --- | --- | --- | --- | --- |
| `auto` (default) | `--quic-engine=hy2` (default) | UDP first, TCP fallback | Hysteria v2; AutoCAR v1 on fallback | Yes on the UDP path |
| `hy2` or `quic` | `--quic-engine=hy2` | UDP | Hysteria v2 | Yes |
| `legacy-quic` | `--quic-engine=legacy` | UDP | AutoCAR v1 | No |
| `tls` | either UDP engine | TCP | AutoCAR v1 | No |

`quic` is an alias for `hy2`. It exists for CLI continuity, not wire
compatibility with the original AutoCAR QUIC engine. A client and server that
select different UDP engines cannot complete the UDP handshake.

## Default Hysteria v2 wire

The default engine delegates its wire format and state machine to
[`github.com/apernet/hysteria/core/v2` v2.12.1](https://github.com/apernet/hysteria/tree/14e9fff1d972ab0187ac7fcf75b9514dc8664065/core).
It is Hysteria v2 over HTTP/3 and QUIC, rather than an AutoCAR-specific framing
layer. This section records AutoCAR's binding and security policy; the upstream
[Hysteria v2 protocol documentation](https://github.com/apernet/hysteria/blob/14e9fff1d972ab0187ac7fcf75b9514dc8664065/PROTOCOL.md)
is the interoperability reference.

### Authentication and transport negotiation

The client establishes HTTP/3 with TLS 1.3 and sends the Hysteria authentication
request containing the shared token and the client's receive-rate hint. On
success, the relay returns whether UDP is enabled and its receive-rate
advertisement. The two advertisements independently select the client-to-relay
and relay-to-client sender rate.

For each direction:

1. by default the relay ignores all client capacity hints, keeps the configured
   model controller (BBR by default, or Reno), and reports automatic bandwidth
   selection;
2. the operator must explicitly set `--allow-client-bandwidth` and finite
   non-zero upload/download ceilings before the relay accepts Brutal hints; and
3. in that opt-in mode, a non-zero client hint selects Brutal at the lower of
   the client value and corresponding server ceiling, while a zero hint keeps
   BBR/Reno for that direction.

The rate values on the Hysteria wire are bytes per second. AutoCAR's CLI accepts
decimal Mbit/s and converts with `Mbit/s * 1,000,000 / 8`.

| Hysteria field | AutoCAR CLI meaning |
| --- | --- |
| Client `MaxTx` | `--upload-mbps`, client to relay |
| Client `MaxRx` | `--download-mbps`, relay to client |
| Server `MaxTx` | `--max-download-mbps`, relay-to-client Brutal negotiation ceiling |
| Server `MaxRx` | `--max-upload-mbps`, client-to-relay Brutal negotiation ceiling |

These server values constrain negotiation with the official client; they are
not a packet policer and do not impose a hard throughput limit on a modified
or zero-hint client. Enforce non-bypassable limits in the host or cloud network.

Unknown, malformed, and unauthenticated HTTP/3 requests are passed to the
configured cover handler. AutoCAR's built-in handler returns a neutral page for
`GET /` and `HEAD /`, with ordinary not-found responses elsewhere. It does not
reveal whether a supplied token was close to valid.

### TCP streams and Fast Open

Each proxied TCP flow uses a Hysteria bidirectional QUIC stream. Its bounded
request identifies the destination, and the relay returns success or a generic
dial error before opaque byte forwarding. Fast Open is disabled by default.
With client `--fast-open=true`, the connection is returned after the target
request is written; application writes may proceed while the response is
deferred until the first read. Fast Open does not bypass TLS, token
authentication, outbound policy, or the destination dial.

An authenticated relay error is an application result, not evidence that UDP
is unavailable. `auto` therefore does not duplicate that request through TLS.

### UDP datagrams

SOCKS5 UDP ASSOCIATE creates one Hysteria logical UDP session. Each QUIC
DATAGRAM carries a session identifier, packet/fragment identifiers, target
address, and payload. Hysteria fragments messages that exceed the available
QUIC DATAGRAM payload and reassembles them inside the same logical session.
This fragmentation is bounded: one logical payload may be at most 4,096 bytes.
The SOCKS frontend drops a larger payload before calling the Hysteria transport
and keeps the association alive. DATAGRAM delivery is intentionally unreliable
and unordered; QUIC does not
retransmit a lost UDP payload.

The SOCKS request's `DST.ADDR` and `DST.PORT` describe the expected local UDP
source as specified by RFC 1928. An unspecified address is bound to the TCP
control peer; a concrete IP must equal that peer, and a domain must resolve to
it. A non-zero port is enforced. Port zero remains the normal dynamic form and
is locked to the first valid datagram. The actual packet source is checked even
after request validation, so DNS cannot authorize a different sender.

The relay bounds session/fragment state before allocation, checks the first
complete target before creating an outbound socket, and re-resolves plus
revalidates the destination on every outbound datagram. Replies are accepted
only from numeric destinations that the session previously approved and wrote
to successfully. This per-session destination set is capped at 256 entries and
never evicts an entry: after it fills, existing destinations remain usable but
new destinations fail closed. A failed socket write does not authorize its
source address for replies. UDP is unavailable when the relay uses
`--disable-udp`, when the client
selects a v1 transport, or when `auto` has only its TCP fallback path available.

### Loss signals are standard QUIC

Hysteria's congestion controller consumes ACKed/lost packet events from the
QUIC transport. Loss declaration itself follows RFC 9002: a packet-number
threshold of three, a time threshold of 9/8 of the relevant RTT estimate, and
PTO probes with exponential backoff. These mechanisms provide rapid standard
loss recovery; they are not advertised as Zeta-TCP's proprietary prediction or
reverse-control implementation.

### Cover and Salamander forms

In plain mode, the UDP endpoint is valid HTTP/3 and unauthenticated probes can
receive the cover site; Hysteria's Chrome-oriented QUIC handshake fingerprint
is enabled by default. Its signature list supports ECDSA P-256/P-384/RSA relay
certificates, not Ed25519. `--disable-chrome-parrot` exists for diagnostics and
is required for an Ed25519 relay certificate; X.509 verification remains
mandatory either way.

When both endpoints load the same `--obfs-password-file` (or
`AUTOCAR_OBFS_PASSWORD`), Salamander wraps the UDP packet connection. A normal
HTTP/3 client then cannot reach the inner cover handler. This is an alternate
obfuscated packet form, not HTTP/3 masquerading and obfuscation simultaneously
visible on the network. Salamander does not affect the separate TLS/TCP
fallback.

## AutoCAR wire protocol v1

Protocol v1 remains the TLS/TCP fallback format and the explicit legacy QUIC
format. It is implemented by `internal/protocol` and retained for controlled
migration and fallback, not used by default Hysteria UDP.

### Transport binding

Protocol v1 is carried over either:

- one bidirectional stream in a legacy QUIC v1 or v2 connection, or
- one TLS-over-TCP connection dedicated to a single proxied stream.

Both require TLS 1.3 and negotiate ALPN `autocar/1`. Normal X.509 chain and
DNS/IP SAN verification is mandatory. The server can additionally require an
mTLS client certificate. Legacy QUIC disables 0-RTT and QUIC DATAGRAM.

Each stream or TLS connection contains one CONNECT exchange followed by an
unframed TCP byte stream. Integers are unsigned and encoded in network byte
order (big endian).

### Common header

Every v1 request and response starts with this 12-byte header:

| Offset | Size | Field | Value |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `AUTO` (`0x4155544f`) |
| 4 | 1 | Version | `1` |
| 5 | 1 | Kind | `1` for CONNECT, `2` for response |
| 6 | 2 | Flags | Kind-specific value |
| 8 | 2 | Length 1 | Kind-specific body length |
| 10 | 2 | Length 2 | Kind-specific body length or zero |

Readers reject a bad magic value, unsupported version, unexpected kind, or a
length beyond its semantic limit before allocation.

### CONNECT request

| Header field | Meaning |
| --- | --- |
| Flags | Network: `1` = `tcp`, `2` = `tcp4`, `3` = `tcp6` |
| Length 1 | Shared-token byte length, 16 through 1024 |
| Length 2 | Destination byte length, 1 through 1024 |
| Body | Token bytes followed immediately by destination bytes |

The destination is a `host:port` value compatible with Go's
`net.SplitHostPort`. IPv6 literals use brackets, for example
`[2001:db8::1]:443`. NUL bytes are forbidden. Hostnames are preserved for
relay-side resolution.

The token is sent only inside the encrypted channel. The relay compares a
SHA-256 digest of the presented token with the configured digest using a
constant-time comparison. It is an authorization factor, not a replacement
for certificate verification.

### Response

| Header field | Meaning |
| --- | --- |
| Flags | Status code |
| Length 1 | Optional human-readable message length, 0 through 1024 |
| Length 2 | Reserved; must be zero |
| Body | Message bytes |

| Value | Name | Meaning |
| ---: | --- | --- |
| 0 | OK | Destination connection established |
| 1 | Bad request | Request framing or fields were invalid |
| 2 | Unauthorized | Shared-token authentication failed |
| 3 | Dial failed | Destination was unavailable or blocked by egress policy |
| 4 | Busy | Concurrent-stream capacity was exhausted |
| 5 | Internal | Reserved for a relay-side internal failure |

Relay errors avoid resolver, host-topology, and operating-system details. A
valid non-OK response is a remote error and does not trigger another transport.

### Relay phase and shutdown

After OK, both sides clear the handshake deadline and copy bytes without more
application framing. Backpressure comes from the underlying stream. Orderly
EOF is propagated as a half-close; a hard error aborts both directions.

Legacy QUIC maps each flow to a separate stream in one connection. The TCP
fallback creates one TLS 1.3 connection per flow and has no custom TCP
multiplexer. Protocol v1 carries TCP only.

## Wire migration

Before the Hysteria integration, `--transport=quic` meant AutoCAR v1. It now
means Hysteria v2. Upgrade both UDP endpoints together, or temporarily pin both
sides to the legacy names:

```sh
# Relay
autocar server [common options] --quic-engine=legacy

# Client
autocar client [common options] --transport=legacy-quic
```

Only one UDP engine can bind a given address. A staged migration can run the
new Hysteria engine on a second UDP port, then switch clients and finally
retire the old port. The TCP/TLS fallback remains protocol v1, so `auto` can
retain TCP reachability while the UDP endpoints are temporarily mismatched.

Any incompatible change to AutoCAR v1 requires a new version and ALPN. Hysteria
wire evolution follows its upstream protocol and the pinned module version.
