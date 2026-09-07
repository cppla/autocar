# Architecture

AutoCAR is a split proxy. It terminates local proxy connections and creates new
connections at an authenticated relay. The native preferred QUIC path avoids
nesting a reliable TCP stream inside another reliable TCP stream. The opt-in
web-cover path instead prioritizes normal HTTP compatibility: H3 is preferred,
with genuine HTTPS/H2 over TCP available when UDP is blocked.

```mermaid
flowchart LR
    A[Application] --> P[SOCKS5 / HTTP / HTTPS ingress]
    P --> C[AutoCAR client]
    C --> N{Selected mode}
    N -->|native: TLS 1.3 + QUIC, ALPN autocar/2| R[AutoCAR relay]
    N -. native TCP fallback: TLS 1.3, ALPN autocar/2 .-> R
    N -->|web: HTTP/3 over UDP; versioned client handshake profile| W[Web-cover relay]
    N -. web TCP fallback: HTTPS / HTTP/2 .-> W
    R --> E[Egress policy + remote DNS]
    W --> E
    E --> T[TCP or UDP target]
```

## Components

| Package | Responsibility |
| --- | --- |
| `internal/proxy` | Bounded SOCKS5 CONNECT/UDP ASSOCIATE and HTTP(S) proxy frontends |
| `internal/tunnel` | Native QUIC/TLS and web H2/H3 listeners, warm connection reuse, stream relay, authentication, pacing negotiation, fallback circuit breakers and UDP session runtime |
| `internal/cover` | Static or fixed-origin reverse-proxy handlers for ordinary H1/H2/H3 requests |
| `internal/protocol` | AutoCAR v2 request/response header and authentication metadata |
| `internal/datagram` | AutoCAR `ACDG` frame validation, fragmentation and bounded reassembly |
| `internal/accel` | Transport-neutral adaptive, bypass and fixed-rate application sender admission |
| `internal/security` | TLS policy, secrets, remote resolution and SSRF/port/CIDR enforcement |
| `internal/transport` | Small TCP and packet interfaces shared by frontends |

The native transport uses upstream `github.com/quic-go/quic-go` v0.61.0. Web H3
uses the `github.com/apernet/quic-go` fork, pinned exactly to
`v0.61.1-0.20260806010916-184d081eef3e`, because its client-only ChromeParrot
profile controls the TLS ClientHello, QUIC transport parameters, connection IDs
and Initial packetization as one coherent handshake. AutoCAR explicitly supplies
a zero-length client source connection ID for that profile.

This is a transparent implementation dependency, not third-party proxy wire
compatibility: AutoCAR does not import an external proxy application module; its
authentication, CONNECT semantics and payload transport remain AutoCAR's. The
dependency-boundary check permits only the exact fork version above, rejects
local replacement or copied/vendored source trees, and scans tracked and
untracked Go source for the known disallowed proxy application-module import.

## Native TCP flow

1. The local frontend authenticates the local user when configured and parses
   one bounded request.
2. The client opens a bidirectional QUIC stream on a shared connection.
3. It writes an `autocar/2` CONNECT request containing the relay token, target,
   sender metadata and optional rate hints.
4. The relay authenticates before dialing. Its safe dialer resolves the name,
   rejects unsafe addresses/ports, and dials only approved numeric IPs.
5. A bounded response confirms the target and reports effective pacing in both
   directions. Only then does raw byte relay begin.
6. EOF is half-closed when possible; hard errors abort both copy directions.

QUIC streams are independent. Canceling a slow open or one flow does not close
sibling flows. A per-connection pacer sees aggregate QUIC statistics, so
concurrent streams share one path estimate rather than each overestimating the
same bottleneck.

## Web-cover TCP flow

The web-cover server binds TCP and UDP on the same numeric port. Its TCP side
serves normal HTTPS using HTTP/1.1 and HTTP/2; its UDP side serves normal
HTTP/3. HTTP/1.1 is cover-only. H2 and H3 CONNECT requests become tunnels only
after credentials bound to their physical TLS or QUIC connection are verified.

1. Exactly one client caller leads authentication of a new physical connection.
   It sends the original 385-to-2,047-byte full bearer, including the timestamp,
   16-byte client nonce, and 206 to 1,453 bytes of authenticated random padding.
   Other callers wait before opening their request streams.
2. The server verifies the full bearer and global nonce-replay state before
   acquiring stream admission or performing DNS/dial work. It returns a
   54-byte, status-bound bootstrap proof containing a fresh server nonce.
3. Both peers derive a connection key with HKDF-SHA-256 over the web key and
   both nonces. Later CONNECT streams use an exact 41-byte sequenced bearer and
   receive an exact 44-byte response proof instead of padded per-stream values.
4. The server accepts each nonzero, monotonically allocated `uint64` sequence
   once through a 128-position out-of-order replay window. H3 TCP CONNECT and
   CONNECT-UDP share the same state on one `*quic.Conn`.
5. A missing, malformed, expired, wrong-key, or replayed credential is stripped
   and routed to the same cover handler as ordinary web traffic without the
   server proactively closing that connection.
6. A valid request passes through the same safe remote resolver and destination
   policy as native mode. The client verifies the status-bound response proof
   before the stream becomes full-duplex. An authenticated `4xx` or `5xx` on the
   leader also completes bootstrap before its application error is returned.

An ambiguous bootstrap proof makes the client close the complete physical
connection and wake waiters to select a replacement. Reconnects and the new H2
connection selected after GOAWAY run the full bootstrap again. QUIC migration or
NAT rebinding that remains the same `*quic.Conn` retains authentication state.

The cover is either a local static directory or a reverse proxy to one fixed,
operator-authorized HTTP(S) origin. TCP cover responses advertise the bound H3
service through `Alt-Svc`. Neither the cover nor an unauthenticated probe sees
the `autocar/2` ALPN or native binary request header. This reduces active-probe
exposure but does not prove browser-indistinguishable passive behavior; see
[WEB_COVER.md](WEB_COVER.md).

The public H1/H2 listener accepts TLS 1.2 and TLS 1.3 for ordinary website
compatibility, while AutoCAR H2 clients and authenticated H2 tunnels require
TLS 1.3. The handler rejects TLS 1.2 from the tunnel path before ticket
verification, strips any credential, and delegates the request to the cover.
H3 remains TLS 1.3-only.

The default web H3 client profile is the immutable `chrome-2026-08` profile. It
enables the pinned fork's full client handshake image and a zero-length source
CID, and locks the outer packet version to QUIC v1 so it agrees with the fixed
version-information transport parameter. `--h3-fingerprint=native` disables ChromeParrot within that same web-H3
fork for interoperability and rollback; it does not select the native
`autocar/2` transport. ChromeParrot is client-only: the relay remains an ordinary
QUIC/H3 server, and H3 SETTINGS, CONNECT requests, application traffic and timing
are outside the handshake profile. H2 independently uses a fixed Chrome 133
ClientHello but retains the Go HTTP/2 stack.

## Native UDP association

SOCKS5 UDP ASSOCIATE asks the tunnel client for a `transport.PacketConn`. The
client opens an authenticated `NetworkUDP` control stream with a random nonzero
request nonce. The relay allocates an independent, nonzero session ID scoped to
that QUIC connection and returns it in the successful response. Payloads use the
assigned ID and travel as QUIC DATAGRAM frames, not on that reliable stream.

Every fragment repeats its session, message, direction and address metadata.
The receiver rejects inconsistent duplicates and caps payload, fragment count,
incomplete messages, buffered bytes and lifetime. On the relay, each association
owns a UDP socket and may return traffic only from destinations previously
requested by that session. Closing the SOCKS control connection closes the
AutoCAR control stream and unblocks both receive loops.

UDP has no TLS/TCP fallback. Explicit `tls` mode therefore does not advertise
SOCKS5 UDP ASSOCIATE. `auto` does advertise it, but an association always makes a
QUIC attempt and fails if QUIC is unavailable; the TCP fallback circuit applies
only to new TCP flows.

## Web-cover UDP association

`web-auto` and explicit `h3` expose `transport.PacketDialer` through RFC 9298
CONNECT-UDP. Explicit `h2` does not. A SOCKS5 UDP association presents one
logical PacketConn, but the H3 implementation creates one authenticated request
stream lazily for each normalized target and reuses that stream for later
datagrams to the same target.

The HMAC ticket binds the H3 origin, Extended CONNECT protocol, and default
MASQUE target path. After authentication, the relay parses the target, applies
the same UDP resolver policy, freezes one successfully dialed numeric endpoint,
and connects one UDP socket to it. HTTP Datagrams use Context ID `0`; target
streams and receive queues are bounded on both client and relay. Closing a
stream closes its socket and releases stream and UDP-session admission.

CONNECT-UDP is H3-only and has no Capsule payload fallback in this version.
Payloads are limited to 1,150 bytes and are not fragmented. Web UDP does not use
the native `ACDG` format or its 4,096-byte logical-message reassembly.

## Automatic fallback

The two automatic modes have separate wire contracts.

### Native `auto`

`auto` keeps QUIC primary and a separate TCP/TLS dialer as fallback. The whole
QUIC attempt—including an existing stream waiting for its protocol response—has
a budget. On an unclassified QUIC-phase failure or timeout, the client opens a
circuit for a cooldown:

- new TCP flows use TLS without repeating the UDP timeout;
- after cooldown, exactly one caller probes QUIC;
- destination rejection or authentication-aware remote errors do not mark the
  QUIC transport dead;
- an individual canceled stream does not tear down the shared connection.

Fallback never weakens certificate or token validation and does not carry UDP.

### Web `web-auto`

`web-auto` uses standard H3 CONNECT as primary and standard H2 CONNECT as its
TCP fallback on the same host and numeric port. The entire H3 open attempt has
a budget. A transport failure opens a cooldown during which new TCP flows go
directly to H2. The configured cooldown is a base randomized by +/-20% per
failure to avoid synchronized fixed-period probes; after it, exactly one caller
probes H3 while other callers remain on H2. A valid, authenticated HTTP error
is positive evidence that H3 is alive and is not reclassified as a transport
failure.

The most recent authenticated success is reported as `h3` or `h2`. H2 fallback
does not weaken certificate or connection-scoped HMAC validation and must not
be treated as a generic UDP-over-TCP fallback. Web SOCKS5 UDP always requires
H3 CONNECT-UDP; it fails rather than crossing the H2 circuit.

## Sender layering

AutoCAR's native sender admission sits above upstream quic-go. `adaptive` observes public
connection statistics and delays application writes; `fixed-rate` uses a token
bucket; `reno` bypasses this layer. These modes and their negotiated rate metadata
apply only to QUIC. A TCP flow taken by `auto`'s TLS fallback is unpaced; explicit
`tls` with fixed-rate is rejected. The selected QUIC library continues to own
congestion control, packetization, ACK handling and RFC 9002 recovery: upstream
quic-go for native, and the pinned fork for web H3.

Web H2/H3 streams do not use the native pacing negotiation and report client
and relay pacing as `not-applicable`. Fixed-rate is rejected with
`web-auto`, `h3`, and `h2`.

This architecture deliberately avoids claims of an injected replacement
transport controller. See [ACCELERATION.md](ACCELERATION.md).

## Resource and trust boundaries

- AutoCAR TLS client configuration is cloned and forced to TLS 1.3; the web
  server's TLS 1.2 allowance applies only to public TCP cover requests.
  `InsecureSkipVerify` is rejected. Native mode assigns only `autocar/2`; web
  mode assigns the standard `h2` or `h3` ALPN and the relay also offers
  `http/1.1` for cover traffic.
- The relay hashes tokens before constant-time comparison, bounding token length
  before hashing.
- Web mode derives a separate HMAC key and uses one padded timestamp/nonce full
  ticket on each physical H2/H3 connection. A 54-byte server-nonce proof derives
  a connection key; later streams use 41-byte sequenced tickets and 44-byte
  status-bound proofs with a 128-position replay window. Invalid credentials are
  handled as cover requests before DNS or destination dialing.
- Native global/per-source connection limits and all authenticated tunnel stream
  budgets are acquired before starting destination work. Public cover requests
  still need conventional HTTP rate/connection controls.
- Handshake, open, destination dial and incomplete-reassembly time are bounded.
  QUIC has a transport idle timeout, but keepalive can preserve an authenticated
  warm connection; live streams and UDP leases last until their control stream
  or connection closes and are bounded by count rather than a session idle TTL.
- Remote error messages are stable and do not disclose resolver or host details.
- Proxy plaintext credentials are not allowed on a non-loopback listener unless
  the operator explicitly opts in.
- Native mode may require mTLS. Web mode rejects mTLS because a normal public
  cover must complete TLS without a client certificate.
- Web CONNECT-UDP has bounded global/per-source server sessions,
  client-global/per-PacketConn target sessions, and receive queues. The relay
  accepts replies only from the connected numeric target.

The relay remains a trusted endpoint: it sees requested destinations and the
plaintext of applications that do not provide their own end-to-end encryption.
