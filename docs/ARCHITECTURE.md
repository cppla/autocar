# Architecture

AutoCAR is a split proxy. It terminates local proxy connections, creates new
connections at an authenticated relay, and never nests a reliable TCP stream
inside another reliable TCP stream on the preferred path.

```mermaid
flowchart LR
    A[Application] --> P[SOCKS5 / HTTP / HTTPS ingress]
    P --> C[AutoCAR client]
    C -->|TLS 1.3 + QUIC, ALPN autocar/2| R[AutoCAR relay]
    C -. new TCP flows when UDP path is unavailable .->|TLS 1.3 / TCP| R
    R --> E[Egress policy + remote DNS]
    E --> T[TCP or UDP target]
```

## Components

| Package | Responsibility |
| --- | --- |
| `internal/proxy` | Bounded SOCKS5 CONNECT/UDP ASSOCIATE and HTTP(S) proxy frontends |
| `internal/tunnel` | QUIC/TLS listeners, warm connection reuse, stream relay, pacing negotiation, fallback circuit breaker and UDP session runtime |
| `internal/protocol` | AutoCAR v2 request/response header and authentication metadata |
| `internal/datagram` | AutoCAR `ACDG` frame validation, fragmentation and bounded reassembly |
| `internal/accel` | Transport-neutral adaptive, bypass and fixed-rate application sender admission |
| `internal/security` | TLS policy, secrets, remote resolution and SSRF/port/CIDR enforcement |
| `internal/transport` | Small TCP and packet interfaces shared by frontends |

The build graph uses `github.com/quic-go/quic-go`. A dependency-boundary check
rejects known Hysteria/apernet modules, local module replacements and known
external-source directory paths.

## TCP flow

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

## UDP association

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

## Automatic fallback

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

## Sender layering

AutoCAR's sender admission sits above quic-go. `adaptive` observes public
connection statistics and delays application writes; `fixed-rate` uses a token
bucket; `reno` bypasses this layer. These modes and their negotiated rate metadata
apply only to QUIC. A TCP flow taken by `auto`'s TLS fallback is unpaced; explicit
`tls` with fixed-rate is rejected. quic-go continues to own congestion control,
packetization, ACK handling and RFC 9002 recovery on QUIC in every mode.

This architecture deliberately avoids claims of an injected BBR/Brutal
transport controller. See [ACCELERATION.md](ACCELERATION.md).

## Resource and trust boundaries

- TLS client configuration is cloned, forced to TLS 1.3 and assigned only the
  `autocar/2` ALPN. `InsecureSkipVerify` is rejected.
- The relay hashes tokens before constant-time comparison, bounding token length
  before hashing.
- Global and per-source connection/session limits are acquired before starting
  attacker-controlled work.
- Handshake, open, destination dial and incomplete-reassembly time are bounded.
  QUIC has a transport idle timeout, but keepalive can preserve an authenticated
  warm connection; live streams and UDP leases last until their control stream
  or connection closes and are bounded by count rather than a session idle TTL.
- Remote error messages are stable and do not disclose resolver or host details.
- Proxy plaintext credentials are not allowed on a non-loopback listener unless
  the operator explicitly opts in.

The relay remains a trusted endpoint: it sees requested destinations and the
plaintext of applications that do not provide their own end-to-end encryption.
