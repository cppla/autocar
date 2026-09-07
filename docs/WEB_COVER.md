# Web-cover mode

AutoCAR v1.0.1 introduces an opt-in `web` relay mode for deployments that need
a genuine HTTPS origin and reliable TCP service across both UDP-capable and
UDP-blocked networks. It is intended for lawful privacy, normal website
compatibility, and service continuity on infrastructure the operator owns or is
authorized to use.

It is not an “undetectable” mode. Standard HTTP does not make all TLS, QUIC,
HTTP framing, packet-size, timing, traffic-volume, endpoint, or application
patterns identical to a browser. Do not use this feature to scan third-party
systems, bypass authorization, or impersonate a site you do not control.

## What is on the wire

One domain and one numeric port provide two ordinary web transports:

| Network path | Public cover | Authenticated tunnel |
| --- | --- | --- |
| TCP | HTTPS with HTTP/1.1 and HTTP/2 over TLS 1.2 or 1.3 | TLS 1.3-only HTTP/2 `CONNECT` for TCP |
| UDP | HTTP/3 over TLS 1.3 | standard HTTP/3 `CONNECT` for TCP; RFC 9298 `CONNECT-UDP` with HTTP Datagrams for UDP |

HTTP/1.1 is a cover-only protocol; it is never upgraded into an AutoCAR
tunnel. HTTP/1.1 and HTTP/2 cover responses advertise the bound HTTP/3 service
with `Alt-Svc`. The H2 and H3 clients reuse warm connections and multiplex
independent CONNECT streams. AutoCAR's H2 client requires TLS 1.3. A TLS 1.2
HTTP/2 CONNECT presented to the public origin is always treated as cover,
including when it carries an otherwise valid ticket: the handler removes
`Proxy-Authorization` before delegation and never dials its authority.

There is no `autocar/2` ALPN or AutoCAR binary stream header on these paths.
The web ALPNs are `h2`, `h3`, and `http/1.1`. Native and web transports remain
separate modes and are not wire-compatible.

## Relay configuration

The relay requires exactly one cover source.

### Static directory

```bash
./autocar server \
  --protocol web \
  --listen :443 \
  --tcp-listen :443 \
  --cover-root /srv/www \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

The static handler serves `GET` and `HEAD`. Other methods receive the same
ordinary `405 Method Not Allowed` behavior whether they came from a random web
client or from an invalid tunnel probe.

### Fixed upstream origin

```bash
./autocar server \
  --protocol web \
  --listen :443 \
  --tcp-listen :443 \
  --cover-upstream https://origin.example.net \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

The upstream must be a fixed `http://` or `https://` origin that you are
authorized to proxy. The requester may choose the path, query, and ordinary
end-to-end headers, but cannot choose the upstream authority. The proxy rewrites
`Host` to the configured origin and removes `Authorization`,
`Proxy-Authorization`, and hop-by-hop headers. It returns a generic `502` if
the upstream cannot be reached. Consequently, an upstream that requires an
`Authorization` request header is not suitable without a separate authorized
front end.

In web mode:

- `--listen` is the UDP/H3 bind address and `--tcp-listen` is the TCP/H1/H2
  bind address; if omitted, `--tcp-listen` inherits `--listen`;
- TCP and UDP must use the same numeric port;
- `--disable-tcp-fallback` is rejected because H2/TCP is part of the mode's
  reliability contract;
- `--client-ca` is rejected because a normal public cover must be reachable
  without a TLS client certificate;
- the public TCP cover accepts TLS 1.2 through TLS 1.3, while authenticated H2
  tunnels and H3 remain TLS 1.3-only; and
- the normal destination policy still resolves remotely and rejects disallowed
  IP ranges and ports before opening an egress socket.

Use a certificate whose SAN covers the client-visible domain. A publicly
trusted certificate and meaningful site content usually provide better normal
web compatibility than a self-signed certificate and an empty directory, but
certificate trust is an operator choice, not an AutoCAR bypass: clients must
still explicitly choose `--ca` or `--system-roots`.

## Client transports

Recommended configuration:

```bash
./autocar client \
  --server relay.example.com:443 \
  --system-roots \
  --token-file /etc/autocar/relay-token \
  --transport web-auto \
  --h3-fingerprint chrome-2026-08 \
  --quic-attempt-timeout 5s \
  --open-timeout 15s \
  --fallback-cooldown 30s
```

The three web transport choices are:

| `--transport` | Behavior |
| --- | --- |
| `web-auto` | For TCP, try H3 first and use H2 during an H3-failure cooldown; for UDP, require H3 CONNECT-UDP with no H2 fallback |
| `h3` | Require HTTP/3 over UDP for TCP CONNECT and CONNECT-UDP; no H2 fallback |
| `h2` | Require HTTPS/HTTP/2 over TCP CONNECT; no H3 attempt and no UDP support |

`--h3-fingerprint=chrome-2026-08` is the default for `web-auto` and `h3`. It
enables the fixed full client QUIC/TLS handshake profile and zero-length source
CID supplied by the pinned `github.com/apernet/quic-go` fork. The profile is
locked to QUIC v1 because its fixed version-information transport parameter is
part of that v1 handshake image.
`--h3-fingerprint=native` disables ChromeParrot inside that same fork as an
explicit interoperability and rollback choice. Here `native` names only the H3
fingerprint fallback; it does not select AutoCAR's native `autocar/2` protocol.

For `web-auto`, `0 < --quic-attempt-timeout < --open-timeout` is required.
When the relay name resolves to both address families, H3 interleaves IPv6 and
IPv4 candidates and starts them with a short stagger; each candidate retains
its own UDP socket so a blackholed first address cannot consume the entire H3
budget before a working family is tried.
After a failed H3 attempt, new TCP streams avoid repeating the UDP timeout.
`--fallback-cooldown` is a base duration; each failure independently selects a
retry point within +/-20% so clients do not probe in a fixed synchronized
cadence. Once that interval expires, exactly one concurrent caller probes H3
while the others continue over H2. An authenticated target rejection is
evidence that H3 itself is alive, so it is returned to the caller rather than
retried over H2.

`--fallback-server` belongs only to native `--transport=auto` and is rejected
for web transports. H3 and H2 use the same `--server` host and port. Web
transports do not accept `--client-cert`/`--client-key`. Native application
pacing negotiation does not apply to H2 or H3 web streams; diagnostics report
both pacing fields as `not-applicable`, and `--pacing=fixed-rate` is rejected.

`web-auto` and explicit `h3` expose SOCKS5 UDP through H3 CONNECT-UDP. Explicit
`h2` does not advertise UDP. The H3-to-H2 fallback carries only new TCP
streams: UDP never falls back to H2 and fails when H3 is unavailable.

## CONNECT-UDP boundary

The H3 UDP path follows
[RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html)'s Extended CONNECT
shape:

- `:protocol` is `connect-udp`;
- the URI uses the default
  `/.well-known/masque/udp/{target_host}/{target_port}/` template;
- `Capsule-Protocol` is negotiated as `?1`; and
- each HTTP Datagram starts with Context ID `0`.

One normalized UDP target owns one H3 request stream and one connected relay
UDP socket. A logical SOCKS5 association opens target streams lazily and reuses
the stream for later datagrams to the same target. Target count, client-global
and server-global session count, per-source server sessions, and receive queues
are bounded. The relay applies the UDP destination policy, resolves once, and
freezes the session to one successfully opened numeric endpoint; replies from
other sources cannot enter that target stream.

The current maximum UDP payload is 1,150 bytes. This leaves room in the
mandatory 1,200-byte QUIC path for QUIC and DATAGRAM framing, the HTTP
quarter-stream ID, and Context ID `0`. A larger logical payload would not be
portable to a minimum-MTU path. Oversized payloads are rejected. This
implementation does not fragment CONNECT-UDP payloads and does
not implement a Capsule data fallback, so it requires negotiated H3 HTTP
Datagrams. These limits are intentionally different from native mode's `ACDG`
fragmentation and 4,096-byte logical payload.

## Per-connection authentication

The configured relay token is input to HKDF-SHA-256, producing a key dedicated
to web-cover authentication. The first AutoCAR CONNECT or CONNECT-UDP opening
attempt on each physical H2/TLS or H3/QUIC connection is the sole bootstrap
leader. It uses the original bounded bearer with a timestamp, a
cryptographically random 16-byte client nonce, and 206 to 1,453 bytes of
authenticated random padding. After the `Bearer ` prefix and base64url
encoding, the complete `Proxy-Authorization` value ranges from 385 to 2,047
bytes. Other concurrent callers wait for this exchange instead of sending
another full bearer.

The server answers a valid bootstrap with an exact 54-byte
`Proxy-Authentication-Info` value. It contains a fresh 16-byte server nonce and
a 16-byte truncated HMAC-SHA-256 tag in `nextnonce=<base64url>` form. The proof
binds the full request, authenticated claims, and HTTP status. A valid signed
`400`, `502`, or `503` therefore establishes the connection just like a `200`;
the client installs authentication state before returning that HTTP error.

Both sides use the client and server nonces with HKDF-SHA-256 to derive a
256-bit key scoped to that physical connection. Each later CONNECT or
CONNECT-UDP sends an exact 41-byte `Bearer` value containing version, a nonzero
big-endian `uint64` sequence, and a 16-byte request tag. Its exact 44-byte
response proof contains the same version and sequence plus a status-bound tag.
The client allocates sequence numbers monotonically across concurrent streams;
the server's 128-position sliding bitmap accepts bounded out-of-order arrival
once and rejects duplicates and values that have fallen behind the window.
Ticket allocation waits when a new sequence would overtake the oldest
unresolved authentication exchange by 128 positions. This wait respects the
request deadline and connection closure; established streams do not retain a
ticket reservation. H2 CONNECT, H3 CONNECT and CONNECT-UDP use the same rule.

The state belongs to the actual `*tls.Conn` or `*quic.Conn`. H3 TCP CONNECT and
CONNECT-UDP therefore share one sequence space and key. A reconnect, TLS/QUIC
resumption onto a replacement connection, or the connection opened after H2
GOAWAY performs a new full bootstrap. A QUIC path migration that remains the
same QUIC connection retains the existing state.

The full ticket's clock window remains 60 seconds in either direction, and
accepted full-ticket nonces remain in the bounded server-wide H2/H3 replay
cache for that complete window. A duplicate, expired, malformed, wrong-key,
over-capacity, or invalid continuation credential is not treated as a tunnel
request. AutoCAR removes `Proxy-Authorization` and passes the request to the
configured cover handler without proactively closing the server connection or
sending an authentication challenge. Authentication still completes before
stream admission, DNS resolution, or destination dialing.

The client accepts exactly one status-bound bootstrap or continuation proof
before exposing a stream. A missing, duplicate, malformed, or mismatched proof
makes the connection state ambiguous, so it closes the entire physical
connection and wakes bootstrap waiters to select a replacement.

This behavior reduces the information available to unauthenticated active
probes; it does not make passive traffic analysis impossible. Server and client
clocks must be synchronized closely enough to satisfy the acceptance window.

## Fingerprint boundary

The H3 client uses the fixed `chrome-2026-08` profile by default. AutoCAR obtains
that profile from the `github.com/apernet/quic-go` fork,
pinned to `v0.61.1-0.20260806010916-184d081eef3e`. It applies the fork's
ChromeParrot client handshake image—including ClientHello, client transport
parameters and Initial packetization—and uses a zero-length client source CID.
ChromeParrot is client-only: it does not turn the AutoCAR relay into a particular
Chrome-facing CDN/server implementation, and it does not make H3 SETTINGS,
CONNECT/authentication traffic, packet sizes, connection reuse or timing match
Chrome. The `native` rollback profile disables this client image.

The H2 client separately uses the fixed `chrome-133` uTLS ClientHello profile.
That describes only its TLS ClientHello; H2 settings, header order, flow control,
connection reuse, payload sizes and timing retain their implementation behavior.
Authenticated H2 and H3 CONNECT requests explicitly suppress the Go HTTP
libraries' default `User-Agent` and automatic `Accept-Encoding: gzip` values.
AutoCAR does not invent browser headers until the complete request-header set
and ordering have been measured and implemented as one coherent profile.

Using the same maintained handshake implementation as the comparator removes
some known stock-QUIC differences, but it is not independent evidence of a
classification advantage and does not make the two application protocols wire
compatible. Therefore the project does not claim that web-cover traffic is
indistinguishable from a browser. A defensible result requires a versioned,
reproducible capture and a classifier evaluated on held-out runs. Until such a
gate passes, passive-fingerprint superiority is unproven.

The frozen comparison corpus, safety boundary, minimum sample counts, and
decision rule are specified in
[STEALTH-BENCHMARK.md](STEALTH-BENCHMARK.md). A smoke run validates the tools;
it is not a comparative result.

## Transport continuity and validation limits

AutoCAR can present one functioning web origin across normal H1/H2 over TCP and H3 over
UDP, while `web-auto` can keep new TCP proxy flows working through genuine H2
when the UDP path is blocked. This fallback applies to new TCP proxy flows;
it does not move UDP datagrams to H2 or migrate an established application stream.

Transport continuity does not establish browser indistinguishability or a
passive-fingerprint advantage. Any evaluation must pin its binaries and
configuration, serve equivalent cover content, separate active-probe behavior
from passive classification, and report failures and confidence intervals
rather than turn a single successful run into a product claim.

The dependency relationship must remain explicit in such a report: AutoCAR web
H3 uses the pinned QUIC fork's client profile. Shared implementation details
are part of provenance, not independent evidence of anti-identification quality.

## Safe validation

Validate only on loopback, an isolated Docker network, or machines and domains
you own or are explicitly authorized to test. Do not point probe tools at
unrelated public addresses.

```bash
# Confirm the public TCP cover and advertised H3 endpoint.
curl --http1.1 https://relay.example.com/
curl --http2 https://relay.example.com/

# Confirm each authenticated TCP path.
./autocar doctor [connection flags] --transport h3 \
  --target example.com:443 --json
./autocar doctor [connection flags] --transport h2 \
  --target example.com:443 --json

# Confirm automatic selection under the deployment's own UDP-block test.
./autocar doctor [connection flags] --transport web-auto \
  --target example.com:443 --json
```

`doctor` opens an authenticated target TCP connection and reports the path that
actually succeeded. It does not prove application correctness, browser
indistinguishability, or comparative resistance to classification. When
testing UDP failure, apply packet filtering only inside an isolated namespace,
container network, or dedicated test host; do not alter a shared production
host's firewall.

For CONNECT-UDP, use an owned UDP echo or DNS fixture inside the same isolated
lab and test both `h3` and `web-auto`. Then block only the lab's UDP forwarding
and verify that TCP uses H2 while the UDP association fails; H2 success is not
evidence of UDP fallback.
