# Security policy

## Supported versions

The latest stable release in the `v1.x` series and the latest commit on `main`
receive security fixes. Versions before `v1.0.0` and development snapshots are
not supported. This policy will be updated when a later major series is
released.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting for this repository and include the affected commit,
reproduction, impact and suggested mitigation.

## Guarantees

AutoCAR protects every authenticated client-to-relay tunnel with TLS 1.3.
Native QUIC and TCP fallback use the `autocar/2` ALPN. Web-cover uses standard
`h3`, `h2`, and cover-only `http/1.1` ALPNs with connection-scoped HMAC
credentials. Its public TCP origin accepts TLS 1.2 and TLS 1.3 for ordinary
website compatibility, but only a TLS 1.3 H2 request can enter the tunnel path;
every TLS 1.2 request remains cover traffic. H3 inherently uses TLS 1.3. The
client rejects `InsecureSkipVerify`; a pinned/private CA or explicitly selected
system roots are required. Native mode may additionally require mTLS. Web mode
cannot require mTLS because its public cover must finish TLS without a client
certificate. QUIC 0-RTT is disabled in both modes.

Assuming the endpoints, configured trust roots, private keys, relay token and
dependencies are not compromised, TLS provides confidentiality, integrity and
relay identity against network attackers. End-to-end HTTPS remains encrypted
between the application and destination.

## Limits

AutoCAR does not hide endpoint IPs, packet size, timing, traffic volume, or the
use of QUIC/TLS. Web mode serves a real configured H1/H2/H3 origin and routes
unauthenticated requests through that cover, but normal HTTP semantics do not
make all observable behavior identical to a browser. The H2 client uses a fixed
Chrome 133 uTLS ClientHello reference; that is not a claim about the complete
TLS/H2 fingerprint. Web H3 defaults to the fixed `chrome-2026-08` client
handshake profile from the exactly pinned `github.com/apernet/quic-go` fork and
uses a zero-length source CID. That client-only profile does not reproduce the
relay, H3 SETTINGS, CONNECT traffic, packet sizes, reuse, or timing. Sharing the
implementation with a comparator is not proof of a classification advantage.
AutoCAR makes no undetectability guarantee.

The relay sees destination metadata and any destination protocol that lacks its
own encryption. A client holding the shared token can distinguish authenticated
tunnel responses from cover traffic. A sufficiently capable passive observer
may distinguish implementations through TLS/QUIC/HTTP details, packet shapes,
timing, connection reuse, or traffic analysis. Active-probe cover behavior does
not eliminate those signals.

The relay is an authenticated proxy, not a tenant sandbox. Application limits
reduce accidental and straightforward resource exhaustion but do not replace
host firewall, cgroup, file-descriptor, memory, CPU and per-source rate limits.

Application-layer pacing is cooperative. An authenticated modified client can
ignore its local rate. Use a host or cloud policer for security/accounting
limits. Negotiated adaptive/fixed-rate pacing applies only to QUIC; a TCP flow
taken by `auto`'s TLS fallback is unpaced and must not be treated as a quota.

Web H2/H3 streams do not use native pacing negotiation. The H3-to-H2 policy is
for new TCP CONNECT streams and must not be described as a generic UDP-over-TCP
fallback.

## Destination policy

The relay resolves names itself and gives the underlying dialer only approved
numeric addresses. By default it rejects:

- loopback, link-local, multicast and unspecified addresses;
- private/ULA/CGNAT addresses unless explicitly enabled;
- IANA translation, documentation, benchmarking, reserved and other
  special-purpose ranges;
- SMTP submission ports 25, 465 and 587;
- operator-supplied denied CIDRs and ports.

This prevents an approved name from being resolved a second time into a local
service. `--allow-private` never permits loopback, link-local or built-in
special-use/control-plane ranges. Operators should add provider-specific
metadata/control-plane addresses to `--deny-cidrs` before serving untrusted
clients.

The same resolver policy applies to every UDP destination. A native UDP
association records a bounded set of successfully requested numeric
destinations and forwards replies only from that set. A web CONNECT-UDP target
stream resolves once and connects its socket to one approved numeric endpoint.
In both cases, replies from unrelated sources are excluded.

## SOCKS5 UDP boundary

The local UDP relay accepts packets only from the IP of its associated TCP
control connection. A concrete UDP ASSOCIATE address must match that peer; a
domain must resolve to it. A nonzero requested source port is pinned, while port
zero pins the first valid sender. RFC 1928 UDP fragments are dropped rather than
silently combined.

Native mode's logical payload limit is 4,096 bytes. Every native AutoCAR
fragment carries its own address metadata. Fragment count, incomplete messages,
buffered bytes and TTL are bounded before attacker-controlled allocation;
conflicting fragments purge the assembly.

Web mode uses H3 RFC 9298 CONNECT-UDP with HTTP Datagram Context ID `0`. It
limits a payload to 1,150 bytes and does not fragment it or fall back to Capsule
data. Each normalized target owns a separate authenticated request stream and a
connected relay UDP socket. Target streams, global and per-source server
sessions, client sessions, and receive queues are bounded. H2 never carries UDP,
so `web-auto` UDP fails if H3 or HTTP Datagram negotiation is unavailable.

## Authentication and error handling

Tokens must be 16–1,024 bytes. In native mode, the relay hashes the bounded
presented token and uses a constant-time digest comparison. It authenticates
every stream before destination resolution or UDP session allocation. Invalid
native requests receive bounded, neutral errors; resolver and operating-system
details are not exposed.

Web mode does not send the shared token directly in an HTTP header. It derives a
separate key with HKDF-SHA-256. Exactly one leader on each physical H2/TLS or
H3/QUIC connection sends the bounded, variable-size full HMAC-SHA-256 bearer.
It includes 206 to 1,453 bytes of cryptographically random padding and a fresh
16-byte client nonce; the complete `Proxy-Authorization` value is 385 to 2,047
bytes. Its MAC also covers the transport, method, extended-CONNECT protocol/path,
normalized authority, timestamp, bounded metadata, ticket version, and padding.

The server returns a 54-byte bootstrap proof with a fresh 16-byte server nonce
and a status-bound 16-byte tag. Both peers use HKDF-SHA-256 over the web key and
the two nonces to derive a key scoped to that physical connection. Subsequent
CONNECT and CONNECT-UDP streams send an exact 41-byte bearer containing a
strictly increasing, nonzero `uint64` sequence and receive an exact 44-byte
status-bound proof. The server's 128-position sliding replay bitmap admits
concurrent out-of-order sequences once, while rejecting duplicates and values
older than its retained window.

The full ticket timestamp window is plus or minus 60 seconds. Accepted full
nonces share a bounded H2/H3 replay cache and remain present for the complete
acceptance window; a replay or full cache fails into cover. H3 TCP CONNECT and
CONNECT-UDP share state on the actual QUIC connection. Replacement connections,
including after H2 GOAWAY or TLS/QUIC resumption, require another full bootstrap;
a path migration that remains the same QUIC connection does not.

The tunnel handler checks the TLS version before attempting H2 ticket
authentication. A TLS 1.2 CONNECT, including one carrying an otherwise valid
ticket, has its `Proxy-Authorization` field removed and is delegated to the
configured cover. It cannot consume tunnel admission or trigger destination
resolution.

Authenticated responses carry exactly one `Proxy-Authentication-Info` value:
54 bytes for the bootstrap and 44 bytes for each continuation. An authenticated
`4xx` or `5xx` still completes the bootstrap before the client reports the HTTP
error. The client closes the whole physical connection if the required proof is
missing, duplicated, malformed, or mismatched, because its connection state is
then ambiguous.

A missing, malformed, expired, replayed, or wrong-key full or continuation
ticket is stripped from the request before the request enters the configured
cover handler. The server does not proactively close the connection, issue a
proxy-authentication challenge, or return an AutoCAR-specific authentication
error for that miss. Authentication still precedes admission, DNS resolution,
and destination dialing. This reduces an unauthenticated active probe's oracle;
it is not proof of browser indistinguishability or passive-fingerprint
resistance. Treat
`Proxy-Authorization` and `Proxy-Authentication-Info` as secrets and keep them
out of access logs and upstream requests.

For an authenticated, well-formed web request, runtime admission exhaustion is
reported as generic HTTP `503` and destination failure as generic HTTP `502`.
Authenticated malformed CONNECT-UDP semantics receive a generic `400`. These
statuses reveal state to a token holder, which is expected: the relay token is
an authorization secret, not a public camouflage value.

On Unix, the TLS private key must be a regular file with mode exactly `0600`.
Token and password files must be regular and have no group/other permission bits
(`0600` or stricter). Each file and its parent directory must be readable and
traversable by the actual runtime user; a root-owned `0600` secret is not usable
by an unprivileged `autocar` service. Generate independent high-entropy secrets
with `autocar token`; do not reuse relay, local proxy and other credentials.

## Resource controls

- Native QUIC and TLS listeners have global and per-source connection limits.
  IPv4 is keyed by address; IPv6 is grouped by `/64` to resist interface-ID
  rotation. Web cover traffic needs conventional HTTP connection/rate controls
  at the host or front end in addition to the shared tunnel-stream admission.
- Native QUIC pre-authentication lifetime, native protocol headers, web tunnel
  request headers, and destination dials are bounded. Ordinary public cover
  requests remain normal HTTP traffic and need deployment-level controls.
- Concurrent tunnel streams and UDP sessions are admitted before starting
  attacker-controlled work.
- Native UDP incomplete reassembly has strict count/byte limits and a fixed TTL.
  Destination authorization maps have a strict count bound and live for their
  UDP association; an association ends with its control stream or connection.
- Client connection establishment is single-flight; fallback has a bounded
  attempt and cooldown so a UDP blackhole cannot multiply dial workers.
- Shutdown closes active transports and unblocks stream and packet receive
  goroutines.

The combined web server shares one active-stream admission budget, destination
policy, HMAC replay cache, and lifecycle across its H2 and H3 listeners. The
public HTTP cover itself can still consume normal HTTP server and upstream
resources; place conventional reverse-proxy, file-descriptor, connection,
request-rate, and bandwidth controls around an Internet-facing deployment.

Web CONNECT-UDP additionally acquires the stream budget and bounded
UDP-session/per-source admission only after authentication and target-template
validation. A target is resolved through the policy-aware UDP resolver and then
frozen to one connected numeric endpoint. Full bounded queues drop datagrams
rather than blocking unrelated H3 streams; this is consistent with unreliable
UDP delivery and must not be treated as a guaranteed-delivery channel.

Legitimate users behind one NAT or IPv6 `/64` share per-source quotas. Global
limits remain authoritative if an attacker rotates addresses. QUIC Initial
packets still cost kernel/network work, so public relays should enforce
firewall-level source rate and burst limits.

## Web-cover origin boundary

Use `--cover-root` only for content the operator intends to publish. The static
handler accepts `GET` and `HEAD` and uses Go's rooted file server.

Use `--cover-upstream` only for a fixed HTTP(S) origin the operator owns or is
authorized to proxy. The requester cannot select another scheme or authority;
the proxy rewrites `Host` and strips `Authorization`, `Proxy-Authorization`,
and hop-by-hop headers in both relevant directions. A malicious public request
can still exercise arbitrary paths and queries on that fixed application, so
the upstream must be hardened as an Internet-facing website. Do not point the
cover at cloud metadata, control-plane, or other sensitive internal services.

TCP and UDP cover listeners must use one numeric port. H1 is cover-only; H2 and
H3 can carry TCP CONNECT, and only H3 can carry CONNECT-UDP. Web mode rejects
server and client mTLS options. It still requires a shared token and normal
server-certificate verification. Operate only domains and infrastructure you
own or are authorized to use, and restrict active validation to loopback,
isolated containers, or dedicated test hosts rather than scanning third
parties.

## Dependency boundary

Native AutoCAR builds on official upstream quic-go. Web H3 uses
`github.com/apernet/quic-go` pinned exactly to
`v0.61.1-0.20260806010916-184d081eef3e`; H2 uses x/net HTTP/2 and uTLS for its
fixed ClientHello reference. A targeted CI boundary allows only that exact web
QUIC fork version, rejects the known external proxy application module, local
replacements, and copied/vendored external-source directories, and scans tracked
and untracked Go source.
That regression check is not a universal provenance or license detector. CI also
runs tests, race detection, vet, CodeQL, a reachable vulnerability scan and
privileged namespace integration tests. These checks reduce risk but are not a
formal audit.
