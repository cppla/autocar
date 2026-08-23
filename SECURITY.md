# Security policy

## Supported versions

Until the first stable release, only the latest commit on `main` receives
security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting for this repository and include the affected commit,
reproduction, impact and suggested mitigation.

## Guarantees

AutoCAR protects the client-to-relay hop with authenticated TLS 1.3. QUIC and
TCP fallback use the `autocar/2` ALPN. The client rejects `InsecureSkipVerify`;
a pinned/private CA or explicitly selected system roots are required. The relay
may additionally require mTLS. QUIC 0-RTT is disabled so tokens and requests are
not replayable early data.

Assuming the endpoints, configured trust roots, private keys, relay token and
dependencies are not compromised, TLS provides confidentiality, integrity and
relay identity against network attackers. End-to-end HTTPS remains encrypted
between the application and destination.

## Limits

AutoCAR does not hide endpoint IPs, packet size, timing or the use of QUIC/TLS.
It has no HTTP cover page, browser-fingerprint imitation or packet obfuscation,
and makes no undetectability guarantee. The relay sees destination metadata and
any destination protocol that lacks its own encryption.

The relay is an authenticated proxy, not a tenant sandbox. Application limits
reduce accidental and straightforward resource exhaustion but do not replace
host firewall, cgroup, file-descriptor, memory, CPU and per-source rate limits.

Application-layer pacing is cooperative. An authenticated modified client can
ignore its local rate. Use a host or cloud policer for security/accounting
limits. Negotiated adaptive/fixed-rate pacing applies only to QUIC; a TCP flow
taken by `auto`'s TLS fallback is unpaced and must not be treated as a quota.

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

The same resolver policy applies to every UDP destination. A UDP association
records a bounded set of successfully requested numeric destinations and
forwards replies only from that set; unsolicited packets are dropped.

## SOCKS5 UDP boundary

The local UDP relay accepts packets only from the IP of its associated TCP
control connection. A concrete UDP ASSOCIATE address must match that peer; a
domain must resolve to it. A nonzero requested source port is pinned, while port
zero pins the first valid sender. RFC 1928 UDP fragments are dropped rather than
silently combined.

The tunnel logical payload limit is 4,096 bytes. Every AutoCAR fragment carries
its own address metadata. Fragment count, incomplete messages, buffered bytes
and TTL are bounded before attacker-controlled allocation; conflicting
fragments purge the assembly.

## Authentication and error handling

Tokens must be 16–1,024 bytes. The relay hashes the bounded presented token and
uses a constant-time digest comparison. It authenticates every stream before
destination resolution or UDP session allocation. Invalid requests receive
bounded, neutral errors; resolver and operating-system details are not exposed.

On Unix, the TLS private key must be a regular file with mode exactly `0600`.
Token and password files must be regular and have no group/other permission bits
(`0600` or stricter). Each file and its parent directory must be readable and
traversable by the actual runtime user; a root-owned `0600` secret is not usable
by an unprivileged `autocar` service. Generate independent high-entropy secrets
with `autocar token`; do not reuse relay, local proxy and other credentials.

## Resource controls

- QUIC and TLS listeners have global and per-source connection limits. IPv4 is
  keyed by address; IPv6 is grouped by `/64` to resist interface-ID rotation.
- QUIC pre-authentication lifetime, protocol headers and destination dials have
  deadlines.
- Concurrent tunnel streams and UDP sessions are admitted before starting
  attacker-controlled work.
- UDP incomplete reassembly has strict count/byte limits and a fixed TTL.
  Destination authorization maps have a strict count bound and live for their
  UDP association; an association ends with its control stream or connection.
- Client connection establishment is single-flight; fallback has a bounded
  attempt and cooldown so a UDP blackhole cannot multiply dial workers.
- Shutdown closes active transports and unblocks stream and packet receive
  goroutines.

Legitimate users behind one NAT or IPv6 `/64` share per-source quotas. Global
limits remain authoritative if an attacker rotates addresses. QUIC Initial
packets still cost kernel/network work, so public relays should enforce
firewall-level source rate and burst limits.

## Dependency boundary

AutoCAR builds on official upstream quic-go and independently maintained
protocol code. A targeted CI boundary rejects known Hysteria/apernet modules and
imports, local module replacements and known external-source directory paths.
That regression check is not a universal provenance or license detector. CI also
runs tests, race detection, vet, CodeQL, a reachable vulnerability scan and
privileged namespace integration tests. These checks reduce risk but are not a
formal audit.
