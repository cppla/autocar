# Security policy

## Supported versions

Until the first stable release, only the latest commit on `main` receives
security fixes.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting feature for this repository. Include the
affected version, reproduction steps, impact, and any suggested mitigation.

## Security guarantees and limits

AutoCAR protects the client-to-relay hop with authenticated TLS 1.3. QUIC
always uses TLS 1.3; the TCP fallback uses TLS 1.3 explicitly. The client never
offers an option to skip certificate verification. A private CA or a publicly
trusted certificate must be configured, and mutual TLS can be required by the
server.

The tunnel protects payload confidentiality and integrity against passive
observers and active network attackers, assuming the configured CA, private
keys, token, endpoints, operating systems, and dependencies are not
compromised. It does not hide endpoint IP addresses, packet sizes, timing, or
the fact that UDP or TLS is in use. The relay can observe destination metadata
and any destination traffic that is itself unencrypted. End-to-end HTTPS
remains encrypted between the application and the destination.

No transport can guarantee that a network operator will not rate-limit or
block it. AutoCAR's default UDP service is valid HTTP/3 and returns a neutral
cover page to unauthenticated probes; the client uses Hysteria's Chrome QUIC
fingerprint. Optional Salamander changes packet appearance with a separate
pre-shared key, but it is obfuscation rather than encryption. It must never be
treated as a substitute for TLS certificate verification, the relay token or
mTLS. When UDP is unavailable, new TCP flows can use the standards-compliant
TLS/TCP fallback. None of these mechanisms is an undetectability guarantee.

The default Chrome-parroting ClientHello intentionally follows a signature
scheme list that omits Ed25519. Relay certificates should therefore use ECDSA
P-256/P-384 (`autocar cert` emits P-256) or RSA. An Ed25519 relay certificate is
supported only when the client explicitly uses `--disable-chrome-parrot`; a
matching handshake failure includes this guidance. This switch does not relax
certificate-chain or hostname verification.

The relay blocks private, loopback, link-local, multicast, and unspecified
destinations by default, and denies common SMTP submission ports. Operators
should keep these defaults unless they fully trust every authenticated client.
Deployment-specific control-plane and metadata ranges can be added with
`--deny-cidrs`, especially before enabling private destinations.

The same policy is applied to every UDP datagram destination after remote DNS
resolution; only the approved numeric address is used for the actual send. A
logical UDP session remembers at most 256 successfully written numeric
destinations. Once full, it rejects new destinations without evicting existing
ones; failed writes never authorize replies. This bounds memory while retaining
valid delayed-reply filtering semantics.
The local SOCKS5 UDP relay accepts datagrams only from the IP of its associated
TCP control connection. A concrete `UDP ASSOCIATE` address must equal that peer;
a domain is resolved under the dial timeout and must include the peer address.
The relay pins the requested non-zero port, or the first valid source port when
the request uses port zero. SOCKS fragmentation is not reassembled and is
dropped.

The Hysteria core exposes a deliberately smaller TLS configuration surface than
Go's `tls.Config`. AutoCAR copies server-name/root verification,
`VerifyPeerCertificate` on the client, certificate selection, strict mTLS, and
ECH fields that the core supports. It rejects unsupported security-sensitive
policies before binding or dialing, including `VerifyConnection`, server
`GetConfigForClient`/`VerifyPeerCertificate`, custom verification clocks or
curve policies, custom server ticket handling, and client-authentication modes
other than no certificate or `RequireAndVerifyClientCert`. TLS 1.2-only fields
such as `CipherSuites` and renegotiation are irrelevant to QUIC/TLS 1.3 and do
not cause rejection. The client session cache in the shared CLI TLS config is
used by the per-flow TCP fallback; Hysteria instead keeps a long-lived QUIC
session.

The relay ignores client-supplied bandwidth hints by default, preventing an
authenticated client from forcing the relay sender into an unbounded Brutal
rate. `--allow-client-bandwidth` is an explicit operator opt-in and is rejected
unless finite upload and download negotiation ceilings are both configured.

Application limits do not replace host-level denial-of-service controls. The
hardened Hysteria fork caps accepted QUIC sessions globally and per source key,
including cover traffic, after Retry and before handshake allocation. It also
caps active TCP handlers globally and per source key across QUIC connections
before they can wait for a target header. Header
reads have a finite deadline. Unauthenticated HTTP/3 connections must complete
authentication within `--handshake-timeout`, and `--max-uni-streams` gives their
unidirectional control streams a separate small bound. HTTP request headers are
capped at 16 KiB before allocation. UDP session admission is global and shared
per authenticated source key across QUIC connections, and occurs before
allocating defragmentation state;
fragment count and total reassembled bytes are fixed and bounded.
`--max-outbound-tcp` and `--max-outbound-udp` separately cap active target
sockets, while `--max-streams` remains a per-QUIC-connection protocol limit.
Clients behind one NAT share `--max-client-connections`,
`--max-client-fallback-connections`, `--max-client-tcp-handlers`, and
`--max-client-udp-sessions`; the global caps
remain authoritative if a peer can rotate source addresses.
Resource keys are an IPv4 address or a masked IPv6 `/64`, so rotating IPv6
interface identifiers does not create new buckets. A legitimate NAT or routed
IPv6 `/64` shares its bucket by design.
The relay requires QUIC Retry source-address validation before allocating a
bounded handshake slot. Initial packets still consume kernel/network work, so production
relays should apply firewall rate and burst limits per source, bound file
descriptors and memory with the service manager, and monitor UDP traffic and
authentication failures.

On the client, connection setup is single-flight and `--max-pending-opens`
bounds stream-open workers whose upstream Hysteria API has no context-aware
variant. Caller deadlines still return immediately; late connections are
closed, and their slot is retained until the underlying call actually exits.

TLS private-key files must be regular files and mode `0600` on Unix. Shared
relay tokens, local-proxy passwords and Salamander passwords must contain at
least 16 bytes; use the bundled `autocar token` command to generate independent
high-entropy values. Do not reuse the relay authentication token as the
Salamander password.
