# AutoCAR security hardening

This directory is based on `github.com/apernet/hysteria/core/v2` v2.12.1
(upstream commit `14e9fff1d972ab0187ac7fcf75b9514dc8664065`) and remains licensed under
the MIT license in `LICENSE.md`.

AutoCAR keeps the fork intentionally small and auditable. Its server adds:

- process-wide and per-source (IPv4 address or IPv6 `/64`) caps on accepted QUIC connections after Retry
  address validation and before handshake state;
- process-wide and per-source caps on active TCP handlers, shared across
  QUIC connections and held for the complete relay lifetime, plus a deadline
  for reading the initial TCP request;
- a finite pre-authentication lifetime and a reduced incoming unidirectional
  stream budget for unauthenticated HTTP/3 peers;
- process-wide and per-source UDP session admission, shared across QUIC
  connections, before allocating defragmentation state; and
- fixed UDP fragment-count and reassembled-size bounds.

Maximum-size UDP payloads use a framing-aware serialization buffer and every
serialization/fragmentation overflow returns an error instead of reporting a
successful silent drop.
The client package exports the 4,096-byte logical payload ceiling so frontends
can reject larger payloads without destroying a healthy UDP association.

Authentication state and its identity are read under the same lock used by the
HTTP authentication handler, preventing dispatch or disconnect accounting from
observing a partially published authentication result.

The QUIC listener forces Retry address validation and acquires the global
connection budget before allocating handshake state. Unauthenticated HTTP/3
request headers are capped at 16 KiB before allocation.

All per-source budgets use one IPv4 address or a masked IPv6 `/64`, preventing
interface-identifier rotation from bypassing the gates while documenting the
intentional NAT/prefix sharing tradeoff.

These changes close resource-exhaustion paths that cannot be intercepted by
the public `server.Outbound` API because incomplete fragments never create an
outbound socket. The TCP admission ordering relies on the narrow local
`../quic-go` `StreamAdmission` hook documented in its `AUTOCAR_PATCHES.md`.
Changes should be rebased and re-audited whenever either pinned upstream
version changes.

The upstream multi-gigabyte TCP and long lossy-UDP stress cases are opt-in via
`AUTOCAR_RUN_UPSTREAM_STRESS=1`; normal CI runs deterministic integration and
network-emulation suites instead of allowing those unbounded cases to consume
the job timeout.

Integration tests generate an ephemeral ECDSA P-256 certificate in memory;
the fork does not carry the upstream repository's fixed test private key.
Timing-sensitive UDP session-manager tests wait for close and shutdown events
instead of sleeping across ticker boundaries, preventing scheduler load from
causing false CI failures.

The client exposes context-aware authentication and TCP stream opens. Timeout
or cancellation aborts the HTTP/3 handshake or the individual QUIC stream,
preventing timed-out proxy opens from retaining worker slots or goroutines.
