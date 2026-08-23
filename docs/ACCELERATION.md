# AutoCAR acceleration model

AutoCAR implements an independent application protocol and sender-pacing layer.
Hysteria v2 is a public design reference; AutoCAR does not include its source and
the two wire protocols are incompatible. The design draws on these public ideas:

- Hysteria v2 demonstrates the value of a persistent multiplexed QUIC session,
  independent streams and unreliable datagrams on difficult paths. AutoCAR
  implements those goals with its own `autocar/2` and `ACDG` formats on official
  upstream quic-go.
- BBR's public model separates estimated bottleneck bandwidth from propagation
  RTT and uses pacing to avoid filling queues. AutoCAR uses that insight in a
  deliberately smaller application-layer estimator.
- ServerSpeeder/LotServer are treated only as public product goals: keep warm
  state, pace independently in both directions and improve loss-path usability.
  AutoCAR does not reproduce any proprietary Zeta-TCP algorithm.

References: [Hysteria protocol documentation](https://v2.hysteria.network/docs/developers/Protocol/),
[Google's BBR paper](https://research.google/pubs/bbr-congestion-based-congestion-control/),
and the [IETF BBR draft](https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr).

## Layering

```text
application write
      │
      ▼
AutoCAR adaptive / fixed-rate / bypass admission
      │
      ▼
quic-go stream or DATAGRAM
      │
      ▼
quic-go congestion control, ACK processing, loss recovery and encryption
```

This distinction is essential. AutoCAR can delay application writes, but it
cannot enlarge quic-go's congestion window, mark packets acknowledged, or
change retransmission decisions. `adaptive` is therefore **BBR-inspired
pacing**, not a QUIC BBR implementation. The transport controller remains the
hard safety bound.

## `adaptive`

The controller samples cumulative connection statistics exposed by quic-go:

- bytes sent and bytes declared lost;
- minimum RTT;
- smoothed RTT;
- sample time.

For each valid interval it computes an approximate delivered rate from the
sent/lost deltas. A bounded eight-sample maximum is the bandwidth estimate.
The target starts from 64 Mbit/s, applies the selected pacing gain, and is then
reduced when either RTT inflation or interval loss crosses a profile threshold.
Every target is clamped to configured minimum and maximum rates.

This is intentionally not a full BBR state machine. In particular AutoCAR has
no transport-visible BDP congestion window, ACK aggregation model, ProbeRTT
drain, ECN policy, inflight bounds or BBRv2/BBRv3 logic. Calling it “real BBR”
would be inaccurate.

Profiles tune application-layer probe/retreat behavior:

| Profile | Pacing gain | RTT response | Loss response | Intended use |
| --- | ---: | --- | --- | --- |
| `conservative` | 1.00 | earliest/strongest | earliest/strongest | shared or shallow-buffer paths |
| `balanced` | 1.08 | middle | middle | default |
| `aggressive` | 1.18 | latest/weakest | latest/weakest | measured private paths only |

The defaults are operational starting points, not universal optima. A queueing
delay test matters at least as much as bulk throughput.

## `reno`

`reno` bypasses AutoCAR's application-layer admission. It does not implement
Reno itself; the pinned quic-go v0.61.0 transport selects Reno for its default
sender. This mode therefore measures that actual upstream baseline and is useful
for A/B tests or for operators who do not want an additional application pacing
layer. A future quic-go upgrade must reverify this label before release.

## `fixed-rate`

`fixed-rate` is a bounded token bucket with a finite burst. It is enabled only
with an explicit, positive byte rate. A request larger than the burst is split
into bounded admission chunks, and cancellation or a write deadline interrupts
the wait.

Fixed-rate negotiation and pacing exist only on the QUIC path. An explicit TLS
transport cannot select this mode. In `auto`, a new TCP flow that falls back to
TLS is unpaced and has no QUIC rate metadata; use `--transport=quic` whenever
fixed-rate behavior is required rather than best effort.

Rates are negotiated independently:

- client to relay: client upload request, capped by the relay receive policy;
- relay to client: relay sender policy, optionally capped by the client's
  download request when the relay explicitly accepts client hints.

The response reports the effective sender mode/profile and both selected rates.
Benchmark telemetry uses the response for the download direction; it never
pretends that the client's local controller sent a relay-originated payload.

Fixed-rate mode does not compensate by dividing by observed ACK ratio. It is
AutoCAR's bounded token-bucket design, with its own `fixed-rate` name and
semantics rather than a Brutal controller. It is also not an enforcement
boundary: a modified client can bypass its local pacer. Use `tc`, nftables or a
cloud policer for non-bypassable limits.

## Warm state and multiplexing

One authenticated QUIC connection carries many independent TCP streams and UDP
associations. Reusing TLS, RTT and transport recovery state avoids repeating a
full setup for every local proxy flow. Stream backpressure is direct: AutoCAR
does not insert an unbounded userspace queue between proxy and destination.

The sender controller is connection-scoped, so concurrent streams share the
same path observations and aggregate rate. The two endpoints still pace their
own sending directions independently.

## UDP

UDP uses QUIC DATAGRAM rather than a reliable stream. AutoCAR's own `ACDG`
format carries session ID, message ID, direction, destination/source address and
fragment metadata. Logical payloads are limited to 4,096 bytes. Reassembly has
fixed message, byte, fragment and TTL bounds; conflicting fragments purge the
assembly. Loss remains loss—AutoCAR does not retransmit UDP datagrams.

## What CI proves

The Linux namespace suite verifies:

- the expected endpoint is the payload sender;
- the reported sender mode/profile and negotiated rate match that direction;
- deterministic pacing-proof loss drops every Nth eligible QUIC UDP datagram of
  at least 1,000 bytes at the receiver INPUT hook; background random `tc netem`
  loss remains a qdisc impairment;
- the lossy stage proves negotiated identity, counters and positive transfer
  progress, while a separate loss-free stage checks fixed-rate accuracy after
  warmup;
- no `sendmsg: operation not permitted` regression occurs;
- TLS fallback, certificate/token failure and plaintext-capture checks work.

The deterministic rule intentionally excludes small ACK and handshake packets.
The suite requires the nft-backed `iptables` frontend plus `ethtool`; it disables
GRO/GSO/TSO before interpreting packet counters.

It records adaptive versus reno throughput but does not require one noisy
GitHub runner sample to exceed the other by a magic ratio. Such a gate is both
flaky and scientifically weak. Production claims require repeated trials,
confidence intervals, queue-delay measurements and multiple loss/RTT models.
