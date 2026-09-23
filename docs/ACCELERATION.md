# AutoCAR acceleration model

AutoCAR implements an independent application protocol and sender-pacing layer.
The native transport uses upstream `github.com/quic-go/quic-go`. Web H3
separately depends on the exactly pinned `github.com/apernet/quic-go` fork for its
client handshake profile; it does not import an external proxy application module
or provide third-party proxy wire compatibility. The design draws on
these public ideas:

- Persistent multiplexed QUIC sessions, independent streams and unreliable
  datagrams support sustained transport on difficult paths. AutoCAR
  implements those native-mode goals with its own `autocar/2` and `ACDG` formats
  on official upstream quic-go.
- BBR's public model separates estimated bottleneck bandwidth from propagation
  RTT and uses pacing to avoid filling queues. AutoCAR uses that insight in a
  deliberately smaller application-layer estimator.
- Warm connection state, independent pacing in both directions and bounded
  backpressure are usability goals for loss-prone paths. AutoCAR does not
  reproduce a proprietary transport algorithm.

References: [reference protocol documentation](https://v2.hysteria.network/docs/developers/Protocol/),
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

The native adapter also tracks cumulative application-send idle time across
the whole connection. Stream writes and datagram batches remain active while
waiting for pacing tokens or QUIC capacity; overlapping sends count as one busy
interval. If idle time spans both at least one stable sampling window and at
least half the observed interval, the controller
rebaselines the counters without changing its target or bandwidth history.
The window is one quarter of minimum RTT, bounded to 10–250 ms. Cumulative
accounting keeps idle gaps visible even when several writers sample inside
that window. This prevents ACK/control traffic during a receive-only interval
from being mistaken for low outbound capacity when traffic changes direction.

This is a conservative application-idle filter, not transport-level knowledge
of every queued packet. A discarded interval also does not update the
application-layer RTT/loss response; the underlying QUIC congestion controller
remains active throughout. Predominantly busy intervals still update the
estimate even when a short source gap exceeds one sampling window, so repeated
backpressure cannot be hidden by small idle gaps. Subsequent active samples can
still reduce the target when capacity, RTT or loss changes. Fixed-rate and bypass
modes are unchanged.

The controller separately measures time actually spent waiting for missing
tokens. Only one admission owner can sleep at a time, so concurrent writers do
not multiply that duration; observations include an in-progress sleep and use
the controller's own clock for its cumulative wait baseline. When this waiting
occupies at least half a valid observation interval, a lower observed rate does
not replace the unpenalized capacity history. Higher observations are still
accepted. For valid delivery observations, current RTT and loss factors still
apply to that capacity, not to a rate already reduced by the previous penalty. With no
capacity history yet, a pacing-limited sample uses the configured initial rate
as a prior; an unconstrained sample can replace it with a lower capacity.

This qualification never subtracts waiting time from the delivery-rate
denominator: QUIC can send already-queued bytes during an application wait.
Actual transport backpressure remains outside token sleep. When a slower path
fills the finite send buffers, predominantly transport-bound samples can age
out the old bandwidth maximum. Sleep share is still an application-level
heuristic, not proof that the path is uncongested.

For `balanced` and `aggressive`, a bounded capacity-recovery probe can break a
low-rate lock-in after real backpressure subsides while RTT stays elevated.
It requires at least three consecutive valid, loss-free, pacing-limited samples
spanning at least one second on the controller clock, without a material RTT
increase. It runs only when the steady target is below 95% of learned capacity.
The temporary admission rate is at most 1.25 times capacity (`balanced`) or
1.50 times capacity (`aggressive`), also capped at twice the steady target and
the configured maximum. Only a real higher wire sample can raise the capacity
estimate; starting or finishing a probe does not add tokens or change history.
The reported `TargetBytesPerSecond` remains the steady target, not this transient
admission rate.

The connection-wide byte allowance covers two bursts or two sampling windows,
whichever is larger, with a hard 1 MiB ceiling. The deadline covers service of
that allowance plus one sample window, or two smoothed RTTs, with a 100 ms
minimum and a two-second maximum. Configurations whose complete allowance
cannot fit those byte/time bounds are not probed. Deadline accounting splits
token refill at expiry even without another observation; cancellation refunds
normal tokens but never replenishes the probe allowance. Admission can finish
before the last wire feedback, so a bounded 250–500 ms grace period accepts
that outcome without allowing further probe-rate admission.

Any newly observed loss, a relative RTT rise above 25% (with a 1 ms noise
tolerance), or transport-bound delivery without a real capacity increase ends
the probe. Idle intervals and counter resets clear qualification. Successful
probes require more than 2% observed capacity growth and are separated by at
least one second or eight smoothed RTTs (the latter capped at 16 seconds).
Unsuccessful attempts back off from two to at most 16 seconds. RTT/loss penalties
continue to determine the steady target; the underlying QUIC controller remains
active. `conservative`, fixed-rate, and bypass modes do not perform these probes.

This is bounded recovery, not a guarantee of recovering all spare capacity:
large bandwidth-delay products or custom bursts can exceed the probe limits;
long-delayed feedback and persistent congestion can prevent discovery. Tests
cover fixed-RTT synthetic fast/slow/fast phases and a small-window real loopback
QUIC receiver slowdown. They do not establish Internet throughput, fairness,
browser similarity, or performance superiority.

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
Reno itself; the native pinned upstream quic-go v0.61.0 transport selects Reno
for its default sender. This mode therefore measures that actual upstream
baseline and is useful
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
semantics rather than a replacement congestion controller. It is also not an enforcement
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
