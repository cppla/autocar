# Acceleration design

AutoCAR combines three public design families without claiming to be a drop-in
replacement for any of them:

| Design family | What AutoCAR adopts | What AutoCAR does not claim |
| --- | --- | --- |
| Hysteria v2 | HTTP/3 over QUIC, a persistent multiplexed session, Fast Open, negotiated Brutal, QUIC DATAGRAM, Chrome-oriented handshake shaping, HTTP/3 cover handling, and optional Salamander | Port hopping, Mimic, a user-facing ECH setup, or invisibility |
| BBR | A real userspace BBRv1-derived delivery-rate/minimum-RTT model, BDP-based pacing and congestion window, and the four BBR phases | Linux kernel TCP BBR, BBRv2, or BBRv3 |
| ServerSpeeder/LotServer/Zeta-TCP objectives | ACK-driven feedback in both directions, paced sending, warm state, standard early loss detection, PTO probes, and independent multiplexed streams | Proprietary prediction, redundant retransmission, FEC, transparent TCP interception, or protocol compatibility |

The implementation comes from an in-tree, security-hardened fork of the pinned
MIT-licensed Hysteria v2.12.1 core and its QUIC fork. AutoCAR adds admission
before TCP handlers and UDP defragmentation state, finite fragment bounds, and
exit policy around it. It does not copy the GPL `tcp-brutal` project. See
[the patch record](../third_party/hysteria-core/AUTOCAR_PATCHES.md) and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## BBR mode (the default)

Leaving client `--upload-mbps=0 --download-mbps=0` selects the configured
model controller. `--congestion=bbr --bbr-profile=standard` is the default on
both endpoints.

This is a real BBRv1-derived sender, not the old quic-go default controller
under a different name. For traffic sent by each endpoint it:

1. samples delivered bytes over send/ACK intervals to estimate bottleneck
   delivery rate;
2. tracks the minimum observed RTT, expiring the estimate periodically so the
   path can be remeasured;
3. derives the bandwidth-delay product, approximately
   `delivery_rate * min_rtt`;
4. applies a pacing gain to the estimated delivery rate; and
5. bounds in-flight data with a congestion-window gain around the BDP, with
   loss-recovery limits when packets are declared lost.

The BBR state machine is:

| Phase | Purpose |
| --- | --- |
| STARTUP | Increase pacing quickly while delivery bandwidth continues to grow |
| DRAIN | Pace below the estimate to remove the queue accumulated during STARTUP |
| PROBE_BW | Cycle pacing gains around the bandwidth estimate to look for new capacity while controlling the queue |
| PROBE_RTT | Temporarily reduce in-flight data to refresh the minimum-RTT model |

In the pinned implementation, the PROBE_BW gain cycle is `1.25, 0.75, 1, 1,
1, 1, 1, 1`. The minimum-RTT sample expires after 10 seconds; PROBE_RTT lasts
at least 200 ms after the in-flight target is reached. These are implementation
details of the pinned version and may change only with an explicit dependency
upgrade and review.

### Profiles

Profiles change how quickly BBR probes and how conservatively it handles an
overshot path. They do not change the Hysteria wire protocol.

| Profile | STARTUP pacing gain | STARTUP CWND gain | Steady CWND gain | Growth rounds | Intended use |
| --- | ---: | ---: | ---: | ---: | --- |
| `conservative` | 2.25 | 1.75 | 1.75 | 2 | Shallow buffers, shared access links, or latency-sensitive paths; enables drain-to-target, overshoot detection, and estimate safeguards |
| `standard` | 2.885 | 2.0 | 2.0 | 3 | General default |
| `aggressive` | 3.0 | 2.25 | 2.5 | 4 | Controlled high-BDP paths; allows more startup ACK aggregation and queue pressure |

Choose the profile independently on the client and relay because each setting
controls only that endpoint's sender. `--congestion=reno` is available as a
diagnostic/fairness baseline. Client bandwidth hints are ignored by default.
They can select Brutal only after the relay operator explicitly enables
`--allow-client-bandwidth` with finite ceilings in both directions.

BBR is model-based, not magic. A bad route, insufficient relay capacity,
policing, CPU saturation, or an already optimal direct route can erase any
benefit. BBRv1 can also compete aggressively with loss-based flows and can
build queues on paths where its model is inaccurate.

## Brutal mode (explicit bandwidth only)

Brutal is selected direction by direction when the client provides a non-zero
capacity and the relay explicitly allows client bandwidth with two finite
ceilings. AutoCAR deliberately has no "guess a large number" default.

| Traffic direction | Client hint | Relay negotiation ceiling |
| --- | --- | --- |
| Client to relay / upload | `--upload-mbps` | `--max-upload-mbps` |
| Relay to client / download | `--download-mbps` | `--max-download-mbps` |

The relay opt-in rejects a zero ceiling. A zero client hint means unknown
capacity and therefore keeps BBR/Reno for that direction. With two non-zero
values, the lower value wins. The negotiated value is a sender pacing target,
not a throughput guarantee.

Example for a measured 20 Mbit/s upload and 100 Mbit/s download:

```sh
# Relay policy for each authenticated client
autocar server [server options] \
  --allow-client-bandwidth \
  --max-upload-mbps=20 \
  --max-download-mbps=100

# Client's measured access-link capacities
autocar client [client options] \
  --upload-mbps=20 \
  --download-mbps=100
```

The sender keeps five one-second ACK/loss sample slots. After at least 50
packet samples, it computes `ack_rate = ACKed / (ACKed + lost)` and clamps the
rate to a minimum of `0.8`. Pacing is approximately
`negotiated_rate / ack_rate`; therefore loss compensation is capped at about
`1 / 0.8 = 1.25x`. Its congestion window is approximately two smoothed RTTs
of that compensated rate. `--disable-loss-compensation` fixes the ACK rate at
one; set it on both endpoints if compensation must be disabled in both
directions.

Brutal intentionally keeps sending near the declared rate instead of backing
off like a conventional congestion-fair controller. It can harm other users,
trigger policers, and waste bandwidth when the entered value exceeds the real
bottleneck. Use it only on a link you control or have permission to reserve,
enter a conservative measured capacity, and configure relay negotiation
ceilings. These values are not a non-bypassable traffic policer; use host or
cloud shaping for hard limits. Keep the zero-bandwidth BBR default on shared or
unknown networks.

## Loss recovery and dual-ended feedback

Congestion control and retransmission are separate layers. BBR and Brutal
consume the same QUIC ACK/loss events; neither replaces QUIC loss detection.
The pinned QUIC transport follows RFC 9002 with:

- packet-threshold loss after three newer packet numbers are acknowledged;
- time-threshold loss at 9/8 of the relevant RTT estimate; and
- probe timeout (PTO) packets with exponential backoff when acknowledgements
  stop arriving.

Both client and relay are QUIC senders and receivers. ACKs flowing in each
direction continuously return RTT, delivery, and loss observations to the
opposite sender. That is the concrete dual-ended feedback mechanism behind
AutoCAR's "reverse-control" goal. It is auditable standard QUIC behavior, not
an assertion that AutoCAR reconstructed Zeta-TCP's private algorithm.

QUIC retransmits lost reliable stream frames, but does not retransmit QUIC
DATAGRAM payloads. AutoCAR adds no speculative retransmission or FEC. Adding
redundancy without a measured policy could amplify congestion and would
require a separate protocol and fairness review.

## Short-flow and multiplexing gains

While the current long-lived QUIC session remains connected, it keeps TLS,
RTT, path-MTU, and controller state warm. Each new TCP proxy flow opens a
stream instead of a new end-to-end TCP connection between the AutoCAR
endpoints. A reconnect creates a fresh session and therefore starts cold; no
TLS resumption or congestion/PMTU state is claimed across reconnects. Fast
Open is disabled by default; when explicitly enabled, it lets the first bytes
be written before the exit-dial response reaches the client.

These mechanisms are most visible for sequential short operations on a
high-RTT path. Independent QUIC streams also prevent a lost ordered byte in one
logical flow from imposing TCP-style application head-of-line blocking on all
other logical flows. They do not remove propagation delay or make the final
relay-to-destination TCP handshake disappear.

## Hysteria traffic-shaping features

- **HTTP/3 cover:** without packet obfuscation, unauthenticated requests see a
  neutral HTTP/3 service rather than a distinctive tunnel error.
- **Chrome parrot:** enabled by default, it selects Hysteria/quic-go handshake
  traits including Chrome-oriented connection-ID behavior. It is a fingerprint
  reduction, not proof that all traffic is identical to a browser. Its
  Chrome-compatible signature list requires an ECDSA P-256/P-384 or RSA relay
  certificate; Ed25519 requires `--disable-chrome-parrot` on the client.
- **Salamander:** an optional shared secret wraps UDP packets before QUIC. It
  changes the observable packet form, so normal HTTP/3 cover probing is no
  longer available in that mode.
- **TLS/TCP fallback:** `auto` gives new TCP flows a real encrypted TCP path
  when UDP is unavailable. UDP associations have no TCP fallback.

AutoCAR does not currently expose port hopping, Hysteria Mimic, or ECH
provisioning. It cannot promise resistance to endpoint blocking, statistical
traffic analysis, global observation, or traffic-volume correlation.

## How to verify a deployment

Run the repository's netem suite first, then repeat the matrix in
[BENCHMARK.md](BENCHMARK.md) on the intended route. At minimum compare:

1. direct, BBR `conservative`, BBR `standard`, and BBR `aggressive` with both
   bandwidth hints zero;
2. Brutal with truthful capacities and relay caps;
3. download and upload, short and bulk payloads, and concurrency greater than
   one; and
4. clean, delayed, lossy, and reordered path profiles.

Retain raw results, packet captures without payload secrets, CPU data, and the
exact build/configuration. A result from one narrow CI profile is evidence for
that profile only, not a universal acceleration claim.
