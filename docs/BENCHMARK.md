# Benchmark methodology

AutoCAR includes a payload benchmark and a privileged Linux namespace suite.
The goal is to detect regressions and identify the sender that was actually
tested—not to manufacture a universal “acceleration percentage.”

## Payload benchmark

Start the bounded target:

```bash
./autocar bench-server --listen 127.0.0.1:9000
```

Measure direct and tunneled paths with the same payload, warmup and iterations:

```bash
./autocar bench-client \
  --transport direct \
  --target 127.0.0.1:9000 \
  --mode download --bytes 8388608 --warmup 2 --iterations 7 --json

./autocar bench-client \
  --transport quic \
  --server relay.example.com:443 --ca server.crt --token-file token \
  --target target.example:9000 \
  --mode download --bytes 8388608 --warmup 2 --iterations 7 --json
```

JSON contains raw `results_mbps` and `durations_ms`, plus `median_mbps`,
`p05_mbps`, `p95_mbps`, `median_duration_ms` and `p95_duration_ms`. The throughput
p95 is the upper tail; use throughput p05 or duration p95 to discuss slow runs.
The selected transport and sender metadata must remain identical across all
measured iterations or the command fails. `transport` is the requested policy
(`auto`, `quic`, `tls` or `direct`); `selected_transport` records the actual
measured path (`quic`, `tls` or `direct`). Do not treat `transport: "auto"` as
evidence that QUIC carried the payload. The output also separates:

- `local_tx_acceleration`: the client's current sender;
- `payload_sender_acceleration`: the sender of the measured payload;
- negotiated rates for each of those identities;
- `tunnel_sender_endpoint`: `client` for upload, `relay` for download.

Direct and explicit `tls` runs omit acceleration fields. When `auto` selects
TLS, it reports `selected_transport: "tls"`, a `tls-fallback` sender label and a
zero negotiated rate; adaptive/reno/fixed-rate labels describe QUIC only.

For download, payload sender metadata comes from the authenticated relay
response. Copying the client's local label into this field would be a false
test, because the client is sending only request/control bytes.

The per-iteration timer starts after the tunnel/direct connection is opened and
the 16-byte benchmark request is written; it covers payload transfer and the
one-byte completion acknowledgement, not tunnel setup. In particular, a short
flow ratio is a warm-payload diagnostic rather than a connection-establishment
benchmark.

## Namespace topology

`scripts/netem-integration.sh` creates two isolated network namespaces joined by
a veth pair: the client is in one, while the relay and bounded benchmark target
are co-located in the server namespace. Traffic therefore crosses a real
namespace boundary in both directions, but the suite does not claim a third
target hop. It runs the real binary and uses real TLS/token files. The initial
smoke/throughput stage applies symmetric random loss on each veth egress with
`tc netem`; this is ordinary qdisc path loss and is not used as a controller
identity proof.

The separate lossy pacing proof removes that random loss and uses the nft-backed
`iptables` frontend to apply deterministic, tuple-scoped loss only at the
**receiver's INPUT hook**. It drops every Nth eligible QUIC UDP datagram whose
matched packet length is at least 1,000 bytes:

| Measurement | Payload sender | Loss hook |
| --- | --- | --- |
| upload | client | relay INPUT |
| download | relay | client INPUT |

For those eligible large data packets this is one-way loss observed at the
receiver. Small ACK and handshake packets are intentionally outside this model.
Putting the rule at INPUT also avoids a Linux implementation trap: with
nft-backed iptables, a local sender OUTPUT `DROP` may propagate a policy error to
the UDP socket and make `sendmsg(2)` return `EPERM`. That tests local firewall
rejection, not congestion or packet loss. The suite therefore also rejects logs
containing `operation not permitted`.

A later fallback scenario uses separate tuple-scoped rules that drop all QUIC
UDP at both receiver INPUT hooks. It is a silent-blackhole state-machine test,
not part of the every-Nth pacing-loss model.

Rules are scoped to the QUIC tuple and inspected through exact eligible and DROP
packet counters. The script checks `DROP == floor(eligible / N)` and fails if the
selected direction did not actually drop packets. It disables GRO/GSO/TSO before
interpreting those counters. The lossy stage gates protocol identity, sender
direction, exact counters and positive progress; fixed-rate accuracy is checked
separately with the deterministic rules empty.

## CI gates

The namespace script's deterministic hard checks cover:

1. wrong-CA and wrong-token failures;
2. no plaintext sentinel in a tunnel capture;
3. direct, QUIC and TLS TCP payload transfer;
4. an initial QUIC failure and a live receiver-side QUIC blackhole both reach
   authenticated TLS fallback within declared timing bounds;
5. upload reports the client sender; download reports the relay sender;
6. `adaptive-balanced`, `reno` and `fixed-rate` labels match the negotiated
   response, not merely CLI input;
7. loss-free fixed-rate aggregate goodput falls in a declared tolerant window
   around each asymmetric effective rate;
8. every lossy mode/direction has exact positive receiver INPUT eligible and
   DROP counters;
9. no sender-side `EPERM`/`operation not permitted` regression.

The fixed-rate accuracy value is total equal-size payload bytes divided by total
measured transfer time (equivalently the harmonic mean of the per-iteration
goodputs), not the median. The default accepted target ratio is `0.82–1.08` after
one warmup and three measured 4 MiB transfers; environment variables can change
those declared inputs and bounds.

The Go integration tests, rather than the namespace script, cover TLS 1.3 and
ALPN selection, SOCKS5 UDP/session cleanup, shared QUIC-connection reuse and
reconnect, and the cooldown's single-probe behavior. Keeping those claims
separate prevents a passing namespace run from being mistaken for coverage it
does not execute.

Adaptive and reno measurements are saved as artifacts, but CI does not require
`adaptive >= reno × 1.10`. That ratio is unstable under shared GitHub runners,
offload behavior, fixed test ordering, short samples and deterministic drop
phase. It can both reject correct code and accept a mislabeled controller.

## Loss models

The default CI case is deliberately narrow and reproducible. A serious
evaluation should sweep at least:

- RTT: 10, 50, 100, 200 and 400 ms;
- random loss: 0, 0.1, 1, 3, 5 and 10 percent;
- correlated/burst loss with several correlation lengths;
- bottleneck rates and queue sizes around the expected BDP;
- one and many concurrent streams;
- upload and download independently;
- competing Reno/BBR traffic and queue-delay impact.

Use at least two warmups and 10–30 measured iterations in randomized order.
Report median, dispersion/confidence interval, p95 completion time, retransmitted
bytes, loss counter, CPU and peak queue delay. A single ratio without these
details is not a defensible result.

## Running locally

The suite requires Linux root privileges plus network namespace, `tc`,
**nft-backed** `iptables`, `ethtool`, `tcpdump` and `curl` support. It deliberately
refuses the legacy iptables backend because its error/counter behavior is not the
regression being proved:

```bash
make build
iptables --version   # output must include: (nf_tables)
sudo AUTOCAR_ARTIFACT_DIR="$PWD/artifacts/netem" \
  ./scripts/netem-integration.sh "$PWD/bin/autocar"
```

Artifacts include JSON measurements, endpoint logs, rule counters and packet
captures. A failed job should be diagnosed from those facts before changing a
performance threshold.

## Interpretation

AutoCAR is a split proxy. A comparison against direct TCP includes different
protocols, endpoints, encryption work and often different congestion control;
it cannot isolate the application pacer alone. `adaptive` versus `reno` on the
same AutoCAR QUIC path is the closer A/B comparison, but it still shares one
underlying quic-go controller.

Results apply only to the stated topology and build. Stable low-latency paths
may favor direct traffic or bypass mode. Publish raw measurements and the exact
commit instead of generalizing a favorable sample.
