# Benchmarking AutoCAR

AutoCAR includes a deterministic TCP source/sink so direct and relayed paths
can move the same payload. It reports payload goodput in decimal Mbit/s. The
tool is for repeatable comparisons; no single result proves that a relay or a
controller is faster on every network.

## Basic comparison

The benchmark server defaults to `127.0.0.1:9000`:

```sh
autocar bench-server
```

A remote-path comparison requires explicit non-loopback opt-in:

```sh
autocar bench-server \
  --listen=0.0.0.0:9000 \
  --allow-public-benchmark
```

`bench-server` has no authentication. A remote caller can make it send or
receive substantial traffic up to its limits. Restrict port 9000 to the test
client and relay with host/cloud firewalls, use the smallest practical
`--max-bytes` and `--max-connections`, and stop it after the test.

Measure the direct route:

```sh
autocar bench-client \
  --transport=direct \
  --target=bench.example.com:9000 \
  --mode=download --bytes=8388608 \
  --warmup=1 --iterations=7 --json
```

Measure the default Hysteria v2/BBR path through an already running relay:

```sh
autocar bench-client \
  --transport=hy2 \
  --server=relay.example.com:443 \
  --ca=relay-ca.crt \
  --token-file=relay-token \
  --congestion=bbr --bbr-profile=standard \
  --upload-mbps=0 --download-mbps=0 \
  --target=bench.example.com:9000 \
  --mode=download --bytes=8388608 \
  --warmup=1 --iterations=7 --json
```

`--transport=quic` is an alias for `hy2`. Use `--transport=tls` to characterize
the TCP/TLS fallback and `--transport=legacy-quic` only against a relay started
with `--quic-engine=legacy`. For `auto`, the JSON transport label describes the
configured mode rather than the path used by each individual flow; select an
explicit transport for performance comparisons.

Repeat with `--mode=upload`. The timer begins after the benchmark request
header is written and ends after the payload plus one-byte completion
acknowledgement. Connection and tunnel-stream setup occur before that timer.
Measure a complete real application operation separately when user-perceived
latency matters.

For Hysteria output, `local_tx_acceleration` and
`local_negotiated_tx_bytes_per_second` always describe the client's
client-to-relay sender. `tunnel_sender_endpoint` identifies which endpoint
sends benchmark payload on the tunnel. Only an upload can therefore populate
`payload_sender_acceleration` from the client process. A download names the
relay as sender but deliberately does not mislabel the client's controller as
relay telemetry; record the relay configuration or collect relay-side
telemetry separately.

## Controller matrix

Do not compare only one controller on one path. A useful minimum matrix is:

| Mode | Client flags | Relay flags | Question answered |
| --- | --- | --- | --- |
| Direct | `--transport=direct` | none | What does the unrelayed route deliver? |
| BBR conservative | `--congestion=bbr --bbr-profile=conservative`, bandwidths zero | matching BBR/profile, caps zero | Does a cautious model reduce queue/loss cost? |
| BBR standard | `--congestion=bbr --bbr-profile=standard`, bandwidths zero | matching BBR/profile, caps zero | Default model result |
| BBR aggressive | `--congestion=bbr --bbr-profile=aggressive`, bandwidths zero | matching BBR/profile, caps zero | Is extra startup pressure useful or harmful? |
| Brutal | truthful non-zero `--upload-mbps` and `--download-mbps` | `--allow-client-bandwidth` plus explicit non-zero negotiation ceilings | Does a reserved/controlled link benefit from a fixed negotiated rate? |
| Reno | `--congestion=reno`, bandwidths zero | `--congestion=reno`, caps zero | Loss-based baseline |
| TLS fallback | `--transport=tls` | TCP listener enabled | What is the reachability path's cost? |

For Brutal, both relay caps and client measurements should be written into the
result metadata. An inflated capacity is not an optimization: it changes the
experiment into an unfair overload test. BBR profiles control the sender at
the endpoint where the flag is set, so record both endpoint configurations.

For every row, exercise at least:

- download and upload;
- short, medium, and bulk payloads;
- one flow and several concurrent flows; and
- clean, high-RTT, random-loss, burst-loss, and reordered profiles.

## Fair-test checklist

1. Pin the AutoCAR commit, Go version, module versions, configuration, client,
   relay, and benchmark target.
2. Keep the direct and tunneled destinations identical. Document both physical
   routes and relay placement; a relay can improve routing or add a detour.
3. Alternate test order, declare warmups, run enough iterations, and retain
   every raw result rather than only the best value.
4. Record RTT, random and burst loss, reordering, MTU, configured link rate,
   CPU, memory, and time of day. Confirm neither endpoint is CPU-limited.
5. Report median plus all individual results. The emitted `p95_mbps` is the
   95th percentile of goodput, where larger is better; it is not latency p95.
6. Distinguish a warm shared QUIC connection from fresh direct TCP flows, and
   state whether setup is timed. Warm payload-phase goodput is useful evidence,
   but it is not the same metric as end-to-end short-flow latency.
7. Repeat on the intended production path. Emulation catches regressions but
   cannot reproduce every queue, middlebox, policer, or competing flow.

Why Hysteria/QUIC can help: streams reuse a warm authenticated connection and
its BBR delivery/RTT model; pacing uses estimated delivery rate and its gain
while the congestion window uses the inferred BDP; explicitly enabled
Fast Open can overlap the target response with initial writes; unrelated
streams avoid TCP-style cross-flow head-of-line blocking. Why it may not help:
the relay adds work and distance, the relay-to-destination leg is still a new
socket, and a clean direct TCP route may already fill the bottleneck.

## Reproducible Linux netem suite

The root-only integration script creates isolated client and relay network
namespaces connected by a veth pair. Its current test matrix is:

| Stage | Path profile | Cases | Pass condition |
| --- | --- | --- | --- |
| Bulk observation | 35 ms one-way delay on both interfaces, 0.5% independent loss each direction, 50 Mbit/s each direction | direct, Hysteria v2 (`quic` alias), TLS | every median is positive; ratios are retained |
| Controller gate | same 35 ms/50 Mbit/s path without random loss; a resettable receiver `INPUT` `iptables statistic nth` rule drops the 200th, 400th, … large sender datagram (0.5%); two warmups and five measured 4 MiB uploads/downloads | client-sender BBR/Reno and 15 Mbit/s Brutal; separate GSO-disabled BBR/Reno relay senders plus the capped Brutal relay sender | upload and download BBR/Reno equal-byte aggregate-goodput ratios are at least 1.10; every rule has non-zero counters and exactly `floor(eligible/200)` drops; Brutal upload and download each stay within 80%–115% of the declared target |
| Cold fallback | same delay/rate, random loss removed, unused UDP port | `auto` Hysteria attempt followed by TLS | first command completes within finite deadlines |
| Warm payload-phase gate | same delay/rate, loss-free, sequential 128 KiB downloads; timing excludes dial, tunnel-stream open, and request header | fresh direct TCP payload phases vs warm Hysteria v2 payload phases | Hysteria median/direct median is at least 1.10; this is not an end-to-end operation-latency claim |
| Authentication | controlled namespace path | wrong CA and wrong token | both are rejected for the expected reason |
| Live UDP failure | first proxy request over Hysteria, then both receivers silently blackhole the established UDP path in `INPUT` while TCP remains available | new TCP proxy flow in `auto` | pcap contains a UDP attempt followed by TCP/TLS, a receiver DROP counter is non-zero, the log contains a timeout-class QUIC failure and no `sendmsg EPERM`, and the flow completes within 10 seconds |
| Confidentiality smoke | pcap of Hysteria and fallback links | unique HTTP plaintext sentinel | sentinel is absent from both captures |

The source and sink benchmark is TCP. SOCKS5 UDP ASSOCIATE, source validation,
datagram framing, and policy behavior are covered by Go integration tests; a
production UDP workload should also be measured with an application-specific
loss/jitter metric rather than TCP goodput.

Run the suite on Linux with `iproute2`, `iptables`, `tcpdump`, `curl`, Python 3,
and root privileges:

```sh
make build
sudo ./scripts/netem-integration.sh ./bin/autocar
```

Override the declared profile explicitly:

```sh
sudo env \
  AUTOCAR_NETEM_DELAY_MS=50 \
  AUTOCAR_NETEM_LOSS=1% \
  AUTOCAR_NETEM_RATE=25mbit \
  AUTOCAR_BENCH_BYTES=4194304 \
  AUTOCAR_BENCH_ITERATIONS=9 \
  AUTOCAR_BENCH_WARMUP=2 \
  AUTOCAR_CONTROLLER_DROP_EVERY=200 \
  AUTOCAR_CONTROLLER_BYTES=4194304 \
  AUTOCAR_CONTROLLER_ITERATIONS=5 \
  AUTOCAR_CONTROLLER_WARMUP=2 \
  AUTOCAR_SHORT_FLOW_BYTES=131072 \
  AUTOCAR_SHORT_FLOW_ITERATIONS=9 \
  AUTOCAR_SHORT_FLOW_WARMUP=3 \
  AUTOCAR_MIN_SHORT_FLOW_RATIO=1.10 \
  AUTOCAR_MIN_BBR_RENO_RATIO=1.10 \
  AUTOCAR_MIN_BRUTAL_TARGET_RATIO=0.80 \
  AUTOCAR_MAX_BRUTAL_TARGET_RATIO=1.15 \
  AUTOCAR_ARTIFACT_DIR="$PWD/artifacts/netem" \
  ./scripts/netem-integration.sh ./bin/autocar
```

The script writes raw JSON, a summary, process logs, and packet captures under
`artifacts/netem`. It also retains `iptables --version`, including the
legacy/nft backend marker, and the actual per-case eligible/DROP counters. The
GitHub Actions netem workflow publishes the directory even when diagnosis is
needed.

## What the CI gate proves

The generic bulk path measurements are observations rather than a universal
speed claim. The controller and warm-payload gates are narrow and declared in
advance. On the deterministic-loss path, two warmups precede five measured
transfers, and both client-side uploads and relay-side downloads with BBR must
beat their Reno baselines by at least 1.10. The receiver-side matcher is reset
before every controller run. `--packet N-1` makes the Nth eligible datagram the
first drop rather than the first QUIC Initial, and a following counter rule
proves both the eligible denominator and exactly `floor(eligible/N)` drops.
Controller senders disable UDP GSO so a matched packet is one QUIC datagram
rather than a host-dependent batch.

Negotiated Brutal is exercised in both directions. Each equal-byte aggregate
goodput must remain between 80% and 115% of its truthful 15 Mbit/s target. The
lower bound rejects a controller that cannot sustain its declared rate; the
upper bound rejects a mislabeled/no-op Brutal path that is actually sending at
the 50 Mbit/s emulated link rate. The client JSON proves its upload controller
and negotiated rate. The download gate uses the separately configured relay
sender, while the raw client JSON intentionally labels only local Tx state.

On the loss-free high-RTT path, sequential warm Hysteria 128 KiB payload
phases must beat fresh direct TCP payload phases by at least 1.10. Because the
timer starts after dial and the request header, this checks warm data-phase
goodput, not complete short-flow setup or user-perceived latency. These checks
demonstrate the selected mechanisms under those profiles only.

Controller acceptance uses aggregate goodput across equal-size measured
transfers. This is the harmonic mean of the per-transfer Mbit/s values and is
equivalent to total bytes divided by total transfer time. Medians remain in the
artifacts for distribution context, but they do not discard a genuine slow
loss-recovery transfer from the acceptance result.

Do not lower `AUTOCAR_MIN_SHORT_FLOW_RATIO` or
`AUTOCAR_MIN_BBR_RENO_RATIO`, widen the Brutal window, or publish a CI ratio as
a universal production claim merely to hide a regression. Fixed nth loss is
repeatable but is not identical packet-number loss across controllers: packet
sizes and retransmissions can change the later sequence. BBR profile quality,
Brutal fairness, burst loss, reordering, ECN/AQM, concurrent sessions,
sustained high-loss behavior, and real-route improvement need the broader
retained matrix above.

The pcap sentinel assertion is a regression smoke test, not a cryptographic
proof. TLS 1.3, verified X.509, token authentication, optional mTLS, and the
threat model remain the security basis.
