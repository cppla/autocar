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
6. Distinguish a warm shared QUIC connection from fresh direct TCP flows. That
   is a real short-flow benefit, but it must be stated in the test description.
7. Repeat on the intended production path. Emulation catches regressions but
   cannot reproduce every queue, middlebox, policer, or competing flow.

Why Hysteria/QUIC can help: streams reuse a warm authenticated connection and
its BBR delivery/RTT model; pacing uses the inferred BDP; explicitly enabled
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
| Controller gate | same 35 ms/50 Mbit/s path without random loss; resettable `iptables statistic nth` drops every 200th large sender datagram (0.5%); two warmups and five measured 4 MiB uploads/downloads | client-sender BBR/Reno/negotiated 15 Mbit/s Brutal; separate GSO-disabled BBR and Reno relays for the relay sender | both upload and download BBR/Reno equal-byte aggregate-goodput ratios are at least 1.10; medians, modes, and negotiation are also reported, and Brutal aggregate goodput reaches at least 50% of its declared upload target |
| Cold fallback | same delay/rate, random loss removed, unused UDP port | `auto` Hysteria attempt followed by TLS | first command completes within finite deadlines |
| Short-flow acceleration gate | same delay/rate, loss-free, sequential 128 KiB downloads | fresh direct TCP vs warm Hysteria v2 connection | Hysteria median/direct median is at least 1.10 |
| Authentication | controlled namespace path | wrong CA and wrong token | both are rejected for the expected reason |
| Live UDP failure | first proxy request over Hysteria, then client UDP output is dropped | new TCP proxy flow in `auto` | new flow completes over TLS within the 10-second bound |
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
  AUTOCAR_MIN_BRUTAL_TARGET_RATIO=0.50 \
  AUTOCAR_ARTIFACT_DIR="$PWD/artifacts/netem" \
  ./scripts/netem-integration.sh ./bin/autocar
```

The script writes raw JSON, a summary, process logs, and packet captures under
`artifacts/netem`. The GitHub Actions netem workflow publishes the directory
even when diagnosis is needed.

## What the CI gate proves

The generic bulk path measurements are observations rather than a universal
speed claim. Three controller-specific gates and one short-flow gate are narrow
and declared in advance: on the separate deterministic-loss path, two warmups
precede five measured transfers, and both client-side uploads and relay-side
downloads with BBR must beat their Reno baselines by at least 1.10. The loss
matcher is reset before each controller run and drops every 200th large sender
datagram. Controller senders disable UDP GSO so a matched packet is one QUIC
datagram rather than a host-dependent batch. Negotiated Brutal must deliver at
least 50% of its truthful 15 Mbit/s upload target. On the loss-free high-RTT
path, sequential warm Hysteria 128 KiB downloads must beat fresh direct TCP by
at least 1.10. These checks demonstrate the selected mechanisms under those
profiles only.

Controller acceptance uses aggregate goodput across equal-size measured
transfers. This is the harmonic mean of the per-transfer Mbit/s values and is
equivalent to total bytes divided by total transfer time. Medians remain in the
artifacts for distribution context, but they do not discard a genuine slow
loss-recovery transfer from the acceptance result.

Do not lower `AUTOCAR_MIN_SHORT_FLOW_RATIO` or
`AUTOCAR_MIN_BBR_RENO_RATIO` merely to hide a regression, and do not publish
the CI ratio as a universal production claim. BBR profile quality, Brutal
fairness, sustained high-loss behavior, and real-route improvement need the
broader retained matrix above.

The pcap sentinel assertion is a regression smoke test, not a cryptographic
proof. TLS 1.3, verified X.509, token authentication, optional mTLS, and the
threat model remain the security basis.
