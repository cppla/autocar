# Benchmarking AutoCAR

AutoCAR includes a deterministic TCP source/sink so a direct route and the
dual-ended tunnel can be measured with the same payload. The benchmark reports
payload goodput in decimal Mbit/s. It is designed for repeatable comparisons,
not as proof that one transport is faster on every network.

## Basic comparison

The benchmark server defaults to `127.0.0.1:9000`. For a same-host test:

```sh
autocar bench-server
```

A remote-path comparison needs an explicit non-loopback opt-in:

```sh
autocar bench-server \
  --listen 0.0.0.0:9000 \
  --allow-public-benchmark
```

`bench-server` has no authentication. A remote caller can make it send or
receive substantial traffic up to the configured limits. Use a host and cloud
firewall to allow port 9000 only from the intended client and relay addresses,
run it only for a controlled test window, and stop it immediately afterward.
The CLI defaults to at most 64 MiB per transfer and 16 concurrent transfers;
keep `--max-bytes` and `--max-connections` no higher than the experiment needs.

From the client host, measure the direct route:

```sh
autocar bench-client \
  --transport direct \
  --target bench.example.com:9000 \
  --mode download --bytes 8388608 --warmup 1 --iterations 7 --json
```

Then measure through an already running relay:

```sh
autocar bench-client \
  --transport quic \
  --server relay.example.com:443 \
  --ca relay-ca.crt \
  --token-file relay-token \
  --target bench.example.com:9000 \
  --mode download --bytes 8388608 --warmup 1 --iterations 7 --json
```

Repeat with `--mode upload`. Use `--transport=tls` to characterize the TCP/TLS
fallback separately. For `--transport=auto`, the output transport label
describes the configured mode, not which path won an individual fallback
decision; use explicit modes when comparing transports.

The timer begins after the benchmark request header has been written and ends
after the payload plus a one-byte completion acknowledgement. Connection and
tunnel stream setup happen before that timer. For user-perceived latency,
measure the complete application operation separately.

## Fair-test checklist

1. Pin the exact AutoCAR build, configuration, client, relay and benchmark
   target for a comparison.
2. Keep the direct and tunneled destination identical. Document the different
   physical routes and relay placement; a relay can improve routing, add a
   detour, or both.
3. Run enough iterations in alternating order. Discard a declared number of
   warmups and retain every raw result, not only the best value.
4. Test multiple payload sizes and concurrency levels. Short flows emphasize
   setup and warm-state behavior; bulk transfers emphasize steady-state
   congestion control.
5. Record RTT, loss, reordering, MTU, bandwidth, CPU utilization and time of
   day. Confirm neither endpoint is CPU-limited.
6. Report median and the individual results. The emitted `p95_mbps` is the
   95th percentile of goodput, where larger is better; it is not a latency
   percentile.
7. Repeat on the real production path. Emulation is useful for regression
   testing but cannot reproduce every queue, middlebox or competing flow.

Why QUIC can help: many flows reuse one authenticated connection and its
congestion state, and loss in one ordered QUIC stream does not impose
application-level head-of-line blocking on other streams. Why it may not help:
the relay adds processing and distance, a single large clean-path TCP flow can
already fill the link, and AutoCAR currently uses quic-go's default congestion
controller rather than claiming a custom BBR implementation.

## Reproducible Linux netem suite

The repository includes a root-only integration script. It creates isolated
client and relay network namespaces connected by a veth pair, applies the same
delay/loss/rate policy in both directions, and runs:

- direct, QUIC and TLS download measurements;
- an `auto` connection whose UDP address is initially unavailable, verifying
  cold-start TCP/TLS fallback;
- an auto-mode proxy request that first succeeds over QUIC, followed by a
  client-side UDP/7443 drop and a second bounded request over TCP/TLS;
- wrong-CA and wrong-token rejection checks;
- a controlled warm-QUIC short-flow acceleration profile;
- an HTTP proxy request containing a unique plaintext sentinel; and
- a packet capture assertion that the sentinel is absent from the client-relay
  link.

On Linux with `iproute2`, `iptables`, `tcpdump`, `curl` and Python 3 installed:

```sh
make build
sudo ./scripts/netem-integration.sh ./bin/autocar
```

Defaults are 35 ms one-way delay on each side (approximately 70 ms base RTT),
0.5% independent loss in each direction, a 50 Mbit/s rate per direction, five
measured 1 MiB transfers and one warmup. They can be changed explicitly:

```sh
sudo env \
  AUTOCAR_NETEM_DELAY_MS=50 \
  AUTOCAR_NETEM_LOSS=1% \
  AUTOCAR_NETEM_RATE=25mbit \
  AUTOCAR_BENCH_BYTES=4194304 \
  AUTOCAR_BENCH_ITERATIONS=9 \
  AUTOCAR_BENCH_WARMUP=2 \
  AUTOCAR_SHORT_FLOW_BYTES=131072 \
  AUTOCAR_MIN_SHORT_FLOW_RATIO=1.10 \
  AUTOCAR_ARTIFACT_DIR="$PWD/artifacts/netem" \
  ./scripts/netem-integration.sh ./bin/autocar
```

The script writes raw benchmark JSON, a comparison summary, process logs and
the pcap under `artifacts/netem`. The GitHub Actions netem workflow publishes
that directory as an artifact.

The suite's general lossy-path bulk measurements are recorded without a speed
threshold. It separately applies one intentionally narrow acceptance profile:
loss-free high RTT, sequential 128 KiB downloads and three declared QUIC
warmups. Fresh direct TCP connections restart congestion state on every
iteration, while QUIC streams reuse the warm connection. The default gate
requires the warm QUIC median to be at least 1.10 times the direct median. This
demonstrates that the implemented connection-reuse acceleration mechanism is
effective under its stated conditions; it is not a universal production-speed
claim. `AUTOCAR_MIN_SHORT_FLOW_RATIO` can change the declared gate for a
different controlled environment, but a release should not lower it merely to
hide a regression.

Performance on a shared virtual runner remains noisy. A broader release claim
should cite retained results from the intended path and configuration, not the
controlled CI profile alone.

The pcap sentinel check is a useful regression smoke test, not a cryptographic
proof. The TLS 1.3 implementation, certificate validation and protocol threat
model remain the security basis.
