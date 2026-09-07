# Isolated real-product stealth pilot

This pilot exercises real AutoCAR worktree binaries, the official pinned
v2.12.2 external baseline binary, and an ordinary standards-library HTTP/3 control.
Its purpose is to validate interoperability, workload generation, and PCAP
collection before paying the cost of the preregistered corpus.

The result is always **calibration / `insufficient_evidence`**. Two captures per
product and cell cannot establish that AutoCAR is less distinguishable than
the baseline. The control uses upstream quic-go v0.61.0 and is deliberately
recorded as **not a real browser**. A later claim-bearing campaign still needs
the preregistered browser diversity, sample count, held-out evaluation, and
statistical gates in `docs/STEALTH-BENCHMARK.md`.

## Safety boundary

`scripts/stealth-pilot.sh` has no SSH or remote-host mode. Before creating a
resource it requires a local Unix/npipe Docker endpoint and pre-existing local
images for the capture helper and baseline binary. It does not fetch, pull, or
contact a public endpoint. Go compilation uses `GOPROXY=off`; the pilot image is
`FROM scratch` and is built with `--network=none`.

Every runtime endpoint is a numeric RFC1918 address on one newly created,
explicitly labelled `--internal` Docker bridge. The origin and all three servers
are checked to be attached only to that bridge. The existing campaign driver
then creates a fresh client namespace per capture and limits tcpdump to the
declared endpoint IP, UDP port, and that namespace. The healthy-only pilot does
not install netem. It never accesses a host capture interface or changes host
routes, qdiscs, or firewall rules.

Secrets and private keys live in a mode-0700 temporary directory. Retained
configuration records contain only SHA-256 commitments, not secret values. The
temporary inputs and labelled Docker resources are removed on exit.

## Workloads

The default pilot records two independent samples for each product in three
`healthy_h3` cells:

- `idle`: establish one usable session with an empty response, then hold it
  quiet for 1.2 seconds;
- `download_1k`: fetch and verify one 1 KiB response; and
- `parallel_20`: issue twenty concurrent 1 KiB requests through one client
  process, allowing each proxy to multiplex streams over its H3 connection.

AutoCAR runs with `--transport h3` and `--h3-fingerprint chrome-2026-08`.
The baseline runs the pinned standard profile with Chrome QUIC parroting enabled,
its `Gecko` mode disabled, and a real reverse-proxy masquerade. Both proxies fetch the same
private deterministic HTTP origin. The H3 control fetches the equivalent
payload directly from its private H3 fixture server.

## Running

The runner intentionally refuses to download prerequisites. Confirm the local
inputs first:

~~~sh
docker image inspect autocar-stealth-capture:local
docker image inspect autocar-hy2-baseline:v2.12.2
scripts/stealth-pilot.sh --self-test
~~~

An already downloaded official binary may instead be supplied as
`STEALTH_PILOT_HYSTERIA_BINARY=/reviewed/path/hysteria-linux-arm64`. Its
architecture-specific preregistered SHA-256 and embedded version/commit are
checked before any server starts.

Run the default 18-PCAP pilot:

~~~sh
scripts/stealth-pilot.sh
~~~

For the cheapest end-to-end check first, run one cell with one sample per
product; this produces three PCAPs:

~~~sh
STEALTH_PILOT_WORKLOADS=download_1k \
STEALTH_PILOT_SAMPLES_PER_CELL=1 \
AUTOCAR_STEALTH_PILOT_DIR=artifacts/stealth-pilot/one-cell \
scripts/stealth-pilot.sh
~~~

Then omit those overrides for the default three-cell, two-sample pilot. The
retained directory contains `pilot-summary.json` and the campaign driver's
immutable plan, event ledger, manifest, and PCAPs. Both summary files must say
`insufficient_evidence`; a different status is treated as a harness failure.

Feature extraction is a separate offline step. A missing host `tshark` does not
change the product result; use a reviewed containerized Wireshark CLI or install
the tool before running `scripts/stealth-passive.sh` against the completed
campaign. The pilot probes the configured capture image for `tshark`, attempts
the offline extractor, and retains `offline/tool-status.json`, the exact probe
stderr, and `offline/extraction.json`. If neither the image nor host provides
`tshark`, the summary says extraction `unavailable` and classification is not
run; this is never converted into a product failure or success.

The repository includes a pinned container wrapper for that follow-up step:

~~~sh
scripts/stealth-offline-container.sh \
  artifacts/stealth-pilot/<pilot>/campaign/capture-manifest.csv \
  artifacts/stealth-pilot/<pilot>/offline-container
~~~

Its image build may contact the package mirror to install the pinned Python and
TShark packages. Feature extraction, classification, and the retained audit run
afterward with `--network none`, read-only inputs, no packet decryption, and no
address columns in `features.csv`. The output directory must be new. A pilot
still finishes as `insufficient_evidence` when the preregistered sample gate is
not met.
