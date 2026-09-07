# Web-cover camouflage and privacy regression gate

This document defines the evidence required before v1.0.1 may make a bounded
claim about the distinguishability of its web-cover mode against a fixed
external baseline. It is a compatibility and privacy regression suite for
systems owned by the operator. It is not a scanner, a firewall-evasion tool, or
a promise of universal unidentifiability.

Only after all gates pass may a report make this scoped conclusion:

> Under the versions, configurations, workloads, network profiles, sample
> sizes, models, and hosts recorded in the evidence manifest, AutoCAR was less
> distinguishable than the frozen baseline and retained a standards-based
> HTTPS/H2 path when UDP was unavailable.

Do not publish that conclusion unless every release gate in this document is
green. A smoke run proves that the harness works; it does not prove the claim.

The frozen 2026-09-07 pilot snapshot completed active checks in local Docker
and remote Linux, collected 65 calibration captures, and extracted 49 features.
Its passive result is `insufficient_evidence`, not browser indistinguishability
or a comparative advantage. These observations belong to that experiment
snapshot; they do not automatically validate later source commits.

## Safety boundary

Run the compatibility checks only in a dedicated Docker network or disposable
lab owned by the operator. `stealth-probe active` and `transition` require the
explicit `--isolated-lab` flag plus one or more exact `--allow-net` IP/CIDR
entries. Names are resolved once, every answer must be inside both the explicit
allowlist and private/loopback space, and subsequent dials use the selected
numeric address. Public and link-local addresses are always rejected. The
checked-in Docker driver:

- creates uniquely named and labeled containers, images, and an internal bridge
  network with no external route;
- uses a user-space gateway to blackhole UDP while continuing to forward TCP;
- never changes host firewall rules, routes, qdiscs, or interfaces;
- sends only valid H1, H2, H3, and CONNECT requests to the two configured lab
  services; and
- deletes only resources whose ownership label matches the current run.

It deliberately does not implement Internet scanning, malformed packet floods,
third-party probing, credential guessing, or any attempt to bypass a network's
security controls. Remote Linux validation means running the same isolated
Docker topology on a machine the operator controls.

## Frozen comparison baseline

The fixed baseline is the official **v2.12.2** (`app/v2.12.2`, commit
`619a6f8`) release selected by the acquisition helper below. Technical source
links, executable names and schema identifiers are retained for reproducibility;
they are not product-positioning claims.

| Architecture | Official release SHA-256 |
| --- | --- |
| `linux/amd64` | `6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94` |
| `linux/arm64` | `ebfacc1ec3a0edfd742cd68ce17f292a6092e606b9d11f99b035c1d888f3d709` |

`scripts/stealth-hysteria.sh fetch` downloads only that release asset and
refuses a checksum mismatch. The standard comparison configuration uses:

- a reverse-proxy masquerade serving the same origin as AutoCAR;
- `listenHTTPS` on the same numeric TCP port as the UDP listener;
- an ECDSA P-256 certificate shared by the product and cover controls;
- Chrome QUIC fingerprint parroting left enabled; and
- stateless reset disabled, which is the quieter v2.12.2 choice.

Comparing with the baseline's unconfigured default 404 is forbidden. Its
[server configuration](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
documents reverse-proxy masquerading and `listenHTTPS`; its
[client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
documents that Chrome QUIC parroting is enabled by default.

AutoCAR's default `chrome-2026-08` web-H3 profile deliberately uses the same
external QUIC fork revision, pinned as
`github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e`, and adds a
zero-length client source CID. This shared implementation is part of the test
provenance, not evidence that AutoCAR is baseline-wire-compatible or already
less distinguishable. Both effective configurations and binaries remain pinned
and hashed independently.

The baseline's `Gecko` mode is also exercised as a healthy tunnel by the Docker
run. It is recorded separately because the source documentation states that
obfuscation disables compatibility with standard QUIC/H3; presenting that mode
as an H3 cover result would be incorrect. Its `Mimic` mode requires root, Linux,
its kernel module, eBPF/XDP, and a real interface. The automated suite will not
attach it to a host interface. Test it
only on a disposable native-Linux interface and retain that evidence, or mark
that mode's comparison `insufficient_evidence`. Never infer its results from
Docker Desktop.

## Tool self-check

Run the deterministic checks before any Docker work:

```sh
make stealth-tools-check
```

This compiles and race-tests the Go compatibility helper, checks shell syntax,
and runs the feature-extractor and classifier self-tests.

## Active compatibility gate

A short local harness check is:

```sh
make stealth-active-smoke
```

On a low-memory remote Linux host, a non-release smoke run may use an AutoCAR
image and matching stealth-lab image that were built and transferred in advance:

```sh
STEALTH_RELEASE_GATE=0 STEALTH_RUN_ROLE=remote-linux \
  STEALTH_EXECUTION_HOST=198.51.100.10:22 \
  STEALTH_AUTOCAR_IMAGE=autocar:smoke \
  STEALTH_LAB_IMAGE=autocar-stealth-lab:smoke \
  ./scripts/stealth-active.sh
```

The two image variables must be supplied together and both images must already
exist in that Docker engine. Run the script from a valid AutoCAR Git checkout;
the harness still records and compares its starting and ending checkout state
even though it does not compile there. This path proves only that the smoke
topology runs; it does not bind the images to the current source tree and cannot
be used as release evidence. `STEALTH_RELEASE_GATE=1` rejects caller-supplied
images and always builds both images from the frozen Git archive for that run.

Every `remote-linux` run also requires `STEALTH_EXECUTION_HOST`. Run the command
from a direct SSH session to that machine; do not launch it through a jump host
or `ProxyJump`. The manifest records both the declared host or `host:port` label
and the SHA-256 fingerprint derived locally from
`/etc/ssh/ssh_host_ed25519_key.pub`. Each formal campaign freezes both the endpoint
and fingerprint in `testdata/stealth/preregistration.json`. The
release checker rejects a different endpoint, a different host key, a missing
host key, or an operator label that is merely self-consistent on another Linux
machine.

The public preregistration file contains a documentation-only address and a
synthetic SSH fingerprint, not a live test machine. Before a formal campaign,
replace both fields in a private experiment checkout and commit that exact
source and preregistration before collecting any samples. Keep that private
commit and its evidence together; do not publish operational host identifiers.
The public template is not a release-evidence registration, and sanitizing it
does not rebind or rewrite any previous campaign's frozen artifacts. Do not
change the scoring policy or host identity after capture begins.

The release-size run is intentionally explicit and takes longer:

```sh
STEALTH_ITERATIONS=100 STEALTH_RELEASE_GATE=1 \
  STEALTH_RUN_ROLE=local-docker \
  ./scripts/stealth-active.sh
```

Use `STEALTH_RUN_ROLE=remote-linux` on the operator-controlled Linux host. A
release-size run rejects an unspecified role, the required `Gecko` check being
disabled, a dirty starting or ending worktree, or any source/HEAD change during the run. Its two
images are built from a `git archive` snapshot of the starting commit rather
than from a mutable live worktree.

`STEALTH_RELEASE_GATE=1` refuses fewer than 100 repetitions. Each iteration
uses new H1, H2, and H3 connections and randomizes whether the relay or its
cover-only control is queried first. Stable response fields must match exactly:

- negotiated HTTP version, TLS version, and ALPN;
- status;
- normalized headers; and
- body length and SHA-256.

Only `Date`, `X-Request-Id`, `Traceparent`, and latency are excluded from exact
semantic comparison. A stable `Server` header, product string, custom
`autocar/2` ALPN, status, or body difference is a failure.

The AutoCAR matrix covers ordinary GET, HEAD, POST, and OPTIONS requests plus
missing, same-length wrong, and replayed CONNECT credentials. The missing and
wrong requests use the same counted target as a valid request; every individual
negative request and replay must retain the exact counter value throughout a
100 ms quiet window. It also submits a
normal baseline-shaped `/auth` request to verify that web mode has no legacy
special case. A counted echo target proves that missing, wrong, and replayed
credentials caused no destination connection, while fresh authenticated H2
and H3 CONNECT requests each opened exactly one.

The baseline matrix uses a separate cover-only control whose `Alt-Svc` lifetime
matches the baseline's 30-day value. This avoids manufacturing a failure by
comparing it with AutoCAR's different but valid `Alt-Svc` formatting. Wrong and
missing `/auth` requests are compared against the real reverse-proxy cover, not
against a default 404.

### UDP-unavailable reliability

The `transition` check keeps one `WebClient` alive through all three stages:

1. the gateway receives and silently drops UDP, while TCP reaches the same
   numeric relay port;
2. the first and immediate second authenticated flows succeed over H2; and
3. after UDP forwarding is restored and the declared base cooldown plus its
   bounded jitter expires, one new probe succeeds over H3.

The output must show paths `h2, h2, h3`, dropped UDP datagrams, a TCP fallback
connection, and forwarded UDP request/reply datagrams after restoration. This
is stronger evidence than starting a fresh client for each phase.

The same gateway first proves the pinned baseline client works with UDP, then
starts a fresh baseline client while UDP is blackholed. A new proxied flow must
fail even though its TCP `listenHTTPS` cover remains configured. That
TCP cover is then exercised over both H1 and H2 through that same UDP-disabled
gateway. This is an availability comparison, not a passive-fingerprint score.

Artifacts are written under `artifacts/stealth-active/<run-id>/`. The manifest
derives its top-level status from the child results. A missing or failed
comparator is `insufficient_evidence`, never `pass`; release evidence is
complete only when all required children pass. The manifest records image IDs,
the starting and ending AutoCAR commit/tree, run role, internal network CIDR,
one-way Docker-engine fingerprint, iteration count, clean-worktree state, and
whether the source remained stable.
Token and key material remain in a mode-0700 temporary directory and are not
copied into artifacts.

## Passive capture contract

Passive evidence must come from isolated connections captured in the owned lab.
The extractor, classifier, and release checker remain offline-only.
scripts/stealth-campaign.py is the separate capture orchestrator. It has no SSH
support, refuses remote Docker contexts, and runs only against a pre-created,
explicitly labelled, internal Docker bridge. It never opens a host capture
interface. For each sample it creates a new client network namespace, joins a
tcpdump sidecar only to that namespace, and applies a BPF restricted to the
declared numeric RFC1918 server IP and port. It then starts one fresh,
read-only, capability-free workload container. Do not capture a production host
or unrelated containers.

The server containers must carry the same exact campaign ownership label, be
running, and be connected only to that internal bridge. Delay and loss are
applied with a campaign-specific netem handle inside the fresh client and
dedicated server container namespaces; a pre-existing non-default root qdisc is
a hard failure. The driver never changes a host qdisc, route, firewall, or
interface. Cleanup verifies the ownership label and qdisc handle before
removing anything.

Build the local capture helper (this does not start a capture):

~~~sh
docker build -f scripts/stealth-capture.Dockerfile \
  -t autocar-stealth-capture:local .
~~~

Copy and review
[campaign-driver.example.json](../testdata/stealth/campaign-driver.example.json).
Its lab network and every server container must already exist with the same
explicit campaign ownership label. Runner commands are argv arrays, never shell
strings. They receive only documented placeholders and must implement one
workload/session, then exit; the new container and network namespace ensure no
connection or client state is shared with another sample. All bind mounts are
required to be read-only and below an explicit allowed_mount_roots entry.

A one-cell, one-sample-per-product calibration is:

~~~sh
python3 scripts/stealth-campaign.py \
  --mode calibration \
  --cell healthy_h3/download_1k \
  --config /path/to/reviewed-campaign-driver.json \
  --output /new/path/calibration-01
~~~

Calibration verifies the topology and capture contract but writes campaign
status insufficient_evidence; it is never release evidence. Omit --cell to
exercise all 21 cells at calibration scale.

After committing the exact preregistration and release source, the complete
schedule is frozen by:

~~~sh
python3 scripts/stealth-campaign.py \
  --mode full \
  --config /path/to/reviewed-campaign-driver.json \
  --output /new/path/campaign-01
~~~

Full mode expands to the exact 31,500 required comparison PCAPs, plus the
declared real-browser H2 control sessions. It requires a clean worktree, the
checked-in preregistration, the pinned baseline binary, two distinct cover
client implementations, two distinct cover servers, and a real-browser variant
with both H3 and H2 commands. --max-samples N creates an intentional checkpoint
and exits 3; continue with the same arguments plus --resume. The immutable plan
binds the schedule, Git state, input files, Docker network, images, containers,
and engine. A changed input makes resume fail closed.

Each sample has exactly one attempt. The retained ledger must contain adjacent
`sample_started` / `sample_complete` pairs in frozen schedule order. A failed,
repeated, interleaved, or interrupted attempt invalidates that campaign for
formal evidence. Checkpoint only after a completed sample using `--max-samples`;
killing an in-flight workload is not a resumable checkpoint. Preserve failed
campaigns for diagnosis; do not automatically rerun campaigns until one passes.

Both proxy workloads explicitly send `Proxy-Connection: keep-alive` on their
local HTTP/1.1 proxy hop. This matches the pinned baseline proxy's persistence
contract; both proxies strip the header before forwarding, and the fixture
rejects a leaked header. Direct browser controls do not carry it. Every baseline
client and server starts with `--disable-update-check` to exclude unrelated
updater streams. These harness corrections were made during calibration, before
the formal corpus; affected earlier calibration captures are inadmissible.

Each campaign must include all cells frozen in
[`testdata/stealth/preregistration.json`](../testdata/stealth/preregistration.json):

- H3 with no injected impairment;
- 35 ms one-way delay with 0.5% loss;
- 100 ms one-way delay with 2% loss; and
- idle, 1 KiB/128 KiB/1 MiB downloads, 1 MiB upload, 20 parallel requests, and
  an interactive bidirectional workload.

There are 21 required cells: three network scenarios times seven workloads. For
every cell, collect at least 500 independent samples for each of `cover`,
`autocar`, and `hysteria2`, distributed across at least five independently
shuffled run/seed groups with at least 100 samples per product/cell/group. The
minimum complete corpus is therefore `21 × 3 × 500 = 31,500` PCAPs. Real browser
H2/H3 traffic and more than one ordinary server implementation should be present
in the broader cover corpus. Do not split packets from one connection across
train and test.

The capture manifest schema is shown in
[`testdata/stealth/manifest.example.csv`](../testdata/stealth/manifest.example.csv).
`client_ip` and `server_ip` establish direction during extraction. They and the
PCAP path are not emitted to the feature table.

The driver also binds every row to client_implementation,
server_implementation, implementation_version, immutable runner image ID,
server container ID, capture-host label, and Docker-engine fingerprint. These
provenance fields remain in the manifest and append-only event ledger but are
not model inputs. This prevents campaign-level browser or cover diversity from
being supported only by an untraceable JSON assertion.

The extractor resolves every PCAP to a canonical path and rejects reuse of
either that path or its SHA-256 bytes under another sample ID. It hashes each
capture before and after parsing to detect mid-run replacement, records the
per-sample digest (without its path) in `extraction.json`, and similarly rejects
a manifest that changes during extraction.

Extract and score a completed campaign with:

```sh
./scripts/stealth-passive.sh /path/to/manifest.csv artifacts/stealth-passive/run-01
```

Use a new output directory for every campaign. The wrapper refuses to
overwrite `features.csv`, `extraction.json`, or `scores.json`, preventing an
older green score from surviving a failed extraction.

The extractor requires `tshark` and reads only unencrypted observer fields:
packet lengths, direction, inter-arrival times, bursts, duration, visible
retransmission flags, and visible TLS/QUIC handshake counts. It does not use
keys, decrypted HTTP fields, IPs, ports, certificate identity, filenames, or
sample IDs as model inputs.

The classifier freezes three model families rather than selecting whichever
one favors AutoCAR:

1. a single-feature rule;
2. L2-regularized logistic regression; and
3. a depth-3 decision tree.

Every prediction is group-held-out by the combined `run_id + seed`. The report
contains ROC-AUC and TPR at 1% FPR for every product/model/cell. Confidence
intervals use a paired block bootstrap: all declared cells from one `run_id +
seed` stay in the same resampled block, avoiding false precision from treating
correlated cells as independent. Lower is better.

## Pre-registered decision rule

All three model families must satisfy all of these conditions:

- in every healthy H3 cell, AutoCAR's TPR at 1% FPR is no more than 2 percentage
  points worse than the baseline's;
- no other declared cell regresses by more than 2 percentage points;
- across every declared cell and paired run/seed group, AutoCAR lowers TPR at
  1% FPR by at least 5 percentage points on the block-weighted aggregate; and
- the upper endpoint of the deterministic 20,000-resample paired 95% bootstrap
  interval for `AutoCAR - baseline` remains below zero.

Every cell is reported. An aggregate cannot hide a regression. The possible
decisions are:

| Status | Meaning |
| --- | --- |
| `pass` | The complete pre-registered superiority and non-regression gates passed. |
| `tie` | Evidence is complete, but the margin or confidence bound does not prove superiority. |
| `fail` | A pre-registered regression bound was exceeded or a tool failed. |
| `insufficient_evidence` | A PCAP, product, cell, group, dependency, or minimum sample count is missing. |

Missing evidence never becomes zero detections and never produces green output.
Changing the preregistration after observing scores invalidates the campaign;
record its Git commit and SHA-256 before capture.

All machine-readable tools use the same status vocabulary: `pass`, `tie`,
`fail`, and `insufficient_evidence`. Operational errors are `fail`; absent or
incomplete observations are `insufficient_evidence`.

### Offline release evidence gate

The normal `make release` target is fail-closed. It will not build release
archives until `scripts/stealth-release-check.py` has verified:

- distinct `local-docker` and `remote-linux` release-size active manifests;
- a schema-v3 remote manifest whose `execution_host`, the explicitly supplied
  expected remote host, and the checked-in preregistration all match exactly;
- distinct Docker-engine fingerprints for those two roles;
- `pass` child results, internal-network proof, clean/stable source state, and
  the same exact commit in both manifests;
- the actual capture manifest, feature table, extraction report, and score
  report by SHA-256, including every current PCAP against its recorded digest;
- a `pass` passive decision from all three preregistered models; and
- campaign metadata matching
  [`campaign.example.json`](../testdata/stealth/campaign.example.json), including
  pre-capture registration time, pinned binaries/configurations, and at least
  two distinct cover client and server implementations with real-browser H2/H3
  traffic.

Provide the evidence paths explicitly:

```sh
make release VERSION=v1.0.1 BUILD_DATE=2026-09-04T00:00:00Z \
  STEALTH_EXPECTED_REMOTE_HOST=198.51.100.10:22 \
  STEALTH_LOCAL_ACTIVE=/path/to/local/manifest.json \
  STEALTH_REMOTE_ACTIVE=/path/to/remote/manifest.json \
  STEALTH_EXTRACTION=/path/to/extraction.json \
  STEALTH_SCORES=/path/to/scores.json \
  STEALTH_CAMPAIGN=/path/to/campaign.json \
  STEALTH_CAPTURE_MANIFEST=/path/to/capture-manifest.csv \
  STEALTH_FEATURES=/path/to/features.csv \
  STEALTH_AUTOCAR_BINARY=/path/to/campaign/autocar \
  STEALTH_AUTOCAR_CONFIG=/path/to/effective-autocar-config \
  STEALTH_HYSTERIA_BINARY=/path/to/pinned/hysteria \
  STEALTH_HYSTERIA_CONFIG=/path/to/effective-hysteria-config
```

The gate is offline and read-only. Missing evidence returns
`insufficient_evidence`; malformed, duplicated, stale, dirty-worktree, or
digest-mismatched evidence returns `fail`. Passing the same active artifact as
both local and remote evidence is rejected.

## Release decision

The web-cover camouflage claim remains unproven until all of the following are
current for the exact release commit:

1. `make check` and `make race` pass;
2. the 100-iteration active compatibility gate passes in local Docker and on
   the operator-controlled remote Linux Docker host;
3. the offline score report returns `pass` for the frozen v2.12.2 baseline's
   standard profile;
4. the baseline's `Gecko` health/capture evidence is retained separately; and
5. its `Mimic` mode is tested on a disposable native-Linux interface, or the release
   explicitly limits its comparison claim and records that mode as
   `insufficient_evidence`.

The pinned ChromeParrot profile addresses known stock ClientHello, client
transport-parameter, CID and Initial-packetization differences, but it is a
client-only handshake profile shared with the comparator. Passing a functional
H3 test—or merely enabling that shared implementation—is not evidence of an
end-to-end classification advantage. Until the passive gate passes with fresh
captures, documentation must not claim that AutoCAR is undetectable or
universally superior.
