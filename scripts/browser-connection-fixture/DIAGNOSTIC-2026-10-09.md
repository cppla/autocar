# Bounded Chrome H3 warm-reconnection observation

This is a local diagnostic, not a passive fingerprint comparison or a formal
corpus. Chrome successfully resumed TLS on a new physical H3 connection in
three admitted trials after one successful readiness check. An earlier
readiness attempt failed in the collection script and remains a separate failed
experiment; it was not replaced inside the successful experiment.

## Setup and frozen procedure

The 2026-10-09 run used macOS/arm64, Chrome **154.0.8037.95**, Playwright CLI
**0.1.22**, and Playwright **1.64.0-alpha-1790635538000**. The observer was built
with Go **1.27.2** from base commit
`932e56ca1210d264c682dacf35538a576915d74c` plus this fixture change. It uses the
official `github.com/quic-go/quic-go` **v0.63.0** HTTP/3 server, not the AutoCAR
web-H3 client or its maintained dependency replacement.

One fixture instance served the entire successful experiment, with the same
lab certificate and TLS ticket keys. It listened only on numeric IPv4 loopback,
had a 540-second lifetime, 64-request/32-admitted-connection budgets and the
unchanged 30-second idle limits. It had no TCP listener. The certificate had a
loopback SAN and a one-day validity; no system trust store was changed.

Each readiness/trial used a separately named, nonpersistent headless CLI
session. Within each trial the same process/context performed all three phases.
The four session startup PIDs were distinct and each session was closed. Raw
temporary profile paths were redacted, so the retained command lines do not
independently establish profile-path uniqueness.

Explicit lab flags were `--enable-quic`, one exact
`--origin-to-force-quic-on=127.0.0.1:<port>`, one exact
`--ignore-certificate-errors-spki-list=<lab-pin>`, `--no-proxy-server`, and
`--enable-automation`. Context `ignoreHTTPSErrors` remained false. Chrome's
headless/automation defaults, including its disable-feature flags, were retained
in sanitized runtime metadata. This is not a normal unmodified browser launch.

Before the first target navigation in each session, the collector saved
`Browser.getVersion` and a successful `Browser.getBrowserCommandLine`. It
required the expected product, headless mode and lab switches, rejected global
certificate bypasses/conflicting QUIC or proxy switches, and required exactly
one origin override and SPKI switch.

The successful experiment froze its plan, browser configuration and collector
at **10:22:26 UTC**, before any target navigation. Its fixed sequence was:

1. Navigate `/` once: HTTP 200, navigation Resource Timing `h3`, positive
   connection ID, and server TLS 1.3 complete with `did_resume: false`.
2. Fetch a unique `/probe?trial=<label>_reuse` with `credentials: "same-origin"`
   and `cache: "no-store"`: HTTP 200/H3, the same physical ID and cold TLS state.
3. Send no target request while waiting up to 50 seconds for that ID's actual
   `connection_closed` record. A fixed sleep alone would not pass this gate.
4. Fetch `<label>_warm` once in the same context: HTTP 200/H3, a different
   physical ID, and complete TLS 1.3 with `did_resume: true` in both the probe
   response and matching server request record.

No sample was retried or replaced in this successful experiment. Full server
logs were retained, including asynchronous closure events. Records must be
joined by physical ID: a previous session's final close can appear in the next
trial's log slice.

## Results and initial collection failure

| Experiment / sample | Cold / reuse / warm IDs | Server TLS resumed | Result |
| --- | --- | --- | --- |
| Initial readiness | 1 / 1 / not attempted | false / false / unknown | Collection failed |
| Revised readiness | 1 / 1 / 2 | false / false / true | Passed |
| Revised trial 1 | 3 / 3 / 4 | false / false / true | Passed |
| Revised trial 2 | 5 / 5 / 6 | false / false / true | Passed |
| Revised trial 3 | 7 / 7 / 8 | false / false / true | Passed |

The initial experiment `h3-warm-20261009` failed at 10:20:38 UTC because its
in-page Fetch collector called `response.status()` instead of reading
`response.status`. Its cold navigation succeeded and the server observed reuse,
but the complete reuse measurement and warm phase were not collected. **Zero
formal trials ran.** Its outputs and frozen inputs were left intact.

The separate `h3-warm-20261009-r2` amendment corrected that property access,
strengthened duplicate-flag and request-accounting checks, and used a fresh
fixture and named sessions without changing browser flags. It ran from
10:22:26 to 10:24:50 UTC. All twelve target requests returned 200/H3. Final
server accounting was one ready event, twelve requests and eight unique closure
events, with no extra target requests. Waiting after reuse took approximately
29.1–29.2 seconds; the remaining interval includes collection overhead. The
close event does not identify the initiator, so this is **observed physical
closure**, not proof of server-initiated idle expiry.

The stopped fixture had no remaining admitted connections. All named browser
sessions closed successfully. No remote host, Docker browser or packet capture
was used for this experiment.

## Provenance and independent functional checks

Local evidence is retained separately in
`output/playwright/h3-warm-20261009/` and
`output/playwright/h3-warm-20261009-r2/`; it is not a public downloadable corpus.
Plans, collectors, command receipts, snapshots, runtime metadata, server logs,
failures and final accounting are retained. Post-run checks confirmed unchanged
frozen inputs, observer source/binary and Chrome launcher/framework hashes.

Selected SHA-256 identities:

| File | SHA-256 |
| --- | --- |
| Observer `main.go` | `84767c3ba1e08389fb9e7d16a97e1da135da9d961f5c2faa2b95e400cbdb6b46` |
| Observer binary | `1adc1f834dbe4a0c516055dceb023c04e759c3356391d59d745f5ce42c10d4e6` |
| Revised frozen plan | `0ada62ac941532a01898d4d9403ea6ce4871d40d0010ccd568085792c33b3af0` |
| Revised collector | `068a2168b4cd3b14f893fcd667dc3dfaf49d653ba8fa01002f7875f32bbe120f` |
| Revised `results.json` | `80cf36ad39e3dd2a39060d6d4b547297c9f08ddfadb8ecbf39aac3687befc114` |
| Revised final server log | `e4bd61741ed6d5a83b986a8618d0381266818ce23b0f88b004d3e3dfd92e2592` |

The fixture's real-Go-peer tests verify cold/reuse/resume state, actual ticket
receipt, both peers' resumed state, physical identity changes, event schemas,
privacy, bounded observers and joined shutdown. Fixture race tests passed ten
repeats, followed by a separate three-repeat run; `make check` also passed.

Separately, ten existing AutoCAR H3 test groups passed three repeats with
`-race` and a 120-second limit:

```sh
go test -race -v ./internal/tunnel \
  -run '^TestWebH3(Resumption|ConnectionAuthMultiplexesOneFullTicket$|DefaultChromeInitialWireShape$|WirePacketCounterHandlesCoalescing$)' \
  -count=3 -timeout=120s
```

Those tests confirmed cold/reuse/reconnect states `[false false true]` for the
opt-in resumption path; default/disabled/rejected-ticket controls remained
`[false false false]`. Their wire tests found no outbound 0-RTT packets. This is
separate functional evidence, not a same-endpoint paired browser measurement.

## Evidence boundary

The browser result establishes **server-observed TLS resumption on a new H3
connection** in this bounded setup. It does not instrument the browser's own
TLS state or establish wire-level absence of browser 0-RTT. Lab target traffic
was loopback-only; the browser process was not OS-isolated from all background
network activity. It does not prove WAN reliability, throughput, passive
indistinguishability, or parity between installed Chrome 154 and the project's
fixed Chrome handshake template. No default profile, production transport or
release gate changed, and the canceled full corpus was not restarted.
