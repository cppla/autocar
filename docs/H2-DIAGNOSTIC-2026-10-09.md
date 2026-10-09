# HTTP/2 endpoint diagnostic: Chrome and AutoCAR

## Outcome and scope

This bounded macOS arm64 diagnostic found different HTTP/2 settings and flow
control in the tested AutoCAR client and installed Chrome. Changing AutoCAR's
TLS ClientHello profile did not change the measured H2 settings. **The browser
acceptance procedure was incomplete**, so this is a partial diagnostic with
`insufficient_evidence`, not a passed browser-similarity test.

The observer terminates TLS and reads decrypted H2 frames. These observations
are not plaintext features available to an ordinary passive network observer.
No packet capture, timing analysis, classifier, throughput comparison or
successful authenticated tunnel was part of this run. Production behavior,
default profiles and release evidence requirements were not changed.

## Procedure

- AutoCAR source: `0c17d9faa81c2e7a16e1ab7e42f98df30598a87a`, built with
  Go **1.27.2**, `golang.org/x/net` **v0.60.0**, using its Go 1.27 HTTP/2 wrapper.
- Nine fresh AutoCAR clients, in order: `native`, `chrome-133`, `chrome-155`,
  three attempts each. Each opened one CONNECT with a synthetic lab token.
  The observer returned a small HTML 200 without an authentication proof;
  the expected outcome was authentication rejection, never a usable tunnel.
- Three sequential, fresh, nonpersistent Playwright CLI **0.1.22** sessions
  using installed Google Chrome **154.0.8037.95**, configured headed, each
  navigating once to the same loopback HTTPS origin and then closing. This
  browser version is **not** the historical Chrome 155 ClientHello fixture.
- Requested lab settings: QUIC disabled, no proxy, and a certificate-specific
  SPKI exception. `ignoreHTTPSErrors` was false; no system trust-store change
  or normal browser profile was used. Actual launch arguments could not be
  retrieved through CDP, as explained below; these are configured settings,
  not independently verified runtime arguments.
- Both modes used the identical frozen observer binary and server SETTINGS,
  but separate ephemeral origins/certificates. This is not a paired same-origin
  or same-request workload. The AutoCAR client verified its ephemeral certificate
  through an explicit test root pool.
- The observer offered only TLS 1.3/h2 on `127.0.0.1`. Its initial SETTINGS in
  order were `HEADER_TABLE_SIZE=4096`, `MAX_CONCURRENT_STREAMS=32`, and
  `MAX_HEADER_LIST_SIZE=16384`. It answered only the first request, then closed;
  connection reuse, resumption and subsequent proxy traffic were not measured.
- Limits: 180 seconds per observer, 32 accepted connections, 15 seconds per
  connection, 64 physical frames including CONTINUATION, 1 MiB of frame input,
  16 KiB frame payloads and decoded header lists. Header values and private
  keys were never serialized. Unknown header names were replaced with `other`.
  Inherited HTTP/2 debug logging was removed before process startup.

The plan and collector were frozen before collection. All first attempts were
retained; there were no replacement samples or navigation retries. Browser and
collector executable hashes matched before and after collection.

## Completion ledger and instrumentation failure

| Evidence | Recorded result |
| --- | --- |
| AutoCAR endpoint observation + response + exact expected auth rejection | 9 / 9 |
| Successful authenticated tunnels | 0, intentionally |
| Browser CLI page loads and endpoint TLS 1.3/h2 observations | 3 / 3 |
| Saved browser Resource Timing `h2` and HTTP 200 | 2 / 3 |
| Saved CDP product `Chrome/154.0.8037.95` | 2 / 3 |
| Runtime launch arguments returned by CDP | 0 / 3 |

The first inspector called `Browser.getBrowserCommandLine` before saving its
navigation measurements. Chrome rejected that query because the automation
switch required by the query was not set. The inspector aborted, and that
session was closed before the missing metadata was noticed. Its successful
page load and endpoint observation remain, but its Resource Timing/product
record cannot be recovered or represented as a pass.

A separately retained inspector revision saved navigation and product data
first for trials 2 and 3, recording the same command-line rejection explicitly.
The browser launch configuration, observer and navigation count did not change.
This was an instrumentation amendment **after trial 1**, not a clean rerun of
the original plan. There were no endpoint connection failures, but the missing
browser metadata prevents declaring the planned acceptance complete.
The browser collector records `trial=0`; connection indices 1, 2 and 3 were
associated with trials by the controlled sequential launch/close logs, not an
embedded per-trial marker. Those raw records were not relabeled.

## Endpoint observations

All nine AutoCAR observations had the same following settings/window values;
all three browser endpoint observations had the same other set. The first
browser observation is retained despite its incomplete browser-side metadata.

| Field | AutoCAR, all three profiles | Installed Chrome 154 |
| --- | --- | --- |
| Initial SETTINGS IDs in wire order | `2, 4, 5, 6` | `1, 2, 4, 6` |
| HEADER_TABLE_SIZE (ID 1) | Omitted; protocol default 4,096 | 65,536 |
| ENABLE_PUSH (ID 2) | 0 | 0 |
| INITIAL_WINDOW_SIZE (ID 4), per stream | 4,194,304 | 6,291,456 |
| MAX_FRAME_SIZE (ID 5) | 1,048,576 | Omitted; protocol default 16,384 |
| MAX_HEADER_LIST_SIZE (ID 6) | 262,144 | 262,144 |
| First connection WINDOW_UPDATE increment | 1,073,741,824 | 15,663,105 |
| Connection credit after that increment | 1,073,807,359 | 15,728,640 |

The final row adds the protocol's initial 65,535-byte connection window; a
WINDOW_UPDATE value is an **increment**, not the resulting window. Omitted
settings retain protocol defaults. See [RFC 9113 sections 6.5.2 and 6.9.2](https://www.rfc-editor.org/rfc/rfc9113.html).

AutoCAR's first CONNECT pseudo-headers were `:authority, :method`. Chrome's
GET pseudo-headers were `:method, :authority, :scheme, :path`. These methods
have different required semantics; omitting scheme/path for ordinary CONNECT
is not itself a defect ([RFC 9113 section 8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5)).

AutoCAR sent only the regular names `proxy-authorization` and `content-type`,
in that order for eight samples and reversed for one. Chrome sent, in order:
`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`,
`upgrade-insecure-requests`, `user-agent`, `accept`, `sec-fetch-site`,
`sec-fetch-mode`, `sec-fetch-user`, `sec-fetch-dest`, `accept-encoding`,
`accept-language`, `priority`. Values were not retained. These small samples
do not establish a general distribution or justify adding browser GET headers
to a CONNECT request.

## Engineering consequence

The current H2 profiles remain ClientHello profiles, not complete browser H2
implementations. Keep that boundary explicit. This observation does not justify
rewriting SETTINGS on the wire, loosening response-header limits, or advertising
windows that the implementation cannot safely handle.

Any later numeric tuning needs its own performance and resource tests, including
concurrency, cancellation, flow control, half-close and shutdown. A later browser
acceptance run should fix the metadata collection **before** freezing the plan.
Neither step substitutes for a held-out passive-traffic evaluation. This run
does not cover Linux, Firefox, Chrome 155, H3, warm reconnects or ordinary human
browsing behavior.

## Local provenance

The exploratory collector source, its tests, frozen plan, both inspectors,
amendment, launch configuration, CLI outputs and endpoint JSONL are retained
locally in ignored `output/playwright/h2-20261009/`. The collector is a local
experiment, not a new supported production command. Its fragmentation, HPACK
CONTINUATION, frame-budget and redaction tests passed under `-race -count=10`.
No remote test machine or production service was used. All three named browser
sessions and the bounded observer were closed.

The following hashes identify retained local files, not independently hosted
or third-party-verified evidence. `result.json` preserves the partial status
and the browser metadata failure, not just the successful endpoint records.

| Artifact | SHA-256 |
| --- | --- |
| Frozen plan | `16228fde30b1f32450e1cdc678c405243e60285d195e4bde52e994ca9e18eb97` |
| Observer source | `ca85877bb652e91030bd85c90677f644a16ac112a4012d3bd2fa543827657aaf` |
| Observer binary | `91a229c47fbcbed5a58643e02b73cd863f36722b76b4b8426e62ca532fa4b1a1` |
| AutoCAR endpoint log | `25fadd4afedfc6e1d3dfa74b03de3f332a186ecb7e2268c68b57646f12990345` |
| Browser endpoint log | `d3fabbbde4e0d1f1b6725764d2358257ded2ac1c8f570d23571e16b3de10f421` |
| Result summary | `43a7230092d69a5788eb127bb8ff5e25e5f8ea16c5dae6f4fc85e185a38d7c48` |
| Chrome framework | `3e7345002bb1a709aeb25d4f52c008aed78d94dd71be679d66e868cbc4e01147` |
