# Loopback HTTP/3 connection diagnostic

This small test origin assigns an ID to each admitted physical QUIC connection.
It helps inspect whether a browser navigation and subsequent fetch reuse a
connection, and whether a later physical connection resumes TLS. It is not an
AutoCAR proxy, a formal corpus generator, or a
production traffic optimization.

An explicitly limited [Chrome diagnostic](DIAGNOSTIC-2026-09-22.md) records one
local six-trial run, including readiness failures and evidence boundaries.

## Run the local fixture

Provide an existing certificate whose SAN covers the chosen loopback address,
and its matching private key with the normal AutoCAR file permissions. The
fixture never generates or replaces credentials.

```sh
go run ./scripts/browser-connection-fixture \
  --listen 127.0.0.1:0 \
  --cert /absolute/path/lab.crt \
  --key /absolute/path/lab.key \
  --duration 180s --max-requests 64 --max-connections 32
```

Only the exact numeric addresses `127.0.0.1` and `[::1]` are allowed. Port zero
selects a free UDP port; the first JSON stdout record reports that address.
The server provides HTTPS over HTTP/3 only, with no TCP/H2 listener. Duration
must be positive and at most 600 seconds; request and lifetime admitted-connection
budgets are respectively 1–64 and 1–32. Excess requests receive 429 and excess
connections are closed. Duration expiry or interruption stops the listener.

In a fresh, dedicated browser profile configured for this lab's H3 origin and
certificate, navigate to `/`, then fetch `/probe?trial=s1-omit` using
`credentials: "omit"`. Repeat in another fresh profile with
`credentials: "same-origin"` and a different trial label. Labels accept 1–32
ASCII letters, digits, underscores or hyphens. Only body-free GET/HEAD requests
are accepted.

The response header `X-Diagnostic-Connection-ID`, `/probe` JSON and request
log's `connection_id` identify server-observed connections within this run.
Request logs contain only fixed fields and validated trial labels, not cookies,
authorization headers, arbitrary URLs or peer addresses. Do not infer browser
H3 from an exit code alone: verify navigation and fetch Resource Timing report
`h3`, and retain browser version, launch settings and server logs. Merely opening
an HTTPS URL does not configure H3; use browser-version-appropriate lab settings
and certificate trust or a narrowly scoped lab pin.

Requests and `/probe` responses also contain a small `tls` object:
`handshake_complete`, `did_resume`, numeric `version` (772 for TLS 1.3), and
`alpn` (`h3` for this origin). Missing TLS state is explicitly `null`, not an
assertion that a handshake was cold. Unexpected nonempty ALPN values are
replaced by `<other>`; tickets, keys, certificates and arbitrary TLS fields are
never serialized.

Each admitted connection emits exactly one `connection_closed` record with
only `kind` and `connection_id`, after its actual QUIC context ends. Request or
stream completion does not produce that event. Observer count is bounded by the
connection budget, and shutdown joins observers before returning. No close
reason is exposed: the event proves physical closure, not which peer or timer
caused it. Filter by `kind` instead of assuming every line after `ready` is a
request.

For a warm-reconnection diagnostic, keep the same browser process/context,
fixture instance and certificate. Check cold and same-origin reuse requests
have the same ID and `did_resume: false`; wait for that ID's actual close event
without sending target requests; then require a different ID, successful H3
response and `did_resume: true`. Save runtime browser version and command line
before target navigation. Server-observed browser TLS state is not both-peer
instrumentation or wire-level proof about 0-RTT. See the bounded
[warm-reconnection observation](DIAGNOSTIC-2026-10-09.md), including its initial
readiness failure.

## Separate from the WebDriver workload diagnostic

The [existing runner](../stealth-browser/README.md#optional-credentials-diagnostic)
uses a numeric RFC1918 origin, its fixed bootstrap document and a verified
`download_1k` payload. It rejects loopback and this fixture does not implement
that workload contract. Its optional credentials diagnostic has a distinct
`insufficient_evidence` receipt; the default formal workload and receipt remain
unchanged.

Keep this `/probe` experiment in its own artifact directory and label it as
calibration/diagnosis. A local browser/version result neither reproduces an
older frozen campaign automatically nor establishes passive indistinguishability.
