# Chrome connection reuse: bounded local diagnostic

## Scope

This is a six-trial, macOS arm64 loopback diagnostic, not a formal corpus,
packet-fingerprint comparison, production benchmark or proof of
indistinguishability. No AutoCAR client/proxy traffic was generated. The normal
WebDriver workload and historical samples were not changed.

Before paired collection, Chrome readiness passed with H3 navigation and fetch.
Playwright Firefox 156.0 (build 1549) failed two separately recorded readiness
attempts with `NS_ERROR_CONNECTION_REFUSED`, first at the fixture's explicit
port and then with a default-port origin. Firefox was excluded **before** the
paired plan was frozen; it supplies no usable samples or conclusion here. Its
failure cause remains unresolved.

## Fixed procedure

- Google Chrome **153.0.8010.52**, headless, controlled by Playwright CLI
  **0.1.21**, with a fresh isolated session for every trial.
- Same H3-only fixture, certificate, origin (`https://127.0.0.1:53223`) and
  browser configuration throughout. No TCP/H2 fallback or cookies set.
- Chrome lab flags: `--enable-quic`, `--origin-to-force-quic-on=127.0.0.1:53223`,
  the certificate-specific `--ignore-certificate-errors-spki-list`, and
  `--no-proxy-server`; no global trust-store change.
- Navigate to `/` and await load, then make one immediate fetch to
  `/probe?trial=<label>` with `cache: "no-store"`. Only `credentials` changes
  within each pair. Labels identify trials; they are not random payload seeds.
- Fixed order: omit/same-origin, same-origin/omit, omit/same-origin. No retries.
- Accept only HTTP 200 for both requests, browser Resource Timing `h3` for both,
  and matching server log, response header and JSON connection identifiers.
- Plan frozen before the first paired navigation; 540-second whole-run limit,
  40-second trial limit. Six paired trials completed in **26.69 seconds**.

## Observations

IDs are allocated once per admitted physical QUIC connection, not per request.
All six trials passed the acceptance checks.

| Trial | Fetch credentials | Navigation ID | Fetch ID | Distinct connections |
| --- | --- | ---: | ---: | ---: |
| pair1_omit | omit | 1 | 2 | 2 |
| pair1_same_origin | same-origin | 3 | 3 | 1 |
| pair2_same_origin | same-origin | 4 | 4 | 1 |
| pair2_omit | omit | 5 | 6 | 2 |
| pair3_omit | omit | 7 | 8 | 2 |
| pair3_same_origin | same-origin | 9 | 9 | 1 |

In this environment, changing fetch credentials mode changed navigation/fetch
connection reuse in all three pairs. This demonstrates a measurement confound
worth controlling, not a reason to rewrite a frozen campaign or add dummy
connections to a proxy. It does not establish behavior in Firefox, historical
browser versions, remote Linux, or real-world browsing workloads.

## Local provenance

The isolated collection is retained locally under
`output/playwright/browser-connections-20260922/`, ignored by Git. It contains
the driver, frozen plan, CLI command outputs, server NDJSON, readiness report,
configuration and results. Raw local artifacts and lab keys are not published;
the hashes below identify those retained files, not independently hosted
evidence. Browser executable/framework and runtime hashes matched before and
after collection. Result status remains `insufficient_evidence`.

| Artifact | SHA-256 |
| --- | --- |
| Frozen plan | `2e2c198009c35ec1572560eb023a5aedbc024b05d8e25b6f280908c1286975de` |
| Results | `9df847240cc8bfc87a6cb95802f32ad606d14e92c14a622e07a9a549b73a88c0` |
| Server request log | `20e92e868a5ba526a58234b266b9131fcd0120804f393d3e6ee57169a7114157` |
| Chrome framework | `f9a7642e684d186ccbce18204594171b4bc548276a7c9e546ef0e7ef97767ab3` |

This diagnostic deliberately does not change release evidence requirements.
