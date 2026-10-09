# Maintaining the compatibility forks

AutoCAR maintains two narrowly scoped compatibility forks. Both retain their
upstream module identities and use global **remote, exact-version** replacements:

| Use | Original module identity | Maintained source |
| --- | --- | --- |
| H2 and web-H3 TLS | `github.com/refraction-networking/utls` | `github.com/cppla/utls` |
| Web-H3 QUIC adapter | `github.com/apernet/quic-go` | `github.com/cppla/quic-go` |

Native transport continues to use official `github.com/quic-go/quic-go` without
a replacement. The web-H3 fork does not redirect that independent dependency.
Do not require/import either `github.com/cppla/*` replacement path directly:
that creates a second module/type identity instead of repairing the existing
dependency graph. Local replacements, version-scoped replacements, duplicate
identities and copied/vendor source bypasses are rejected by the boundary gate.

## uTLS source lineage

The uTLS module declaration and AutoCAR imports remain
`github.com/refraction-networking/utls`. A global **remote, exact-version**
`replace` in AutoCAR's `go.mod` selects the published fork for both H2 and the
web-H3 adapter's transitive imports. It is not a local source override.

The upstream baseline is
`v1.8.3-0.20261006222701-ff1b50fbbe9a`
(`ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67`). It requires Go 1.27;
AutoCAR's minimum supported toolchain is Go 1.27.2.

The initial compatibility patch queue fixes custom-QUIC shutdown signaling and
transport-parameter ownership after preset cloning. Its deterministic shutdown
and real QUIC-TLS parameter tests live in the fork; see
[the fork maintenance notes](https://github.com/cppla/utls/blob/master/FORK.md).
The session-resumption follow-up also propagates cancellation out of a paused
resume event, routes custom ClientHello build failures through QUIC channel
cleanup, and exposes a terminal TLS error once. Deterministic regressions cover
both custom and Go hellos, real verified tickets, cancellation and repeated Close.
AutoCAR separately checks the H3 Initial shape and reconnect contract. H2 now
uses upstream's PSK/HelloRetryRequest support on the same physical connection,
with fresh proxy authentication after reconnect, instead of the old
private-error-text-triggered cold redial. This does not change the explicitly
selected `chrome-133` or `chrome-2026-10` templates or establish passive browser
similarity. H3 resumption requires the separate QUIC adapter patch below; it is
not a consequence of merely replacing uTLS.

The separate H2 `chrome-155` option selects upstream's explicit
`HelloChrome_155`, never `HelloChrome_Auto`. It needs no further dependency
change. The older `chrome-133` remains distinct and is still selected when an
existing config omits the H2 profile; newly generated web bundles pin 155.
AutoCAR's real-wrapper cold-wire comparison retains the upstream browser
fixture, checksum, parser attribution and license under
`internal/tunnel/testdata/chrome155/`. This checks a bounded historical wire
reference, not browser equivalence or current-version freshness.

## Web-H3 QUIC source lineage

The web-H3 module keeps the original require
`github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c`, from the public
`v0.63.0-mod-rename` branch at exact commit
`a10df75c260cee8161f3261d63a37bd125a6bb2a`. The new maintained repository starts
from that published source, not an older default branch or an unpublished
experiment. The original module declaration and imports stay unchanged; only
the exact replacement selects `github.com/cppla/quic-go`.

The fork adds explicit opt-in browser-profile session resumption, its
regressions, and narrowly scoped test/build maintenance. It also fixes CRYPTO
tail offset and memory ownership across later handshake flights, including
cold HelloRetryRequest handshakes, without changing the initial cold packet
layout. See [the exact patch queue](https://github.com/cppla/quic-go/blob/main/FORK.md).
Preserve the existing full-handshake profile,
certificate verification, transport-parameter ownership and per-client cache
isolation. A resumed TLS connection still requires fresh AutoCAR authentication;
it must not enable 0-RTT or reuse a previous connection's authentication state.
Cold/warm functional and wire checks do not establish passive browser similarity.

The official QUIC source baseline for advisory review is
`github.com/quic-go/quic-go v0.63.0`. This is separate from the renamed web-H3
module's pseudo-version and from the independently updatable native transport
dependency. Update `WEB_QUIC_OFFICIAL_BASELINE` in `scripts/govulncheck.sh` and
its offline fixture when the web-H3 source lineage changes. Preserve and review
the intermediate adapter patches as well as the new maintained patch queue.

## Updating the patch queue

1. Preserve the upstream history, copyright headers and all license/notice
   files. Record the upstream commit, each compatibility patch's purpose and
   regression test, and the exact fork commit in the fork's maintenance notes.
   Keep fixes separate from mechanical upstream updates. Do not remove preset
   isolation or change a frozen ClientHello to restore pointer aliasing.
2. Publish the reviewed fork commit, then resolve it with
   `go list -m -json github.com/cppla/utls@<full-commit>` or
   `go list -m -json github.com/cppla/quic-go@<full-commit>` and retain the
   returned version and origin hash. Pin that exact published pseudo-version
   in `go.mod` and the corresponding `ALLOWED_UTLS_VERSION` or
   `ALLOWED_WEB_QUIC_FORK_VERSION` in `scripts/check-dependency-boundary.sh`;
   never use a branch, `latest`, local replacement, or invented pseudo-version.
   The original requires record the actual source baselines, not fork versions.
   Update their matching allowlists only when those baselines really change.
3. Check that H2 and web H3 resolve the same original uTLS module with one
   replacement. Check that web H3 resolves the maintained QUIC replacement
   while native transport still resolves official QUIC. Retain module sums and
   regenerate `THIRD_PARTY_NOTICES.md` with `make notices`; the generator records
   each replacement and reads its actual license files. Do not edit generated
   attribution to hide either fork.
4. Run `make check`, the targeted compatibility tests, race tests and the
   applicable CI/release gates with `GOTOOLCHAIN=local` and an explicitly
   installed supported Go version. A newer downloaded toolchain must not be
   reported as a successful test of an older selected compiler. Review the
   actual diff to each pinned handshake profile; functional success does not
   establish browser similarity or permit silently changing a frozen profile.

The boundary regression suite is offline and uses disposable fixtures. It
does not fetch the fork. Publication, checksums and same-commit CI remain
separate verification steps; a matching allowlist alone proves none of them.

## Upstream vulnerability review

Run these separate checks from the selected AutoCAR commit:

```sh
./scripts/govulncheck.sh
./scripts/govulncheck.sh --upstream-utls > /tmp/autocar-utls-upstream-advisories.json
./scripts/check-upstream-advisories.sh /tmp/autocar-utls-upstream-advisories.json
./scripts/govulncheck.sh --upstream-quic > /tmp/autocar-quic-official-upstream-advisories.json
./scripts/check-upstream-advisories.sh /tmp/autocar-quic-official-upstream-advisories.json
```

All scans/queries use the pinned `govulncheck` tool version in the wrapper.
The source scan inspects the actual package/call graph. The uTLS query uses
`-mode=query -json` against its **original module and baseline version** from
`go.mod`. The separate QUIC query uses the **official source-lineage baseline**
recorded above, not the renamed adapter/fork path and not whatever native QUIC
version happens to be selected. These are module-level advisory queries, not
reachability scans of either fork. Query output is a stream of JSON objects,
not one JSON document. CI preserves both outputs independently, even when
another scan fails, and fails when a query returns an OSV advisory pending
explicit human review. There is no automatic ignore list. A query failure is
not a clean result.

The initial baseline query on 2026-10-08 at approximately 10:57 UTC, using Go
1.27.1 and govulncheck v1.7.0, returned no matching OSV entries; the reported
database timestamp was 2026-10-07T14:10:51Z. This is a dated query result, not
a statement that the upstream code or maintained fork is vulnerability-free.

For each returned advisory, record its ID/URL, affected upstream files/symbols,
whether the vulnerable source exists in the exact fork commit, package usage
and reachable-call evidence where available, any upstream fix, the verified
backport commit, and the review date. Resolve the finding by taking a verified
fix/baseline update or by an explicit reviewed policy change with that evidence;
do not suppress an advisory just because the renamed fork has no database
entry. Keep the review with the dependency-update PR or release evidence.

`govulncheck` follows a replacement's module path, so retaining original import
paths does **not** automatically retain upstream advisory coverage. The query
helps recover known original-uTLS candidates; the official QUIC query separately
recovers candidates from the web adapter's source lineage. Neither proves the
maintained fork safe, and an empty advisory result is not a copied-source review.
Also review relevant Go `crypto/tls` security changes because uTLS carries its
own TLS implementation, and review official QUIC advisories against the exact
web-H3 fork lineage. For QUIC, compare each affected official file/symbol and fix
against the exact original adapter baseline and maintained patch queue; account
for added or divergent adapter code as well. Scanning the official native QUIC
module does not cover that renamed fork, and querying the renamed adapter path
is not a substitute for the official source-lineage query. Record those
source/patch reviews separately; do not call
them automated reachability results or reuse an older review for changed code.

This is an update/release procedure, not a background monitoring service.

## October 2026 security refresh

The October 9 pre-merge scan reported 11 reachable advisory IDs in the Go
1.27.1 / `x/net v0.59.0` build, following the October 8 advisory publication.
Current builds require [Go 1.27.2](https://go.dev/doc/devel/release#go1.27.0)
and select `x/net v0.60.0`, including the
[HTTP/2 HPACK race fix](https://pkg.go.dev/vuln/GO-2026-6617). CI, release builds
and all current Go builder images are updated together; historical validation
records and frozen capture inputs are not rewritten.

The uTLS fork separately backports Go commit
[`f022e61963529d5e691f0e42a87fd5b520f01636`](https://github.com/golang/go/commit/f022e61963529d5e691f0e42a87fd5b520f01636)
for [GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607). A newer compiler cannot
repair copied TLS source. This shared decoder serves ECH server processing and
local custom-client transcript reconstruction. AutoCAR's configured fork use is
client-side with GREASE ECH, limiting the affected server-input path, but the
public fork still receives the exact upstream fix and bounded regressions.

Go 1.27.2 also rejects CONNECT in `httputil.ReverseProxy`; tests retain this
security behavior and assert no upstream dial. See the
[cover compatibility boundary](WEB_COVER.md#fixed-upstream-origin). Functional
passes, a clean reachability scan, and the separate copied-source review remain
distinct evidence, not a claim that every dependency is vulnerability-free.
