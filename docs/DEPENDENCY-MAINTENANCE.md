# Maintaining the uTLS compatibility fork

AutoCAR maintains one small compatibility fork at `github.com/cppla/utls`.
Its module declaration and AutoCAR imports remain
`github.com/refraction-networking/utls`. A global **remote, exact-version**
`replace` in AutoCAR's `go.mod` selects the published fork for both H2 and the
web-H3 adapter's transitive imports. It is not a local source override. Do not
also require/import `github.com/cppla/utls`: that creates a second module/type
identity instead of repairing the existing dependency graph.

The upstream baseline is
`v1.8.3-0.20261006222701-ff1b50fbbe9a`
(`ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67`). It requires Go 1.27;
AutoCAR's minimum supported toolchain is Go 1.27.1. Native transport continues
to use official quic-go. Web H3 retains its existing, independently pinned
QUIC dependency; this change does not require another maintained QUIC fork.

The initial compatibility patch queue fixes custom-QUIC shutdown signaling and
transport-parameter ownership after preset cloning. Its deterministic shutdown
and real QUIC-TLS parameter tests live in the fork; see
[the fork maintenance notes](https://github.com/cppla/utls/blob/master/FORK.md).
AutoCAR separately checks the H3 Initial shape and reconnect contract. H2 now
uses upstream's PSK/HelloRetryRequest support on the same physical connection,
with fresh proxy authentication after reconnect, instead of the old
private-error-text-triggered cold redial. This does not change the explicitly
selected `chrome-133` or `chrome-2026-10` templates, enable H3 profile resumption,
or establish passive browser similarity.

## Updating the patch queue

1. Preserve the upstream history, copyright headers and all license/notice
   files. Record the upstream commit, each compatibility patch's purpose and
   regression test, and the exact fork commit in the fork's maintenance notes.
   Keep fixes separate from mechanical upstream updates. Do not remove preset
   isolation or change a frozen ClientHello to restore pointer aliasing.
2. Publish the reviewed fork commit, then resolve it with
   `go list -m -json github.com/cppla/utls@<full-commit>` and retain the returned
   version and origin hash. Pin that exact published pseudo-version in both
   `go.mod` and `ALLOWED_UTLS_VERSION` in
   `scripts/check-dependency-boundary.sh`; never use a branch, `latest`, local
   replacement, or invented pseudo-version. The original require records the
   actual upstream baseline, not the fork's version. Update its matching
   allowlist only when that baseline really changes.
3. Check that H2 and web H3 resolve the same original uTLS module with one
   replacement. Retain module sums and regenerate `THIRD_PARTY_NOTICES.md` with
   `make notices`; the generator records the replacement and reads its actual
   license files. Do not edit generated attribution to hide the fork.
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
```

Both use the pinned `govulncheck` tool version in the wrapper. The first scans
the actual package/call graph. The second uses `-mode=query -json` against the
**original upstream module and baseline version** from `go.mod`; it is a
module-level advisory query, not a reachability scan of the fork. Its output
is a stream of JSON objects, not one JSON document. CI retains this output and
fails when the query returns an OSV advisory, pending explicit human review.
There is no automatic ignore list. A query failure is not a clean result.

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
helps recover known original-uTLS candidates; it cannot prove the fork safe.
Also review relevant Go `crypto/tls` security changes because uTLS carries its
own TLS implementation, and review official QUIC advisories against the exact
web-H3 fork lineage. Scanning the official native QUIC module does not cover
that renamed fork. Record those source/patch reviews separately; do not call
them automated reachability results or reuse an older review for changed code.

This is an update/release procedure, not a background monitoring service.
