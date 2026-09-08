# Release policy and checklist

An ordinary AutoCAR release delivers functionality and bug fixes. It does not
certify browser equivalence, passive indistinguishability, or a comparative
privacy advantage. v1.0.1 keeps native mode as the default and labels web-cover
as an experimental, explicitly enabled feature.

## Ordinary release quality

From the exact, clean release commit, use an explicit version and UTC build time:

```sh
make release VERSION=v1.0.1 BUILD_DATE=2026-09-08T00:00:00Z
```

Use a recorded UTC build time rather than copying the example timestamp. The
tag workflow uses the source commit's UTC timestamp for consistent metadata.
The release recipe freezes `HEAD` and its tree before running quality checks,
binds the embedded commit to that `HEAD`, and rejects a dirty checkout or source
drift during checking and packaging. Supplying `COMMIT` cannot relabel the
source being released.

`release-quality-check` runs the ordinary checks, race tests, offline research
tool self-tests, and reachable-vulnerability scan. The tool self-tests check
the research implementation; they do not collect a corpus or produce an
empirical comparison result. The cross-platform build retains dependency
license notices and `release-artifact-check` validates archive members, matching
license text, target platform, main module and clean embedded VCS commit. Version
and build-time inputs are syntax-checked, but `go version -m` does not expose
the injected runtime version/date for these `-trimpath` binaries.

The published packages are:

| Platform | Archive |
| --- | --- |
| Linux x86-64 | `autocar-linux-amd64.tar.gz` |
| Linux ARM64 | `autocar-linux-arm64.tar.gz` |
| macOS Apple Silicon | `autocar-darwin-arm64.tar.gz` |
| Windows x86-64 | `autocar-windows-amd64.zip` |

Each archive contains its executable, `LICENSE`, and `THIRD_PARTY_NOTICES.md`.
The GitHub release also supplies `SHA256SUMS`; verify the downloaded archive's
digest before installation. Cross-compilation establishes build coverage, not
runtime coverage of every operating system and architecture.

Before publishing, the tag's exact commit must have successful main-branch CI,
CodeQL and Linux netem checks. The publication workflow extracts the exact
Linux amd64 release archive, executes its binary to verify the runtime version,
commit and build time, and runs Linux native upgrade/rollback and web smoke
acceptance checks against that candidate. The other platform archives receive
cross-build and build-metadata checks, not native runtime checks in that workflow.
Retain the build/check logs and hashes. Record a failure as a failure even if a
later isolated rerun passes; investigate timing-sensitive fixtures and avoid
relaxing assertions merely to obtain a green run. Never reuse an older
commit's successful checks as evidence for a changed release source.

Release notes live in `docs/releases/<version>.md` and must state capabilities,
compatibility, operational limits and the scope of actual validation. A tag
and uploaded binaries must identify the same frozen source. Do not mark a
release published until the workflow, uploaded assets and checksums have been
verified.

## Optional comparison research

Only a release carrying a bounded research claim additionally requires
`make release-with-evidence`, with explicit version, build time and all evidence
variables. See the complete command and contract in
[STEALTH-BENCHMARK.md](STEALTH-BENCHMARK.md).
`release-with-evidence` first runs the existing `release-evidence-check` and
then the ordinary release recipe. The standalone evidence target remains
available for offline checks.

The strict gate still requires the frozen registration, exact source and
binary/configuration hashes, distinct local Docker and remote Linux active
results, complete PCAPs and browser controls, and the preregistered statistical
decision. Missing observations remain `insufficient_evidence`; malformed or
mismatched evidence fails. Ordinary release success neither bypasses these
requirements for a claim nor rewrites previous experiments. The incomplete
31,500-PCAP research campaign is not required for the non-comparative v1.0.1
release.
