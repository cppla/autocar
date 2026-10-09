# Chrome 155 cold ClientHello reference

`clienthello.hex` is copied byte-for-byte from
[`cppla/utls` commit `7295e1b508c33c2993ab878fad7432c9e7fdca9e`](https://github.com/cppla/utls/blob/7295e1b508c33c2993ab878fad7432c9e7fdca9e/testdata/chrome155_clienthello.hex).
The [upstream capture notes](https://github.com/cppla/utls/blob/7295e1b508c33c2993ab878fad7432c9e7fdca9e/testdata/chrome155_clienthello.md)
record official Google Chrome **155.0.8059.40**, macOS ARM64, October 6, 2026,
a fresh dedicated browser profile, QUIC disabled, and an HTTPS navigation to
`www.example.com`. This is a previously captured browser record, not a fresh
browser run by AutoCAR's test and not bytes emitted by the TLS library.

The decoded TLS record is 1,955 bytes. The 1,950-byte ClientHello handshake,
excluding the five-byte record header, has SHA-256:

```text
235618e3922e52a71a9f6593a71ec4ca182dab6b3ab4e90a2a1733133e97439a
```

No keylog, credentials, certificates, or application payload are retained here.
The parser in `../../web_chrome155_fixture_test.go` is adapted from the same
upstream commit's `u_chrome155_test.go`; its copyright header and BSD license
are retained. The parser is independent of the library's ClientHello generator
and Fingerprinter, but is not a separately developed third-party validator.

The AutoCAR test records the actual H2 TLS wrapper writing to an in-process
peer, using the fixture's SNI. It checks eight cold handshakes for each policy:
empty enabled cache, nil cache, and disabled tickets. It compares ordered
ciphers, signatures, groups, versions, ALPN, key-share group/length, and the
exact ordered trust-anchor IDs, plus every other extension body. It normalizes
random/session-ID bytes, ordinary extension permutation, GREASE codepoints, ephemeral
key material, and GREASE ECH randomness. The ECH payload must remain in the
144/176/208/240-byte family. Cold PSK and early-data extensions are forbidden.
GREASE extensions retain their captured positions and corresponding bodies;
the comparison does not normalize them into the freely shuffled middle group.
The advertised trust-anchor IDs do not change AutoCAR's actual CA validation.

Run from the repository root:

```sh
go test ./internal/tunnel -run '^TestChrome155(ActualClientHelloMatchesBrowserFixture|ComparisonPreservesCapabilityDifferences)$' -count=1
```

Passing is evidence of this **normalized cold ClientHello shape only**. It is
not a fresh browser experiment, a warm-browser resumption comparison, an H3
profile update, a complete H2 fingerprint match, or a passive-classifier result.
TCP behavior, H2 SETTINGS/headers/flow control, server behavior, connection reuse,
packetization, workload sizes and timing remain outside this comparison.
