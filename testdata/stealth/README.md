# Stealth benchmark fixtures

`preregistration.json` is the public template for the release-gate contract. Its
remote endpoint and SSH fingerprint are synthetic examples, not live host
identifiers. Replace both in a private experiment checkout before capture,
commit that change, and record the exact private commit in the
campaign manifest. Changing cells, models, sample sizes, seeds, or margins after
seeing scores invalidates the campaign. Keep historical evidence and its frozen
registration unchanged; this sanitized template does not identify a past run.

`manifest.example.csv` documents the capture manifest schema. Each PCAP must be
one isolated connection or browser session between the declared client and
server IPs. Per-sample implementation, image, container, capture-host, and
Docker-engine fields bind cover-diversity claims to individual captures. The
extractor uses endpoint addresses only to determine direction and does not emit
addresses, paths, or provenance fields into the feature table.

campaign-driver.example.json documents the capture-driver contract. It is a
template, not a runnable or release-approved configuration: every placeholder
must be replaced, the referenced internal Docker lab must be created and
labelled explicitly, and each runner image must be independently reviewed.

PCAPs are deliberately not checked into Git. A complete release campaign is
large and belongs in a content-addressed artifact store; its SHA-256 manifest
and final score report should be retained with the release evidence.

Every row must reference a distinct canonical file with distinct SHA-256
content. Copying one capture to multiple filenames or sample IDs is rejected.
Retain a campaign metadata JSON that binds the capture interval, exact AutoCAR
commit, preregistration digest, capture-manifest digest, product provenance, and
the independent ordinary-cover implementations represented by the corpus.
`campaign.example.json` documents that fail-closed metadata contract; replace
every placeholder and hash the actual binaries and effective configurations.
