# Real-browser workload runner

This directory contains an independent, defensive experiment runner for one
real Chromium or Firefox ESR browser session. It talks to the browser through
the W3C WebDriver HTTP API using only Python's standard library. Runtime
subprocesses are fixed argv arrays; no command is evaluated by a shell.

The runner is intentionally limited to a numeric RFC1918 server. A successful
run additionally requires every workload request's
`PerformanceResourceTiming.nextHopProtocol` to exactly equal the requested
`h3` or `h2` value. A TCP or UDP program that merely exits successfully cannot
produce a passing browser receipt.

## Fixture contract

The server must expose these HTTPS endpoints on the same origin as `/`:

- `GET /bytes/{size}?seed=N&request=i` returns the fixed unseeded fixture body.
- `POST /upload/{size}?seed=N&request=i` accepts the domain-1 deterministic
  payload and returns the 32-byte domain-2 receipt.
- `POST /exchange/256/512?seed=N&request=i` accepts the domain-3 payload and
  returns the domain-4 payload.

Requests and responses use `application/octet-stream`. `upload_1m` is one 1 MiB
upload, and `interactive` is exactly eight ordered 256-byte-up/512-byte-down
exchanges. `browser_h2` is an auxiliary alias for one `download_128k` request;
the receipt preserves the `browser_h2` label expected by the campaign driver.

## Reproducible images

Build one immutable image per browser. The reviewed Debian 13 amd64 inputs are
checked in as `versions.debian13-amd64.json`. Every build requires:

- `BASE_IMAGE`: a Debian 13 base reference ending in `@sha256:<64 hex>`;
- `BROWSER_FAMILY`: `chromium` or `firefox-esr`;
- `BROWSER_PACKAGE_VERSION`: an exact Debian package version; and
- `WEBDRIVER_PACKAGE_VERSION`: the exact matching Debian chromium-driver
  package version, or the exact Mozilla geckodriver release version.

Firefox builds also require `WEBDRIVER_ARCHIVE_SHA256`, which is checked before
the Mozilla release archive is extracted. The Dockerfile supports `amd64` and
`arm64` Firefox release assets.

Example shapes, with reviewed exact values substituted:

```sh
docker build -f scripts/stealth-browser/Dockerfile \
  --build-arg 'BASE_IMAGE=debian:13-slim@sha256:<reviewed-base-digest>' \
  --build-arg BROWSER_FAMILY=chromium \
  --build-arg 'BROWSER_PACKAGE_VERSION=<exact-debian-version>' \
  --build-arg 'WEBDRIVER_PACKAGE_VERSION=<same-exact-debian-version>' \
  -t autocar-stealth-browser:chromium .

docker build -f scripts/stealth-browser/Dockerfile \
  --build-arg 'BASE_IMAGE=debian:13-slim@sha256:<reviewed-base-digest>' \
  --build-arg BROWSER_FAMILY=firefox-esr \
  --build-arg 'BROWSER_PACKAGE_VERSION=<exact-debian-version>' \
  --build-arg 'WEBDRIVER_PACKAGE_VERSION=<exact-geckodriver-version>' \
  --build-arg 'WEBDRIVER_ARCHIVE_SHA256=<reviewed-release-archive-sha256>' \
  -t autocar-stealth-browser:firefox-esr .
```

The build runs each executable's `--version`, hashes the browser and WebDriver
binaries, and writes `/campaign/browser-lock.json`. Runtime execution recomputes
those values and fails if the image contents differ from the lock.

The machine-readable identity for campaign configuration is:

```sh
docker run --rm --network none autocar-stealth-browser:chromium identity
```

It prints one compact JSON object containing only `client_implementation`,
`implementation_version`, and `browser_binary_sha256`.

## Runtime

One sample invocation is:

```sh
docker run --rm --network '<owned-internal-network>' \
  autocar-stealth-browser:chromium \
  --browser chromium \
  --protocol h3 \
  --server 10.203.0.10:8443 \
  --workload download_128k \
  --seed 12345 \
  --accept-insecure-certs
```

`--accept-insecure-certs` is an explicit option for an isolated, owned RFC1918
lab certificate. Omit it when the runner image already trusts the lab CA.

On success, stdout contains exactly one compact JSON object with the frozen
receipt fields. Browser and WebDriver diagnostics never share stdout. Any
navigation, payload, result-length, Resource Timing, identity, or requested
protocol mismatch exits nonzero without printing a success receipt.

Offline checks do not start Docker, a browser, or a network listener:

```sh
python3 scripts/stealth-browser/run_cover.py --self-test
python3 -m unittest -v scripts/stealth-browser/test_run_cover.py
```
