#!/usr/bin/env bash
set -Eeuo pipefail

# GO-2026-5288 is an automatically generated Go DB entry that currently says
# all Hysteria v2 versions are affected. The reviewed upstream GHSA limits the
# vulnerable range to <= 2.8.1, while AutoCAR pins 2.12.1. The vulnerable
# feature is application-layer protocol sniffing, which this adapter neither
# imports nor enables. Keep the exception fail-closed: changing the version,
# introducing sniff hooks, finding another reachable advisory, receiving an
# incomplete JSON stream, or a scanner execution error all fail this script.
#
# https://github.com/advisories/GHSA-9fw6-xgg2-mq9q
# https://pkg.go.dev/vuln/GO-2026-5288

EXPECTED_HYSTERIA_VERSION=v2.12.1
ACTUAL_HYSTERIA_VERSION=$(go list -m -f '{{.Version}}' github.com/apernet/hysteria/core/v2)
if [[ ${ACTUAL_HYSTERIA_VERSION} != "${EXPECTED_HYSTERIA_VERSION}" ]]; then
  echo "error: review the GO-2026-5288 exception before changing Hysteria (${ACTUAL_HYSTERIA_VERSION})" >&2
  exit 1
fi

if find cmd internal -type f -name '*.go' \
  -exec grep -EHin 'RequestHook[[:space:]]*:|/sniff(["`])' {} +; then
  echo "error: protocol sniffing is incompatible with the narrow GO-2026-5288 exception" >&2
  exit 1
fi

TOOL_DIR=${RUNNER_TEMP:-/tmp}/autocar-govulncheck-v1.7.0
mkdir -p "${TOOL_DIR}"
GOBIN="${TOOL_DIR}" go install golang.org/x/vuln/cmd/govulncheck@v1.7.0

set +e
"${TOOL_DIR}/govulncheck" -format=json ./... | go run ./tools/vulnfilter
PIPELINE_STATUS=("${PIPESTATUS[@]}")
set -e

SCANNER_STATUS=${PIPELINE_STATUS[0]}
FILTER_STATUS=${PIPELINE_STATUS[1]}
if (( FILTER_STATUS != 0 )); then
  exit "${FILTER_STATUS}"
fi
if (( SCANNER_STATUS != 0 && SCANNER_STATUS != 3 )); then
  echo "error: govulncheck failed with status ${SCANNER_STATUS}" >&2
  exit "${SCANNER_STATUS}"
fi
