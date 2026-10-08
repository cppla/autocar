#!/usr/bin/env bash
set -Eeuo pipefail

mode=${1:-source}
if (( $# > 1 )) || [[ ${mode} != source && ${mode} != --upstream-utls ]]; then
  echo "usage: $0 [--upstream-utls]" >&2
  exit 2
fi

readonly GOVULNCHECK_VERSION=v1.7.0
TOOL_DIR=${RUNNER_TEMP:-/tmp}/autocar-govulncheck-${GOVULNCHECK_VERSION}
mkdir -p "${TOOL_DIR}"
GOBIN="${TOOL_DIR}" go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
if [[ ${mode} == --upstream-utls ]]; then
  # Query the original upstream baseline, not the fork pseudo-version. The
  # dependency boundary separately freezes this require and its replacement.
  upstream_version=$(go list -m -f '{{.Version}}' github.com/refraction-networking/utls)
  if [[ -z ${upstream_version} ]]; then
    echo "error: no original uTLS baseline version found" >&2
    exit 1
  fi
  "${TOOL_DIR}/govulncheck" -mode=query -json "github.com/refraction-networking/utls@${upstream_version}"
  exit
fi
"${TOOL_DIR}/govulncheck" ./...
