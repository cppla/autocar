#!/usr/bin/env bash
set -Eeuo pipefail

mode=${1:-source}
if (( $# > 1 )) || [[ ${mode} != source && ${mode} != --upstream-utls && ${mode} != --upstream-quic ]]; then
  echo "usage: $0 [--upstream-utls|--upstream-quic]" >&2
  exit 2
fi

readonly GOVULNCHECK_VERSION=v1.7.0
# Official source lineage of the web QUIC baseline a10df75c260c. This is
# deliberately separate from both its renamed module identity and the native
# transport's independently updatable official dependency in go.mod. Review
# and update this version whenever the web QUIC source baseline changes.
readonly WEB_QUIC_OFFICIAL_BASELINE=v0.63.0
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
if [[ ${mode} == --upstream-quic ]]; then
  "${TOOL_DIR}/govulncheck" -mode=query -json "github.com/quic-go/quic-go@${WEB_QUIC_OFFICIAL_BASELINE}"
  exit
fi
"${TOOL_DIR}/govulncheck" ./...
