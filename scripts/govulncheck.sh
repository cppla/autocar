#!/usr/bin/env bash
set -Eeuo pipefail

readonly GOVULNCHECK_VERSION=v1.7.0
TOOL_DIR=${RUNNER_TEMP:-/tmp}/autocar-govulncheck-${GOVULNCHECK_VERSION}
mkdir -p "${TOOL_DIR}"
GOBIN="${TOOL_DIR}" go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
"${TOOL_DIR}/govulncheck" ./...
