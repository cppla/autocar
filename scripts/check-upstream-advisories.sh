#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <govulncheck-query-json>" >&2
  exit 2
fi

# govulncheck's pinned JSON handler writes each top-level OSV field on its own
# line. Query mode returns success even when it emits advisory candidates.
if grep -qE '^[[:space:]]*"osv"[[:space:]]*:' -- "$1"; then
  echo 'Original uTLS baseline has advisory candidates. Review applicability and patches; this is not a fork reachability result.' >&2
  exit 1
else
  grep_status=$?
  if (( grep_status != 1 )); then
    echo "error: could not inspect the original uTLS advisory query" >&2
    exit "${grep_status}"
  fi
fi
