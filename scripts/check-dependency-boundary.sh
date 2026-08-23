#!/usr/bin/env bash
set -Eeuo pipefail

readonly FORBIDDEN_MODULE_PATTERN='github\.com/apernet/(hysteria|quic-go)(/|[[:space:]"`]|$)'
status=0

if matches=$(grep -nE "${FORBIDDEN_MODULE_PATTERN}" go.mod); then
  echo "error: go.mod references a prohibited downstream module:" >&2
  printf '%s\n' "${matches}" >&2
  status=1
else
  grep_status=$?
  if (( grep_status != 1 )); then
    echo "error: could not inspect go.mod" >&2
    status=1
  fi
fi

local_replacements=$(
  awk '
    {
      line = $0
      sub(/[[:space:]]*\/\/.*/, "", line)
      $0 = line
      for (field = 1; field < NF; field++) {
        if ($field == "=>") {
          target = $(field + 1)
          sub(/^["`]/, "", target)
          if (target ~ /^(\.\/|\.\.\/|\/|[[:alpha:]]:[\\\/])/) {
            print NR ":" target
          }
        }
      }
    }
  ' go.mod
)
if [[ -n ${local_replacements} ]]; then
  echo "error: go.mod contains local replace directives:" >&2
  printf '%s\n' "${local_replacements}" >&2
  status=1
fi

if imports=$(git grep -nE '["`]github\.com/apernet/(hysteria|quic-go)(/[^"`[:space:]]*)?["`]' -- '*.go' ':(exclude)third_party/**'); then
  echo "error: build Go source imports a prohibited downstream module:" >&2
  printf '%s\n' "${imports}" >&2
  status=1
else
  git_grep_status=$?
  if (( git_grep_status != 1 )); then
    echo "error: could not inspect tracked Go source" >&2
    status=1
  fi
fi

tracked_external_sources=$(
  git ls-files | awk -F/ '
    /^third_party\/(hysteria-core|quic-go)(\/|$)/ {
      paths[$1 "/" $2] = 1
    }
    END {
      for (path in paths) {
        print path
      }
    }
  ' | sort
)
if [[ -n ${tracked_external_sources} ]]; then
  echo "error: prohibited external source directories are tracked:" >&2
  printf '%s\n' "${tracked_external_sources}" >&2
  status=1
fi

if (( status != 0 )); then
  exit "${status}"
fi

echo "dependency boundary check passed"
