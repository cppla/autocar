#!/usr/bin/env bash
set -Eeuo pipefail

readonly ALLOWED_WEB_QUIC_MODULE='github.com/apernet/quic-go'
readonly ALLOWED_WEB_QUIC_VERSION='v0.61.1-0.20260806010916-184d081eef3e'
readonly FORBIDDEN_HYSTERIA_PATTERN='github\.com/apernet/hysteria(/|[[:space:]"`]|$)'
readonly FORBIDDEN_HYSTERIA_GO_PATTERN='["`]github\.com/apernet/hysteria(/[^"`[:space:]]*)?["`]'
status=0

module_counts=$(
  awk -v module="${ALLOWED_WEB_QUIC_MODULE}" -v version="${ALLOWED_WEB_QUIC_VERSION}" '
    {
      line = $0
      sub(/[[:space:]]*\/\/.*/, "", line)
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      fields = split(line, part, /[[:space:]]+/)
      for (field = 1; field <= fields; field++) {
        if (part[field] == module || index(part[field], module "/") == 1) {
          count++
        }
      }
      if (part[1] == "require" && part[2] == module) {
        if (fields == 3 && part[3] == version) {
          exact++
        }
      } else if (part[1] == module) {
        if (fields == 2 && part[2] == version) {
          exact++
        }
      }
    }
    END { print count + 0, exact + 0 }
  ' go.mod
)
read -r web_quic_count exact_web_quic_count <<<"${module_counts}"
if (( web_quic_count != 1 || exact_web_quic_count != 1 )); then
  echo "error: go.mod must require exactly ${ALLOWED_WEB_QUIC_MODULE} ${ALLOWED_WEB_QUIC_VERSION}:" >&2
  awk -v module="${ALLOWED_WEB_QUIC_MODULE}" 'index($0, module) { print NR ":" $0 }' go.mod >&2
  status=1
fi

if matches=$(grep -nE "${FORBIDDEN_HYSTERIA_PATTERN}" go.mod); then
  echo "error: go.mod references the prohibited Hysteria application module:" >&2
  printf '%s\n' "${matches}" >&2
  status=1
else
  grep_status=$?
  if (( grep_status != 1 )); then
    echo "error: could not inspect go.mod" >&2
    status=1
  fi
fi

web_quic_replacements=$(
  awk -v module="${ALLOWED_WEB_QUIC_MODULE}" '
    index($0, module) && index($0, "=>") { print NR ":" $0 }
  ' go.mod
)
if [[ -n ${web_quic_replacements} ]]; then
  echo "error: the pinned web QUIC module must not be replaced:" >&2
  printf '%s\n' "${web_quic_replacements}" >&2
  status=1
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

while IFS= read -r -d '' source_file; do
  if imports=$(grep -nE "${FORBIDDEN_HYSTERIA_GO_PATTERN}" "${source_file}"); then
    echo "error: Go source references the prohibited Hysteria application module:" >&2
    while IFS= read -r match; do
      printf '%s:%s\n' "${source_file#./}" "${match}" >&2
    done <<<"${imports}"
    status=1
  else
    grep_status=$?
    if (( grep_status != 1 )); then
      echo "error: could not inspect Go source ${source_file#./}" >&2
      status=1
    fi
  fi
done < <(find . -type f -name '*.go' ! -path './.git/*' -print0)

external_sources=""
for source_dir in \
  third_party/hysteria \
  third_party/hysteria-core \
  third_party/quic-go \
  vendor/github.com/apernet/hysteria \
  vendor/github.com/apernet/quic-go; do
  if [[ -e ${source_dir} || -L ${source_dir} ]]; then
    external_sources+="${source_dir}"$'\n'
  fi
done
if [[ -n ${external_sources} ]]; then
  echo "error: prohibited vendored or copied external source directories are present:" >&2
  printf '%s' "${external_sources}" >&2
  status=1
fi

if (( status != 0 )); then
  exit "${status}"
fi

echo "dependency boundary check passed"
