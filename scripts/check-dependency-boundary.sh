#!/usr/bin/env bash
set -Eeuo pipefail

readonly ALLOWED_WEB_QUIC_MODULE='github.com/apernet/quic-go'
readonly ALLOWED_WEB_QUIC_VERSION='v0.63.1-0.20261004180939-a10df75c260c'
readonly ALLOWED_WEB_QUIC_REPLACEMENT='github.com/cppla/quic-go'
readonly ALLOWED_WEB_QUIC_FORK_VERSION='v0.63.1-0.20261009040133-c1cae948af15'
readonly ALLOWED_UTLS_MODULE='github.com/refraction-networking/utls'
readonly ALLOWED_UTLS_UPSTREAM_VERSION='v1.8.3-0.20261006222701-ff1b50fbbe9a'
readonly ALLOWED_UTLS_REPLACEMENT='github.com/cppla/utls'
readonly ALLOWED_UTLS_VERSION='v0.0.0-20261009031926-14c2a4cb1403'
readonly FORBIDDEN_HYSTERIA_PATTERN='github\.com/apernet/hysteria(/|[[:space:]"`]|$)'
readonly FORBIDDEN_HYSTERIA_GO_PATTERN='["`]github\.com/apernet/hysteria(/[^"`[:space:]]*)?["`]'
status=0

# This targeted gate accepts the canonical token spelling emitted by Go.
# Counting raw tokens is unsafe if quoted paths can hide escaped characters:
# a version-scoped replacement could then override the allowed global pin.
noncanonical_module_tokens=$(
  awk '
    {
      line = $0
      sub(/[[:space:]]*\/\/.*/, "", line)
      if (line ~ /["\\]/ || index(line, sprintf("%c", 96))) {
        print NR ":" line
      }
    }
  ' go.mod
)
if [[ -n ${noncanonical_module_tokens} ]]; then
  echo "error: go.mod must use unquoted, unescaped canonical tokens:" >&2
  printf '%s\n' "${noncanonical_module_tokens}" >&2
  status=1
fi

# Keep the upstream module identity for both direct and transitive imports. Only
# one global, remote, immutable replacement per fork is allowed; a version-scoped
# replace could leave another selected upstream version unpatched.
check_managed_fork() {
  local label=$1 module=$2 upstream=$3 replacement=$4 version=$5
  local counts source_count target_count require_count replace_count
  if [[ ${version} == TODO_* ]]; then
    echo "error: the managed ${label} fork's published version has not been pinned" >&2
    status=1
  elif [[ ! ${version} =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(0\.)?[0-9]{14}-[0-9a-f]{12}$ ]]; then
    echo "error: the managed ${label} fork must use an exact published pseudo-version" >&2
    status=1
  fi
  counts=$(
    awk -v module="${module}" -v upstream="${upstream}" \
        -v replacement="${replacement}" -v version="${version}" '
    {
      line = $0
      sub(/[[:space:]]*\/\/.*/, "", line)
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      fields = split(line, part, /[[:space:]]+/)
      for (field = 1; field <= fields; field++) {
        gsub(/^["`]|["`]$/, "", part[field])
        if (part[field] == module || index(part[field], module "/") == 1) source_count++
        if (part[field] == replacement || index(part[field], replacement "/") == 1) target_count++
      }
      first = (part[1] == "require" || part[1] == "replace") ? 2 : 1
      if (part[first] == module && fields == first + 1 && part[first + 1] == upstream) exact_require++
      if (part[first] == module && fields == first + 3 && part[first + 1] == "=>" &&
          part[first + 2] == replacement && part[first + 3] == version) exact_replace++
    }
    END { print source_count + 0, target_count + 0, exact_require + 0, exact_replace + 0 }
    ' go.mod
  )
  read -r source_count target_count require_count replace_count <<<"${counts}"
  if (( source_count != 2 || target_count != 1 || require_count != 1 || replace_count != 1 )); then
    echo "error: require exactly ${module} ${upstream} and globally replace it with ${replacement} ${version}" >&2
    status=1
  fi
}
check_managed_fork uTLS "${ALLOWED_UTLS_MODULE}" "${ALLOWED_UTLS_UPSTREAM_VERSION}" \
  "${ALLOWED_UTLS_REPLACEMENT}" "${ALLOWED_UTLS_VERSION}"
check_managed_fork 'web QUIC' "${ALLOWED_WEB_QUIC_MODULE}" "${ALLOWED_WEB_QUIC_VERSION}" \
  "${ALLOWED_WEB_QUIC_REPLACEMENT}" "${ALLOWED_WEB_QUIC_FORK_VERSION}"

# The managed web adapter must not redirect the independent native transport.
native_quic_replacements=$(
  awk '
    {
      line = $0
      sub(/[[:space:]]*\/\/.*/, "", line)
      sub(/^[[:space:]]+/, "", line)
      fields = split(line, part, /[[:space:]]+/)
      first = part[1] == "replace" ? 2 : 1
      if ((part[first] == "github.com/quic-go/quic-go" ||
           index(part[first], "github.com/quic-go/quic-go/") == 1) && index(line, "=>")) {
        print NR ":" line
      }
    }
  ' go.mod
)
if [[ -n ${native_quic_replacements} ]]; then
  echo "error: native transport must keep the official QUIC module without replacement:" >&2
  printf '%s\n' "${native_quic_replacements}" >&2
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
  if grep -qE '["`]github\.com/cppla/(utls|quic-go)(/[^"`[:space:]]*)?["`]' "${source_file}"; then
    echo "error: ${source_file#./} imports the replacement path directly; retain the original module import path" >&2
    status=1
  fi
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

# Go permits escaped interpreted-string import paths. Require their canonical
# spelling too, so literal path checks cannot miss a second module identity.
# Tokenize only enough to distinguish import declarations from comments,
# ordinary strings and rune literals. This stays offline and does not run Go.
escaped_imports=$(
  python3 - <<'PY'
from pathlib import Path
import re

tokens = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\[\s\S]|[^"\\])*"|'
    r'\x60[^\x60]*\x60|'
    r"'(?:\\[\s\S]|[^'\\])*'|"
    r'[^\W\d]\w*|[^\s]'
)
for path in Path(".").rglob("*.go"):
    if ".git" in path.parts or not path.is_file():
        continue
    source = path.read_text(encoding="utf-8")
    importing = grouped = False
    for match in tokens.finditer(source):
        token = match.group()
        if token.startswith(("//", "/*")):
            continue
        if token == "import":
            importing = True
            grouped = False
        elif importing:
            if token == "(":
                grouped = True
            elif token.startswith(('"', chr(96))):
                if token.startswith('"') and "\\" in token:
                    line = source.count("\n", 0, match.start()) + 1
                    print(f"{path}:{line}: escaped import path")
                importing = grouped
            elif token == ")" or (token == ";" and not grouped):
                importing = False
PY
)
if [[ -n ${escaped_imports} ]]; then
  echo "error: Go import paths must use unescaped canonical spelling:" >&2
  printf '%s\n' "${escaped_imports}" >&2
  status=1
fi

external_sources=""
for source_dir in \
  third_party/hysteria \
  third_party/hysteria-core \
  third_party/quic-go \
  third_party/utls \
  vendor/github.com/apernet/hysteria \
  vendor/github.com/apernet/quic-go \
  vendor/github.com/refraction-networking/utls \
  vendor/github.com/cppla/utls \
  vendor/github.com/cppla/quic-go; do
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
