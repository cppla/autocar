#!/usr/bin/env sh
set -eu

expected_hysteria='v2.12.1'
expected_quic='v0.61.1-0.20260806010916-184d081eef3e'

module_version() {
    awk -v module="$2" '
        $1 == module { print $2; found = 1 }
        END { if (!found) exit 1 }
    ' "$1"
}

replace_target() {
    awk -v module="$2" '
        $1 == "replace" && $2 == module && $3 == "=>" { print $4; found = 1 }
        END { if (!found) exit 1 }
    ' "$1"
}

root_hysteria="$(module_version go.mod github.com/apernet/hysteria/core/v2)"
root_quic="$(module_version go.mod github.com/apernet/quic-go)"
core_quic="$(module_version third_party/hysteria-core/go.mod github.com/apernet/quic-go)"
root_hysteria_replace="$(replace_target go.mod github.com/apernet/hysteria/core/v2)"
root_quic_replace="$(replace_target go.mod github.com/apernet/quic-go)"
core_quic_replace="$(replace_target third_party/hysteria-core/go.mod github.com/apernet/quic-go)"

if [ "$root_hysteria" != "$expected_hysteria" ]; then
    echo "local Hysteria fork provenance mismatch: go.mod requires $root_hysteria, source is $expected_hysteria" >&2
    echo "rebase and re-audit third_party/hysteria-core before changing the requirement" >&2
    exit 1
fi
if [ "$root_quic" != "$expected_quic" ] || [ "$core_quic" != "$expected_quic" ]; then
    echo "local QUIC fork provenance mismatch: root=$root_quic core=$core_quic source=$expected_quic" >&2
    echo "rebase and re-audit third_party/quic-go before changing either requirement" >&2
    exit 1
fi
if [ "$root_hysteria_replace" != './third_party/hysteria-core' ] || \
   [ "$root_quic_replace" != './third_party/quic-go' ] || \
   [ "$core_quic_replace" != '../quic-go' ]; then
    echo "local fork replacements are missing or redirected" >&2
    echo "root Hysteria=$root_hysteria_replace root QUIC=$root_quic_replace core QUIC=$core_quic_replace" >&2
    exit 1
fi

grep -Fq "core/v2\` $expected_hysteria" third_party/hysteria-core/AUTOCAR_PATCHES.md
grep -Fq "\`$expected_quic\`" third_party/quic-go/AUTOCAR_PATCHES.md
