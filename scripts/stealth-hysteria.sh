#!/bin/sh
set -eu
umask 077

# Reproducible Hysteria 2 baseline preparation. This script refuses unpinned
# versions and always emits a reverse-proxy masquerade; comparing against the
# built-in default 404 is explicitly unsupported.

version=v2.12.2
commit=619a6f8
amd64_sha=6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94
arm64_sha=ebfacc1ec3a0edfd742cd68ce17f292a6092e606b9d11f99b035c1d888f3d709
release_base=https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.2
newline='
'
carriage_return=$(printf '\r')

usage() {
	cat >&2 <<'EOF'
usage:
  scripts/stealth-hysteria.sh fetch OUTPUT_DIR [amd64|arm64]
  scripts/stealth-hysteria.sh server-config OUTPUT CERT KEY PASSWORD ORIGIN [standard|gecko] [OBFS_PASSWORD]
  scripts/stealth-hysteria.sh client-config OUTPUT SERVER SNI CA PASSWORD HTTP_LISTEN [standard|gecko] [OBFS_PASSWORD]

The standard profile keeps Chrome QUIC parroting enabled and configures both an
HTTP/3 reverse-proxy masquerade and TCP listenHTTPS on the same numeric port.
Gecko is a separate non-HTTP/3 obfuscation profile and must not be presented as
a valid H3 cover endpoint.
EOF
}

require_scalar() {
	name=$1
	value=$2
	case "$value" in
		""|*"$newline"*|*"$carriage_return"*) echo "$name must be a non-empty single-line value" >&2; exit 2 ;;
	esac
}

yaml_quote() {
	# YAML single quoted scalars escape one quote as two quotes.
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "sha256sum or shasum is required" >&2
		return 1
	fi
}

fetch() {
	[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage; exit 2; }
	out=$1
	arch=${2:-}
	if [ -z "$arch" ]; then
		case "$(uname -m)" in
			x86_64|amd64) arch=amd64 ;;
			aarch64|arm64) arch=arm64 ;;
			*) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
		esac
	fi
	case "$arch" in
		amd64) expected=$amd64_sha ;;
		arm64) expected=$arm64_sha ;;
		*) echo "architecture must be amd64 or arm64" >&2; exit 2 ;;
	esac
	command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }
	mkdir -p "$out"
	tmp=$(mktemp "${TMPDIR:-/tmp}/autocar-hysteria.XXXXXX")
	trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
	url="${release_base}/hysteria-linux-${arch}"
	curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$tmp" "$url"
	actual=$(sha256_file "$tmp")
	if [ "$actual" != "$expected" ]; then
		echo "Hysteria checksum mismatch: expected $expected, got $actual" >&2
		exit 1
	fi
	chmod 0755 "$tmp"
	mv -f -- "$tmp" "$out/hysteria-linux-$arch"
	trap - EXIT HUP INT TERM
	cat >"$out/provenance.json" <<EOF
{
  "product": "hysteria2",
  "version": "$version",
  "commit": "$commit",
  "architecture": "$arch",
  "url": "$url",
  "sha256": "$actual",
  "verified": true
}
EOF
	printf '%s\n' "$out/hysteria-linux-$arch"
}

server_config() {
	[ "$#" -ge 5 ] && [ "$#" -le 7 ] || { usage; exit 2; }
	out=$1
	cert=$2
	key=$3
	password=$4
	origin=$5
	profile=${6:-standard}
	obfs_password=${7:-}
	for pair in "CERT:$cert" "KEY:$key" "PASSWORD:$password" "ORIGIN:$origin"; do
		require_scalar "${pair%%:*}" "${pair#*:}"
	done
	case "$origin" in
		http://*|https://*) ;;
		*) echo "ORIGIN must be an http(s) URL; default 404 comparison is forbidden" >&2; exit 2 ;;
	esac
	case "$profile" in
		standard) ;;
		gecko) require_scalar OBFS_PASSWORD "$obfs_password" ;;
		*) echo "profile must be standard or gecko" >&2; exit 2 ;;
	esac
	{
		printf 'listen: :8443\n'
		printf 'tls:\n  cert: %s\n  key: %s\n' "$(yaml_quote "$cert")" "$(yaml_quote "$key")"
		printf 'auth:\n  type: password\n  password: %s\n' "$(yaml_quote "$password")"
		printf 'quic:\n  disableStatelessReset: true\n'
		if [ "$profile" = gecko ]; then
			printf 'obfs:\n  type: gecko\n  gecko:\n    password: %s\n    minPacketSize: 512\n    maxPacketSize: 1200\n' "$(yaml_quote "$obfs_password")"
		fi
		printf 'masquerade:\n  type: proxy\n  proxy:\n    url: %s\n    rewriteHost: true\n    insecure: false\n    xForwarded: false\n  listenHTTPS: :8443\n' "$(yaml_quote "$origin")"
	} >"$out"
}

client_config() {
	[ "$#" -ge 6 ] && [ "$#" -le 8 ] || { usage; exit 2; }
	out=$1
	server=$2
	sni=$3
	ca=$4
	password=$5
	http_listen=$6
	profile=${7:-standard}
	obfs_password=${8:-}
	for pair in "SERVER:$server" "SNI:$sni" "CA:$ca" "PASSWORD:$password" "HTTP_LISTEN:$http_listen"; do
		require_scalar "${pair%%:*}" "${pair#*:}"
	done
	case "$profile" in
		standard) ;;
		gecko) require_scalar OBFS_PASSWORD "$obfs_password" ;;
		*) echo "profile must be standard or gecko" >&2; exit 2 ;;
	esac
	{
		printf 'server: %s\n' "$(yaml_quote "$server")"
		printf 'auth: %s\n' "$(yaml_quote "$password")"
		printf 'tls:\n  sni: %s\n  ca: %s\n' "$(yaml_quote "$sni")" "$(yaml_quote "$ca")"
		printf 'quic:\n  disableChromeParrot: false\n'
		if [ "$profile" = gecko ]; then
			printf 'obfs:\n  type: gecko\n  gecko:\n    password: %s\n    minPacketSize: 512\n    maxPacketSize: 1200\n' "$(yaml_quote "$obfs_password")"
		fi
		printf 'lazy: true\nhttp:\n  listen: %s\n' "$(yaml_quote "$http_listen")"
	} >"$out"
}

[ "$#" -ge 1 ] || { usage; exit 2; }
command=$1
shift
case "$command" in
	fetch) fetch "$@" ;;
	server-config) server_config "$@" ;;
	client-config) client_config "$@" ;;
	*) usage; exit 2 ;;
esac
