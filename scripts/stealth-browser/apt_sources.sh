#!/bin/sh
set -eu

# Emit only frozen, signature-checked Debian sources. No host files are edited.
[ "$#" -eq 2 ] || { echo 'usage: apt_sources.sh DEBIAN_TIMESTAMP SECURITY_TIMESTAMP' >&2; exit 2; }
for snapshot in "$@"; do
	[ "${#snapshot}" -eq 16 ] && printf '%s' "$snapshot" | grep -Eq '^[0-9]{8}T[0-9]{6}Z$' || {
		echo 'APT snapshot must be an exact YYYYMMDDTHHMMSSZ timestamp' >&2
		exit 2
	}
done

# HTTP bootstraps the CA-less base image. APT still verifies Debian signatures
# and package hashes using its pinned-image archive keyring. Only the archived
# metadata's expiry check is disabled, separately on each frozen source.
printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' "$1" "$2"
