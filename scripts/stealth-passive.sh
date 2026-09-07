#!/bin/sh
set -eu

# Offline-only wrapper. It never captures traffic or contacts a network; PCAPs
# must come from the isolated, user-owned lab described in the benchmark doc.

if [ "$#" -ne 2 ]; then
	echo "usage: $0 CAPTURE_MANIFEST.csv OUTPUT_DIR" >&2
	exit 2
fi

invocation_dir=$(pwd -P)
manifest=$1
output=$2
case "$output" in
	''|/) echo "refusing unsafe output directory" >&2; exit 2 ;;
esac
case "$manifest" in /*) ;; *) manifest="$invocation_dir/$manifest" ;; esac
case "$output" in /*) ;; *) output="$invocation_dir/$output" ;; esac
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd -P)
if [ "$output" = / ]; then
	echo "refusing unsafe output directory" >&2
	exit 2
fi
for generated in features.csv extraction.json scores.json; do
	if [ -e "$output/$generated" ]; then
		echo "refusing to overwrite existing evidence file: $output/$generated" >&2
		exit 2
	fi
done
python3 scripts/stealth-features.py \
	--manifest "$manifest" \
	--output "$output/features.csv" \
	--status-output "$output/extraction.json"

python3 scripts/stealth-classify.py \
	--features "$output/features.csv" \
	--preregistration testdata/stealth/preregistration.json \
	--output "$output/scores.json"

printf 'offline stealth evidence written to %s\n' "$output"
