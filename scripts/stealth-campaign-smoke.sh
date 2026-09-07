#!/bin/sh
set -eu
umask 077

# Toy UDP-only smoke for the campaign driver's Docker/capture path. Its output
# is calibration evidence and must never support a product comparison claim.

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"

docker_bin=$(printenv DOCKER_BIN 2>/dev/null || printf docker)
label_key=com.cppla.autocar.stealth-campaign
label_value=driver-smoke
label="$label_key=$label_value"
network=autocar-stealth-driver-smoke
capture_image=autocar-stealth-capture-driver-smoke:local
toy_image=autocar-stealth-campaign-toy-driver-smoke:local
servers="autocar-stealth-toy-cover autocar-stealth-toy-autocar autocar-stealth-toy-hysteria2"

command -v "$docker_bin" >/dev/null 2>&1 || {
	echo "docker is required" >&2
	exit 2
}
for name in $servers; do
	if [ -n "$($docker_bin container ls -aq --filter "name=^$name$")" ]; then
		echo "refusing to reuse existing container: $name" >&2
		exit 2
	fi
done
if [ -n "$($docker_bin network ls -q --filter "name=^$network$")" ]; then
	echo "refusing to reuse existing network: $network" >&2
	exit 2
fi
for image in "$capture_image" "$toy_image"; do
	if [ -n "$($docker_bin image ls -q "$image" 2>/dev/null)" ]; then
		echo "refusing to overwrite existing image tag: $image" >&2
		exit 2
	fi
done

cleanup_container() {
	name=$1
	[ -n "$($docker_bin container ls -aq --filter "name=^$name$")" ] || return 0
	actual=$($docker_bin container inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$name" 2>/dev/null || true)
	if [ "$actual" != "$label_value" ]; then
		echo "refusing to remove container with mismatched ownership: $name" >&2
		return 1
	fi
	$docker_bin container rm -f "$name" >/dev/null
}

cleanup() {
	exit_code=$?
	trap - EXIT HUP INT TERM
	for name in $servers; do cleanup_container "$name" || exit_code=1; done
	if [ -n "$($docker_bin network ls -q --filter "name=^$network$")" ]; then
		actual=$($docker_bin network inspect --format "{{ index .Labels \"$label_key\" }}" "$network" 2>/dev/null || true)
		if [ "$actual" = "$label_value" ]; then
			$docker_bin network rm "$network" >/dev/null || exit_code=1
		else
			echo "refusing to remove network with mismatched ownership: $network" >&2
			exit_code=1
		fi
	fi
	for image in "$capture_image" "$toy_image"; do
		if [ -n "$($docker_bin image ls -q "$image" 2>/dev/null)" ]; then
			actual=$($docker_bin image inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$image" 2>/dev/null || true)
			if [ "$actual" = "$label_value" ]; then
				$docker_bin image rm "$image" >/dev/null || exit_code=1
			else
				echo "refusing to remove image with mismatched ownership: $image" >&2
				exit_code=1
			fi
		fi
	done
	exit "$exit_code"
}
trap cleanup EXIT HUP INT TERM

$docker_bin build --label "$label" -f scripts/stealth-capture.Dockerfile \
	-t "$capture_image" . >/dev/null
$docker_bin build --label "$label" -f scripts/stealth-campaign-toy.Dockerfile \
	-t "$toy_image" . >/dev/null
$docker_bin network create --internal --driver bridge --subnet 10.203.77.0/24 \
	--label "$label" "$network" >/dev/null

start_server() {
	name=$1
	address=$2
	$docker_bin run -d --name "$name" --label "$label" --network "$network" \
		--ip "$address" --read-only --cap-drop ALL \
		--security-opt no-new-privileges "$toy_image" server --listen :8443 >/dev/null
}
start_server autocar-stealth-toy-cover 10.203.77.10
start_server autocar-stealth-toy-autocar 10.203.77.11
start_server autocar-stealth-toy-hysteria2 10.203.77.12

suffix="$(date +%s)-$$"
configured_output=$(printenv AUTOCAR_STEALTH_CAMPAIGN_SMOKE_DIR 2>/dev/null || true)
configured_cell=$(printenv AUTOCAR_STEALTH_CAMPAIGN_SMOKE_CELL 2>/dev/null || true)
if [ -n "$configured_output" ]; then
	output=$configured_output
else
	output="$repo_root/artifacts/stealth-campaign-smoke/$suffix"
fi
if [ -n "$configured_cell" ]; then
	cell=$configured_cell
else
	cell=healthy_h3/download_1k
fi
python3 scripts/stealth-campaign.py \
	--mode calibration \
	--cell "$cell" \
	--config testdata/stealth/campaign-driver.smoke.json \
	--output "$output"

printf 'toy-only campaign driver smoke passed; calibration artifact: %s\n' "$output"
