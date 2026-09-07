#!/bin/sh
set -eu
umask 077

# Formal, local-Linux-only browser/AutoCAR/Hysteria capture orchestration.
# `prepare` runs the complete 21-cell, one-sample calibration and stops there.
# A full 31,500-PCAP campaign starts only through an explicit later subcommand.

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
config_tool="$script_dir/stealth-full-config.py"
campaign_tool="$script_dir/stealth-campaign.py"
browser_versions="$script_dir/stealth-browser/versions.debian13-amd64.json"
docker_bin=${DOCKER_BIN:-docker}

caddy_ref='caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d'
nginx_ref='nginx@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8'
label_key='com.cppla.autocar.stealth-campaign'
minimum_capacity_kib=31457280
minimum_inodes=50000
minimum_memory_and_swap_kib=4194304

usage() {
	cat >&2 <<'EOF'
usage:
  scripts/stealth-full-lab.sh self-test
  scripts/stealth-full-lab.sh prepare ABSOLUTE_NEW_LAB_DIR
  scripts/stealth-full-lab.sh resume-calibration ABSOLUTE_LAB_DIR
  scripts/stealth-full-lab.sh status ABSOLUTE_LAB_DIR
  scripts/stealth-full-lab.sh plan-only ABSOLUTE_LAB_DIR
  scripts/stealth-full-lab.sh checkpoint ABSOLUTE_LAB_DIR [NEW_SAMPLE_LIMIT]
  scripts/stealth-full-lab.sh resume ABSOLUTE_LAB_DIR [NEW_SAMPLE_LIMIT]
  scripts/stealth-full-lab.sh full ABSOLUTE_LAB_DIR
  scripts/stealth-full-lab.sh cleanup ABSOLUTE_LAB_DIR

prepare builds immutable local runner images, downloads and verifies official
Hysteria v2.12.2, starts five labelled servers on one unique --internal bridge,
and captures 63 required calibration PCAPs plus two browser-H2 controls. It
never starts the preregistered full run.

The full output is fixed at LAB_DIR/full-campaign so cleanup/status can reason
about it safely. Run plan-only first, then checkpoint/resume or explicit full.
At least 30 GiB free, 50,000 free inodes, and 4 GiB combined physical
RAM plus configured swap are required (nominal 4 GiB VMs commonly report
slightly less physical RAM and satisfy this gate with swap).
Only local unix-socket Docker on Linux/amd64 is accepted.
EOF
}

die() {
	echo "stealth full lab: $*" >&2
	exit 2
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

absolute_safe_dir() {
	value=$1
	case "$value" in
		/*) ;;
		*) die "lab directory must be absolute" ;;
	esac
	case "$value" in
		/|*','*|*"\n"*|*"\r"*) die "unsafe lab directory" ;;
	esac
}

require_local_linux_docker() {
	[ "$(uname -s)" = Linux ] || die "formal lab orchestration must run on the Linux lab host"
	context=$($docker_bin context show)
	endpoint=$($docker_bin context inspect "$context" --format '{{ (index .Endpoints "docker").Host }}')
	case "$endpoint" in
		unix://*) ;;
		*) die "remote Docker contexts are refused: $endpoint" ;;
	esac
	architecture=$($docker_bin info --format '{{.Architecture}}')
	case "$architecture" in
		amd64|x86_64) ;;
		*) die "the frozen Debian 13 browser pins currently support Docker amd64 only" ;;
	esac
}

free_kib() {
	df -Pk "$1" | awk 'NR==2 {print $4}'
}

free_inodes() {
	df -Pi "$1" | awk 'NR==2 {print $4}'
}

require_capacity() {
	path=$1
	available=$(free_kib "$path")
	case "$available" in ''|*[!0-9]*) die "cannot read free disk capacity for $path" ;; esac
	[ "$available" -ge "$minimum_capacity_kib" ] || die "$path needs at least 30 GiB free for the formal lab"
	inodes=$(free_inodes "$path")
	case "$inodes" in ''|*[!0-9]*) die "cannot read free inode count for $path" ;; esac
	[ "$inodes" -ge "$minimum_inodes" ] || die "$path needs at least 50,000 free inodes"
}

require_memory() {
	mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
	swap_kib=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
	case "$mem_kib:$swap_kib" in *[!0-9:]*|:*) die "cannot read Linux memory capacity" ;; esac
	total_kib=$((mem_kib + swap_kib))
	[ "$total_kib" -ge "$minimum_memory_and_swap_kib" ] || \
		die "formal browser lab needs at least 4 GiB combined RAM+swap; found $((total_kib / 1024)) MiB"
}

safe_capture_host() {
	value=$1
	case "$value" in
		''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.:-]*) die "STEALTH_CAPTURE_HOST must be a safe single-line host identifier" ;;
	esac
	[ "${#value}" -le 255 ] || die "STEALTH_CAPTURE_HOST is too long"
	printf '%s\n' "$value"
}

require_clean_git() {
	git -C "$repo_root" rev-parse --verify HEAD >/dev/null
	[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ] || \
		die "formal lab preparation requires a clean Git worktree"
	git -C "$repo_root" diff --quiet
	git -C "$repo_root" diff --cached --quiet
}

json_value() {
	file=$1
	path=$2
	python3 - "$file" "$path" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit("missing JSON field " + sys.argv[2])
    value = value[part]
if not isinstance(value, (str, int)) or isinstance(value, bool):
    raise SystemExit("JSON field is not scalar")
text = str(value)
if not text or any(character in text for character in "\x00\r\n"):
    raise SystemExit("JSON field is not a safe scalar")
print(text)
PY
}

resolve_image_id() {
	identifier=$($docker_bin image inspect --format '{{.Id}}' "$1")
	case "$identifier" in
		sha256:????????????????????????????????????????????????????????????????) ;;
		*) die "image did not resolve to an immutable ID: $1" ;;
	esac
	printf '%s\n' "$identifier"
}

pull_pinned_image() {
	reference=$1
	label=$2
	case "$reference" in *@sha256:????????????????????????????????????????????????????????????????) ;; *) die "$label is not digest-pinned" ;; esac
	$docker_bin pull "$reference" >&2
	digests=$($docker_bin image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$reference")
	printf '%s\n' "$digests" | grep -Fx "$reference" >/dev/null || die "$label repository digest was not retained after pull"
	resolve_image_id "$reference"
}

assert_new_docker_name() {
	kind=$1
	name=$2
	case "$kind" in
		container) ids=$($docker_bin container ls -aq --filter "name=^${name}$") ;;
		network) ids=$($docker_bin network ls -q --filter "name=^${name}$") ;;
		image) ids=$($docker_bin image ls -q "$name" 2>/dev/null || true) ;;
		*) die "internal unsupported Docker kind" ;;
	esac
	[ -z "$ids" ] || die "refusing to reuse existing Docker $kind: $name"
}

owned_container_remove() {
	name=$1
	label_value=$2
	if ! $docker_bin container inspect "$name" >/dev/null 2>&1; then
		return 0
	fi
	actual=$($docker_bin container inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$name")
	[ "$actual" = "$label_value" ] || die "refusing to remove container with mismatched ownership: $name"
	$docker_bin container rm -f "$name" >/dev/null
}

prepare_lab() {
	[ "$#" -eq 1 ] || { usage; exit 2; }
	lab_dir=$1
	absolute_safe_dir "$lab_dir"
	[ ! -e "$lab_dir" ] || die "refusing to overwrite existing lab path: $lab_dir"
	parent=$(dirname "$lab_dir")
	[ -d "$parent" ] || die "lab parent directory does not exist: $parent"
	for tool in "$docker_bin" python3 git awk grep sed date dirname mkdir chmod chown sleep curl df uname id sort openssl; do require_command "$tool"; done
	require_local_linux_docker
	require_memory
	require_capacity "$parent"
	require_clean_git
	capture_host=$(safe_capture_host "${STEALTH_CAPTURE_HOST:-local-linux-docker-full-lab}")
	[ -f "$browser_versions" ] || die "browser pin manifest is missing"
	[ -f "$script_dir/stealth-browser/Dockerfile" ] || die "browser runner Dockerfile is missing"

	mkdir -m 0700 "$lab_dir"
	lab_dir=$(CDPATH= cd -- "$lab_dir" && pwd -P)
	inputs="$lab_dir/inputs"
	logs="$lab_dir/logs"
	mkdir -m 0700 "$inputs" "$logs"
	runtime_user="$(id -u):$(id -g)"
	if [ "$(id -u)" -eq 0 ] || [ "$(id -g)" -eq 0 ]; then
		runtime_user=65532:65532
		chown 65532:65532 "$inputs"
	fi
	success=false
	signal_name=
	on_signal() {
		signal_name=$1
		signal_status=$2
		trap - HUP INT TERM
		echo "stealth full lab: preparation received $signal_name; preserving exact owned resources and evidence" >&2
		exit "$signal_status"
	}
	on_exit() {
		trap - EXIT
		if [ "$success" != true ]; then
			echo "stealth full lab: preparation stopped; labelled resources and evidence were preserved in $lab_dir" >&2
			if [ -f "$lab_dir/lab-metadata.json" ] && [ -d "$lab_dir/calibration" ] && [ ! -f "$lab_dir/lab-state.json" ]; then
				echo "stealth full lab: resume-calibration accepts only completed sample boundaries; a failed or interrupted sample requires investigation and a new campaign" >&2
			else
				echo "stealth full lab: inspect with status, then use explicit cleanup after ruling out an active campaign" >&2
			fi
		fi
	}
	trap on_exit EXIT
	trap 'on_signal SIGHUP 129' HUP
	trap 'on_signal SIGINT 130' INT
	trap 'on_signal SIGTERM 143' TERM

	timestamp=$(date -u +%Y%m%dT%H%M%SZ)
	suffix="full-${timestamp}-$$"
	campaign_id="$suffix"
	label_value=$campaign_id
	ownership_label="$label_key=$label_value"
	network="autocar-stealth-$suffix"
	runner_tag="autocar-stealth-runner:$suffix"
	capture_tag="autocar-stealth-capture:$suffix"
	chromium_tag="autocar-stealth-chromium:$suffix"
	firefox_tag="autocar-stealth-firefox:$suffix"
	origin_container="autocar-full-origin-$suffix"
	caddy_container="autocar-full-caddy-$suffix"
	nginx_container="autocar-full-nginx-$suffix"
	autocar_container="autocar-full-relay-$suffix"
	hysteria_container="autocar-full-hysteria-$suffix"
	extractor_container="autocar-full-extract-$suffix"

	for name in "$origin_container" "$caddy_container" "$nginx_container" "$autocar_container" "$hysteria_container" "$extractor_container"; do
		assert_new_docker_name container "$name"
	done
	assert_new_docker_name network "$network"
	for name in "$runner_tag" "$capture_tag" "$chromium_tag" "$firefox_tag"; do assert_new_docker_name image "$name"; done
	python3 "$config_tool" write-ownership-journal --lab-dir "$lab_dir" \
		--campaign-id "$campaign_id" --network "$network" \
		--origin-container "$origin_container" --caddy-container "$caddy_container" \
		--nginx-container "$nginx_container" --autocar-container "$autocar_container" \
		--hysteria-container "$hysteria_container" --extractor-container "$extractor_container"

	# Choose a non-overlapping RFC1918 /24 from the current local Docker inventory.
	$docker_bin network ls -q >"$logs/network-ids.txt"
	if [ -s "$logs/network-ids.txt" ]; then
		# shellcheck disable=SC2046
		$docker_bin network inspect $(sed -n '1,10000p' "$logs/network-ids.txt") >"$logs/networks-before.json"
	else
		printf '[]\n' >"$logs/networks-before.json"
	fi
	subnet=$(python3 "$script_dir/stealth-pilot-config.py" select-subnet --networks-json "$logs/networks-before.json")
	case "$subnet" in 10.242.*.0/24) ;; *) die "subnet selector returned an unsafe value: $subnet" ;; esac
	prefix=${subnet%0/24}
	caddy_ip=${prefix}10
	nginx_ip=${prefix}11
	autocar_ip=${prefix}20
	hysteria_ip=${prefix}30
	origin_ip=${prefix}40

	git_head=$(git -C "$repo_root" rev-parse --verify HEAD)
	build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	$docker_bin build --pull --label "$ownership_label" \
		--build-arg VERSION=v1.0.1-full-lab --build-arg COMMIT="$git_head" \
		--build-arg BUILD_DATE="$build_date" -f scripts/stealth-full-runner.Dockerfile \
		-t "$runner_tag" . >"$logs/runner-build.log" 2>&1
	runner_id=$(resolve_image_id "$runner_tag")

	$docker_bin create --name "$extractor_container" --label "$ownership_label" "$runner_id" >/dev/null
	$docker_bin cp "$extractor_container:/autocar" "$inputs/autocar"
	$docker_bin cp "$extractor_container:/stealth-pilot" "$inputs/stealth-pilot"
	owned_container_remove "$extractor_container" "$label_value"
	chmod 0555 "$inputs/autocar" "$inputs/stealth-pilot"

	hysteria_release="$inputs/hysteria-release"
	mkdir -m 0700 "$hysteria_release"
	"$script_dir/stealth-hysteria.sh" fetch "$hysteria_release" amd64 >"$logs/hysteria-fetch.log"
	hysteria_binary="$hysteria_release/hysteria-linux-amd64"
	hysteria_expected_sha=$(json_value "$hysteria_release/provenance.json" sha256)

	$docker_bin build --pull --label "$ownership_label" -f scripts/stealth-capture.Dockerfile \
		-t "$capture_tag" . >"$logs/capture-build.log" 2>&1
	capture_id=$(resolve_image_id "$capture_tag")

	base_image=$(json_value "$browser_versions" base_image)
	chromium_package=$(json_value "$browser_versions" chromium.browser_package_version)
	chromium_driver=$(json_value "$browser_versions" chromium.webdriver_package_version)
	firefox_package=$(json_value "$browser_versions" firefox-esr.browser_package_version)
	gecko_version=$(json_value "$browser_versions" firefox-esr.webdriver_package_version)
	gecko_sha=$(json_value "$browser_versions" firefox-esr.webdriver_archive_sha256)
	pull_pinned_image "$base_image" "browser base" >/dev/null
	$docker_bin build --pull --label "$ownership_label" \
		--build-arg BASE_IMAGE="$base_image" --build-arg BROWSER_FAMILY=chromium \
		--build-arg BROWSER_PACKAGE_VERSION="$chromium_package" \
		--build-arg WEBDRIVER_PACKAGE_VERSION="$chromium_driver" \
		-f scripts/stealth-browser/Dockerfile -t "$chromium_tag" . \
		>"$logs/chromium-build.log" 2>&1
	chromium_id=$(resolve_image_id "$chromium_tag")
	$docker_bin build --pull --label "$ownership_label" \
		--build-arg BASE_IMAGE="$base_image" --build-arg BROWSER_FAMILY=firefox-esr \
		--build-arg BROWSER_PACKAGE_VERSION="$firefox_package" \
		--build-arg WEBDRIVER_PACKAGE_VERSION="$gecko_version" \
		--build-arg WEBDRIVER_ARCHIVE_SHA256="$gecko_sha" \
		-f scripts/stealth-browser/Dockerfile -t "$firefox_tag" . \
		>"$logs/firefox-build.log" 2>&1
	firefox_id=$(resolve_image_id "$firefox_tag")

	caddy_id=$(pull_pinned_image "$caddy_ref" Caddy)
	nginx_id=$(pull_pinned_image "$nginx_ref" nginx)
	# The pinned official Caddy binary carries cap_net_bind_service in its file
	# capabilities. Linux refuses to exec it when that capability is absent from
	# the container bounding set, even for the unprivileged lab port 8443.
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--cap-add NET_BIND_SERVICE \
		--security-opt no-new-privileges --entrypoint /usr/bin/caddy "$caddy_id" version \
		>"$logs/caddy-version.txt" 2>&1 || die "could not execute the pinned Caddy binary"
	grep -F 'v2.10.2' "$logs/caddy-version.txt" >/dev/null || die "Caddy binary is not v2.10.2"
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint /usr/sbin/nginx "$nginx_id" -V \
		>"$logs/nginx-version.txt" 2>&1
	grep -F 'nginx/1.29.1' "$logs/nginx-version.txt" >/dev/null || die "nginx binary is not 1.29.1"
	grep -F -- '--with-http_v2_module' "$logs/nginx-version.txt" >/dev/null || die "nginx lacks HTTP/2"
	grep -F -- '--with-http_v3_module' "$logs/nginx-version.txt" >/dev/null || die "nginx lacks HTTP/3"

	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --user "$runtime_user" \
		--mount "type=bind,src=$inputs,dst=/lab" --entrypoint /autocar "$runner_id" \
		token --out /lab/token
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --user "$runtime_user" \
		--mount "type=bind,src=$inputs,dst=/lab" --entrypoint /autocar "$runner_id" \
		cert --hosts "cover.test,$caddy_ip,$nginx_ip" --organization "Ordinary Site Lab" \
		--cert /lab/server.crt --key /lab/server.key >"$logs/certificate.log"
	openssl x509 -in "$inputs/server.crt" -pubkey -noout >"$logs/server-public-key.pem"
	openssl pkey -pubin -in "$logs/server-public-key.pem" -outform DER \
		-out "$logs/server-spki.der"
	openssl dgst -sha256 -binary -out "$logs/server-spki.sha256" "$logs/server-spki.der"
	chromium_spki_sha256=$(openssl base64 -A -in "$logs/server-spki.sha256")
	python3 - "$chromium_spki_sha256" <<'PY'
import base64, binascii, sys
value = sys.argv[1]
try:
    decoded = base64.b64decode(value, validate=True)
except (binascii.Error, ValueError) as error:
    raise SystemExit("generated Chromium SPKI pin is not valid Base64") from error
if len(value) != 44 or not value.endswith("=") or len(decoded) != 32:
    raise SystemExit("generated Chromium SPKI pin is not a canonical SHA-256 Base64 value")
if base64.b64encode(decoded).decode("ascii") != value:
    raise SystemExit("generated Chromium SPKI pin is not canonical Base64")
PY

	password=$(sed -n '1p' "$inputs/token")
	[ -n "$password" ] || die "generated token is empty"
	"$script_dir/stealth-hysteria.sh" server-config "$inputs/hysteria-server.yaml" \
		/campaign/server.crt /campaign/server.key "$password" "http://$origin_ip:8080" standard
	"$script_dir/stealth-hysteria.sh" client-config "$inputs/hysteria-client.yaml" \
		"$hysteria_ip:8443" cover.test /pilot/server.crt "$password" 127.0.0.1:18080 standard
	unset password
	chmod 0600 "$inputs/token" "$inputs/server.key" "$inputs/hysteria-server.yaml" "$inputs/hysteria-client.yaml"
	chmod 0644 "$inputs/server.crt"

	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=32m \
		"$chromium_id" identity >"$inputs/chromium-identity.json"
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=32m \
		"$firefox_id" identity >"$inputs/firefox-identity.json"
	chromium_client=$(json_value "$inputs/chromium-identity.json" client_implementation)
	chromium_version=$(json_value "$inputs/chromium-identity.json" implementation_version)
	chromium_binary_sha=$(json_value "$inputs/chromium-identity.json" browser_binary_sha256)
	firefox_client=$(json_value "$inputs/firefox-identity.json" client_implementation)
	firefox_version=$(json_value "$inputs/firefox-identity.json" implementation_version)
	firefox_binary_sha=$(json_value "$inputs/firefox-identity.json" browser_binary_sha256)
	autocar_version=$($docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint /autocar "$runner_id" version)
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --mount "type=bind,src=$hysteria_binary,dst=/hysteria,readonly" \
		--entrypoint /hysteria "$runner_id" version >"$logs/hysteria-version.txt" 2>&1
	grep -F 'Version:' "$logs/hysteria-version.txt" | grep -F 'v2.12.2' >/dev/null || die "Hysteria version mismatch"
	grep -F 'CommitHash:' "$logs/hysteria-version.txt" | grep -F '619a6f856b69fb7ee6a7a379e810e68b84004605' >/dev/null || die "Hysteria commit mismatch"
	hysteria_version='v2.12.2-619a6f856b69fb7ee6a7a379e810e68b84004605'

	if [ "$(id -u)" -eq 0 ] || [ "$(id -g)" -eq 0 ]; then
		chown -R 65532:65532 "$inputs"
	fi
	preregistered_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	python3 "$config_tool" generate \
		--lab-dir "$lab_dir" --inputs-root "$inputs" \
		--campaign-output "$inputs/campaign.json" --metadata-output "$lab_dir/lab-metadata.json" \
		--full-output-dir "$lab_dir/full-campaign" \
		--autocar-effective-output "$inputs/autocar-effective.json" \
		--hysteria-effective-output "$inputs/hysteria-effective.json" \
		--caddy-output "$inputs/Caddyfile" --nginx-output "$inputs/nginx.conf" \
		--campaign-id "$campaign_id" --network "$network" \
		--capture-image "$capture_id" --runner-image "$runner_id" \
		--chromium-image "$chromium_id" --firefox-image "$firefox_id" \
		--capture-host "$capture_host" --user "$runtime_user" \
		--origin-container "$origin_container" --origin-ip "$origin_ip" \
		--caddy-container "$caddy_container" --caddy-ip "$caddy_ip" \
		--nginx-container "$nginx_container" --nginx-ip "$nginx_ip" \
		--autocar-container "$autocar_container" --autocar-ip "$autocar_ip" \
		--hysteria-container "$hysteria_container" --hysteria-ip "$hysteria_ip" \
		--cert "$inputs/server.crt" --key "$inputs/server.key" --token "$inputs/token" \
		--autocar-binary "$inputs/autocar" --hysteria-binary "$hysteria_binary" \
		--hysteria-client-config "$inputs/hysteria-client.yaml" \
		--hysteria-server-config "$inputs/hysteria-server.yaml" \
		--autocar-version "$autocar_version" --hysteria-version "$hysteria_version" \
		--hysteria-expected-sha256 "$hysteria_expected_sha" \
		--chromium-client-implementation "$chromium_client" \
		--chromium-version "$chromium_version" --chromium-binary-sha256 "$chromium_binary_sha" \
		--chromium-spki-sha256 "$chromium_spki_sha256" \
		--firefox-client-implementation "$firefox_client" \
		--firefox-version "$firefox_version" --firefox-binary-sha256 "$firefox_binary_sha" \
		--caddy-image "$caddy_ref" --nginx-image "$nginx_ref" \
		--preregistration-recorded-at "$preregistered_at"
	if [ "$(id -u)" -eq 0 ] || [ "$(id -g)" -eq 0 ]; then
		chown -R 65532:65532 "$inputs"
	fi
	# Guarantee the whole-second preregistration timestamp precedes capture.
	sleep 2

	$docker_bin network create --internal --driver bridge --subnet "$subnet" \
		--label "$ownership_label" "$network" >/dev/null

	$docker_bin run -d --name "$origin_container" --label "$ownership_label" \
		--network "$network" --ip "$origin_ip" --read-only --cap-drop ALL \
		--security-opt no-new-privileges --pids-limit 128 --memory 128m \
		"$runner_id" serve-origin --listen :8080 >/dev/null
	$docker_bin run -d --name "$caddy_container" --label "$ownership_label" \
		--network "$network" --ip "$caddy_ip" --read-only --cap-drop ALL \
		--cap-add NET_BIND_SERVICE \
		--security-opt no-new-privileges --pids-limit 128 --memory 256m --user "$runtime_user" \
		--tmpfs /data:rw,nosuid,nodev,size=32m --tmpfs /config:rw,nosuid,nodev,size=16m \
		--tmpfs /tmp:rw,nosuid,nodev,size=16m \
		--mount "type=bind,src=$inputs/Caddyfile,dst=/campaign/Caddyfile,readonly" \
		--mount "type=bind,src=$inputs/server.crt,dst=/campaign/server.crt,readonly" \
		--mount "type=bind,src=$inputs/server.key,dst=/campaign/server.key,readonly" \
		--entrypoint /usr/bin/caddy "$caddy_id" run --config /campaign/Caddyfile --adapter caddyfile >/dev/null
	$docker_bin run -d --name "$nginx_container" --label "$ownership_label" \
		--network "$network" --ip "$nginx_ip" --read-only --cap-drop ALL \
		--security-opt no-new-privileges --pids-limit 128 --memory 256m --user "$runtime_user" \
		--tmpfs /tmp:rw,nosuid,nodev,size=64m \
		--mount "type=bind,src=$inputs/nginx.conf,dst=/campaign/nginx.conf,readonly" \
		--mount "type=bind,src=$inputs/server.crt,dst=/campaign/server.crt,readonly" \
		--mount "type=bind,src=$inputs/server.key,dst=/campaign/server.key,readonly" \
		--entrypoint /usr/sbin/nginx "$nginx_id" -c /campaign/nginx.conf -g 'daemon off;' >/dev/null
	$docker_bin run -d --name "$autocar_container" --label "$ownership_label" \
		--network "$network" --ip "$autocar_ip" --read-only --cap-drop ALL \
		--security-opt no-new-privileges --pids-limit 128 --memory 512m --user "$runtime_user" \
		--mount "type=bind,src=$inputs,dst=/campaign,readonly" --entrypoint /autocar "$runner_id" \
		server --protocol web --listen :8443 --tcp-listen :8443 \
		--cert /campaign/server.crt --key /campaign/server.key --token-file /campaign/token \
		--cover-upstream "http://$origin_ip:8080" --allow-private --deny-ports none >/dev/null
	$docker_bin run -d --name "$hysteria_container" --label "$ownership_label" \
		--network "$network" --ip "$hysteria_ip" --read-only --cap-drop ALL \
		--security-opt no-new-privileges --pids-limit 128 --memory 512m --user "$runtime_user" \
		--mount "type=bind,src=$inputs,dst=/campaign,readonly" \
		--mount "type=bind,src=$hysteria_binary,dst=/hysteria,readonly" \
		--entrypoint /hysteria "$runner_id" server --disable-update-check \
		-c /campaign/hysteria-server.yaml >/dev/null

	for name in "$origin_container" "$caddy_container" "$nginx_container" "$autocar_container" "$hysteria_container"; do
		actual=$($docker_bin container inspect --format '{{range $key, $value := .NetworkSettings.Networks}}{{println $key}}{{end}}' "$name")
		[ "$actual" = "$network" ] || die "$name escaped the dedicated lab network"
	done

	wait_origin "$network" "$origin_ip" "$runner_id" "$ownership_label"
	wait_log "$caddy_container" 'serving initial configuration'
	wait_log "$nginx_container" 'start worker process'
	wait_log "$autocar_container" 'transport=h3'
	wait_log "$hysteria_container" 'server up and running'
	for endpoint_ip in "$caddy_ip" "$nginx_ip"; do
		$docker_bin run --rm --label "$ownership_label" --network "$network" --read-only \
			--cap-drop ALL --security-opt no-new-privileges --user "$runtime_user" \
			--mount "type=bind,src=$inputs/server.crt,dst=/pilot/server.crt,readonly" \
			"$runner_id" h3-workload --server "$endpoint_ip:8443" --server-name cover.test \
			--ca /pilot/server.crt --workload download_1k --seed 1 >/dev/null
	done
	# Exercise every browser/server pair over both H3 and H2 before scheduling
	# any capture. The strict runner receipts are retained as readiness evidence.
	for browser_name in chromium firefox-esr; do
		if [ "$browser_name" = chromium ]; then
			browser_image=$chromium_id
			browser_endpoint=$caddy_ip
		else
			browser_image=$firefox_id
			browser_endpoint=$nginx_ip
		fi
		for browser_protocol in h3 h2; do
			if [ "$browser_protocol" = h2 ]; then browser_workload=browser_h2; else browser_workload=download_128k; fi
			set --
			if [ "$browser_name" = chromium ] && [ "$browser_protocol" = h3 ]; then
				set -- --certificate-spki-sha256 "$chromium_spki_sha256"
			fi
			$docker_bin run --rm --label "$ownership_label" --network "$network" --read-only \
				--cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --memory 896m \
				--user 65532:65532 --tmpfs /tmp:rw,nosuid,nodev,size=256m \
				--tmpfs /run:rw,nosuid,nodev,size=32m --tmpfs /dev/shm:rw,nosuid,nodev,size=256m \
				"$browser_image" --browser "$browser_name" --protocol "$browser_protocol" \
				--server "$browser_endpoint:8443" --workload "$browser_workload" \
				--seed 20260904 --accept-insecure-certs "$@" \
				>"$logs/browser-${browser_name}-${browser_protocol}-readiness.json"
		done
	done
	require_clean_git

	python3 "$campaign_tool" --mode calibration --groups 1 --samples-per-group 1 \
		--include-cover-h2 --config "$inputs/campaign.json" --output "$lab_dir/calibration"
	python3 "$config_tool" verify-calibration --lab-dir "$lab_dir" \
		--campaign-dir "$lab_dir/calibration" --metadata "$lab_dir/lab-metadata.json" \
		--config "$inputs/campaign.json" --token "$inputs/token" --output "$lab_dir/lab-state.json"
	python3 "$config_tool" verify-ready --lab-dir "$lab_dir" >/dev/null
	success=true
	trap - EXIT HUP INT TERM
	printf 'formal lab calibrated as insufficient_evidence; full capture was not started: %s\n' "$lab_dir"
}

wait_origin() {
	network=$1
	origin_ip=$2
	runner_id=$3
	ownership_label=$4
	attempts=100
	while [ "$attempts" -gt 0 ]; do
		if $docker_bin run --rm --label "$ownership_label" --network "$network" --read-only \
			--cap-drop ALL --security-opt no-new-privileges "$runner_id" \
			probe-http --url "http://$origin_ip:8080/health" >/dev/null 2>&1; then
			return 0
		fi
		attempts=$((attempts - 1))
		sleep 0.1
	done
	die "origin readiness timeout"
}

wait_log() {
	name=$1
	needle=$2
	attempts=150
	while [ "$attempts" -gt 0 ]; do
		if $docker_bin logs "$name" 2>&1 | grep -F "$needle" >/dev/null; then return 0; fi
		running=$($docker_bin container inspect --format '{{.State.Running}}' "$name" 2>/dev/null || true)
		[ "$running" = true ] || die "$name exited before readiness"
		attempts=$((attempts - 1))
		sleep 0.1
	done
	die "$name readiness timeout"
}

load_lab() {
	lab_dir=$1
	absolute_safe_dir "$lab_dir"
	lab_dir=$(CDPATH= cd -- "$lab_dir" && pwd -P) || die "lab directory is missing"
	metadata="$lab_dir/lab-metadata.json"
	state="$lab_dir/lab-state.json"
	python3 "$config_tool" status --lab-dir "$lab_dir" >/dev/null
	journal="$lab_dir/ownership-journal.json"
	partial_lab=false
	extractor_container=
	if [ -f "$metadata" ]; then
		campaign_id=$(python3 "$config_tool" value --metadata "$metadata" --field campaign_id)
		ownership_label=$(python3 "$config_tool" value --metadata "$metadata" --field ownership_label)
		network=$(python3 "$config_tool" value --metadata "$metadata" --field network)
		origin_container=$(python3 "$config_tool" value --metadata "$metadata" --field origin_container)
		caddy_container=$(python3 "$config_tool" value --metadata "$metadata" --field caddy_container)
		nginx_container=$(python3 "$config_tool" value --metadata "$metadata" --field nginx_container)
		autocar_container=$(python3 "$config_tool" value --metadata "$metadata" --field autocar_container)
		hysteria_container=$(python3 "$config_tool" value --metadata "$metadata" --field hysteria_container)
	else
		[ -f "$journal" ] || die "lab metadata and ownership journal are both missing"
		partial_lab=true
		campaign_id=$(python3 "$config_tool" journal-value --journal "$journal" --field campaign_id)
		ownership_label=$(python3 "$config_tool" journal-value --journal "$journal" --field ownership_label)
		network=$(python3 "$config_tool" journal-value --journal "$journal" --field network)
		origin_container=$(python3 "$config_tool" journal-value --journal "$journal" --field origin_container)
		caddy_container=$(python3 "$config_tool" journal-value --journal "$journal" --field caddy_container)
		nginx_container=$(python3 "$config_tool" journal-value --journal "$journal" --field nginx_container)
		autocar_container=$(python3 "$config_tool" journal-value --journal "$journal" --field autocar_container)
		hysteria_container=$(python3 "$config_tool" journal-value --journal "$journal" --field hysteria_container)
		extractor_container=$(python3 "$config_tool" journal-value --journal "$journal" --field extractor_container)
	fi
	config="$lab_dir/inputs/campaign.json"
	full_output="$lab_dir/full-campaign"
}

assert_live_lab() {
	require_local_linux_docker
	network_doc=$($docker_bin network inspect --format "{{.Driver}}|{{.Internal}}|{{.Scope}}|{{index .Labels \"$label_key\"}}" "$network" 2>/dev/null || true)
	[ "$network_doc" = "bridge|true|local|$campaign_id" ] || die "lab network is missing or its isolation/ownership changed"
	for name in "$origin_container" "$caddy_container" "$nginx_container" "$autocar_container" "$hysteria_container"; do
		doc=$($docker_bin container inspect --format "{{.State.Running}}|{{index .Config.Labels \"$label_key\"}}" "$name" 2>/dev/null || true)
		[ "$doc" = "true|$campaign_id" ] || die "owned lab server is missing or stopped: $name"
		attached=$($docker_bin container inspect --format '{{range $key, $value := .NetworkSettings.Networks}}{{println $key}}{{end}}' "$name")
		[ "$attached" = "$network" ] || die "lab server network membership changed: $name"
	done
}

require_full_ready() {
	load_lab "$1"
	[ "$partial_lab" = false ] || die "lab preparation did not reach configured state"
	python3 "$config_tool" verify-ready --lab-dir "$lab_dir" >/dev/null
	assert_live_lab
	require_clean_git
	require_capacity "$lab_dir"
}

resume_calibration() {
	[ "$#" -eq 1 ] || { usage; exit 2; }
	load_lab "$1"
	[ "$partial_lab" = false ] || die "calibration cannot resume before metadata exists; use cleanup and prepare a new lab"
	[ ! -f "$state" ] || die "lab-state.json already exists; use verify-ready/plan-only rather than resuming calibration"
	[ -f "$lab_dir/calibration/plan.json" ] || die "no frozen calibration plan exists; prepare stopped before calibration began"
	assert_live_lab
	require_clean_git
	require_capacity "$lab_dir"
	python3 "$campaign_tool" --mode calibration --groups 1 --samples-per-group 1 \
		--include-cover-h2 --resume --config "$config" --output "$lab_dir/calibration"
	python3 "$config_tool" verify-calibration --lab-dir "$lab_dir" \
		--campaign-dir "$lab_dir/calibration" --metadata "$metadata" \
		--config "$config" --token "$lab_dir/inputs/token" --output "$state"
	python3 "$config_tool" verify-ready --lab-dir "$lab_dir" >/dev/null
	printf 'formal lab calibration recovered and verified: %s\n' "$lab_dir"
}

plan_only() {
	[ "$#" -eq 1 ] || { usage; exit 2; }
	require_full_ready "$1"
	[ ! -e "$full_output" ] || die "refusing to overwrite existing full output; use resume/checkpoint/full"
	python3 "$campaign_tool" --mode full --plan-only --config "$config" --output "$full_output"
	printf 'full plan frozen; no full samples captured: %s\n' "$full_output"
}

resume_limited() {
	mode=$1
	shift
	[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage; exit 2; }
	require_full_ready "$1"
	[ -d "$full_output" ] || die "$mode requires plan-only first"
	limit=${2:-500}
	case "$limit" in ''|*[!0-9]*) die "sample limit must be a positive integer" ;; esac
	[ "$limit" -gt 0 ] || die "sample limit must be positive"
	if python3 "$campaign_tool" --mode full --resume --max-samples "$limit" \
		--config "$config" --output "$full_output"; then
		result=0
	else
		result=$?
	fi
	case "$result" in
		0) printf 'full campaign completed: %s\n' "$full_output" ;;
		3) printf 'durable checkpoint written after at most %s new samples: %s\n' "$limit" "$full_output" ;;
		*) exit "$result" ;;
	esac
}

run_full() {
	[ "$#" -eq 1 ] || { usage; exit 2; }
	require_full_ready "$1"
	[ -d "$full_output" ] || die "full requires plan-only first"
	python3 "$campaign_tool" --mode full --resume --config "$config" --output "$full_output"
	python3 "$config_tool" status --lab-dir "$lab_dir"
}

show_status() {
	[ "$#" -eq 1 ] || { usage; exit 2; }
	load_lab "$1"
	python3 "$config_tool" status --lab-dir "$lab_dir"
	if $docker_bin network inspect "$network" >/dev/null 2>&1; then
		for name in "$origin_container" "$caddy_container" "$nginx_container" "$autocar_container" "$hysteria_container"; do
			$docker_bin container inspect --format '{{.Name}} {{.State.Status}} {{.Image}}' "$name" 2>/dev/null || true
		done
	else
		echo "runtime_resources=absent"
	fi
}

cleanup_lab() {
	[ "$#" -eq 1 ] || { usage; exit 2; }
	load_lab "$1"
	require_local_linux_docker
	allowed=" $origin_container $caddy_container $nginx_container $autocar_container $hysteria_container $extractor_container "
	unexpected=
	for identifier in $($docker_bin container ls -aq --filter "label=$ownership_label"); do
		name=$($docker_bin container inspect --format '{{.Name}}' "$identifier" | sed 's#^/##')
		case "$allowed" in *" $name "*) ;; *) unexpected="$unexpected $name" ;; esac
	done
	[ -z "$unexpected" ] || die "refusing cleanup while sample/transient containers exist:$unexpected"
	for name in "$origin_container" "$caddy_container" "$nginx_container" "$autocar_container" "$hysteria_container" $extractor_container; do
		owned_container_remove "$name" "$campaign_id"
	done
	if $docker_bin network inspect "$network" >/dev/null 2>&1; then
		actual=$($docker_bin network inspect --format "{{index .Labels \"$label_key\"}}" "$network")
		[ "$actual" = "$campaign_id" ] || die "refusing to remove network with mismatched ownership"
		$docker_bin network rm "$network" >/dev/null
	fi
	for identifier in $($docker_bin image ls -q --filter "label=$ownership_label" | sort -u); do
		actual=$($docker_bin image inspect --format "{{index .Config.Labels \"$label_key\"}}" "$identifier")
		[ "$actual" = "$campaign_id" ] || die "refusing to remove image with mismatched ownership"
		$docker_bin image rm "$identifier" >/dev/null 2>&1 || die "could not remove owned image $identifier"
	done
	printf 'removed only labelled lab containers/network/images; retained all evidence: %s\n' "$lab_dir"
}

self_test() {
	[ "$#" -eq 0 ] || { usage; exit 2; }
	require_command python3
	python3 -m py_compile "$config_tool" "$campaign_tool" \
		"$script_dir/stealth-browser/run_cover.py" "$script_dir/stealth-browser/write_lock.py"
	python3 "$config_tool" self-test
	python3 "$campaign_tool" --self-test
	python3 "$script_dir/stealth-browser/test_run_cover.py"
	if command -v go >/dev/null 2>&1; then GOPROXY=off go test ./scripts/stealth-pilot; fi
	python3 - "$browser_versions" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value == {
    "schema_version": 1,
    "architecture": "amd64",
    "base_image": "debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132",
    "chromium": {
        "browser_package_version": "152.0.7977.82-1~deb13u1",
        "webdriver_package_version": "152.0.7977.82-1~deb13u1",
    },
    "firefox-esr": {
        "browser_package_version": "140.15.0esr-1~deb13u1",
        "webdriver_package_version": "0.36.0",
        "webdriver_release_commit": "a3d508507022",
        "webdriver_archive_sha256": "0bde38707eb0a686a20c6bd50f4adcc7d60d4f73c60eb83ee9e0db8f65823e04",
    },
}
PY
	printf '{"schema_version":1,"status":"pass","self_test":true}\n'
}

[ "$#" -ge 1 ] || { usage; exit 2; }
command_name=$1
shift
cd "$repo_root"
case "$command_name" in
	self-test) self_test "$@" ;;
	prepare) prepare_lab "$@" ;;
	resume-calibration) resume_calibration "$@" ;;
	status) show_status "$@" ;;
	plan-only) plan_only "$@" ;;
	checkpoint) resume_limited checkpoint "$@" ;;
	resume) resume_limited resume "$@" ;;
	full) run_full "$@" ;;
	cleanup) cleanup_lab "$@" ;;
	*) usage; exit 2 ;;
esac
