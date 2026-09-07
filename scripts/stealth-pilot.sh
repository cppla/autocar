#!/bin/sh
set -eu
umask 077

# Small, real-product calibration capture. There is deliberately no SSH,
# remote Docker, host-network, firewall, or host-qdisc path in this script.

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"

usage() {
	cat >&2 <<'EOF'
usage: scripts/stealth-pilot.sh [--self-test]

Environment:
  AUTOCAR_STEALTH_PILOT_DIR       new artifact directory
  STEALTH_PILOT_SAMPLES_PER_CELL  calibration samples per product/cell (default 2; max 5)
  STEALTH_PILOT_WORKLOADS         supported comma list (default idle,download_1k,parallel_20)
  STEALTH_PILOT_CAPTURE_IMAGE     existing local capture image (default autocar-stealth-capture:local)
  STEALTH_PILOT_HYSTERIA_IMAGE    existing local official image (default autocar-hy2-baseline:v2.12.2)
  STEALTH_PILOT_HYSTERIA_BINARY   optional existing official binary; avoids image extraction
  DOCKER_BIN                      Docker CLI (default docker)

The normal run captures healthy_h3/{idle,download_1k,parallel_20}. It always
finishes as calibration/insufficient_evidence and cannot establish a product
superiority claim. The cover arm is a standard quic-go H3 control, not a real
browser; this is recorded in every manifest.
EOF
}

if [ "${1:-}" = --self-test ]; then
	[ "$#" -eq 1 ] || { usage; exit 2; }
	python3 scripts/stealth-pilot-config.py self-test
	GOPROXY=off go test ./scripts/stealth-pilot
	exit 0
fi
[ "$#" -eq 0 ] || { usage; exit 2; }

docker_bin=${DOCKER_BIN:-docker}
samples=${STEALTH_PILOT_SAMPLES_PER_CELL:-2}
pilot_workloads=${STEALTH_PILOT_WORKLOADS:-idle,download_1k,parallel_20}
capture_image=${STEALTH_PILOT_CAPTURE_IMAGE:-autocar-stealth-capture:local}
hysteria_source_image=${STEALTH_PILOT_HYSTERIA_IMAGE:-autocar-hy2-baseline:v2.12.2}
hysteria_binary_input=${STEALTH_PILOT_HYSTERIA_BINARY:-}

case "$samples" in
	''|*[!0-9]*) echo "STEALTH_PILOT_SAMPLES_PER_CELL must be an integer" >&2; exit 2 ;;
esac
if [ "$samples" -lt 1 ] || [ "$samples" -gt 5 ]; then
	echo "STEALTH_PILOT_SAMPLES_PER_CELL must be in 1..5; this runner is calibration-only" >&2
	exit 2
fi
case "$pilot_workloads" in
	idle|download_1k|parallel_20|idle,download_1k|idle,parallel_20|download_1k,parallel_20|idle,download_1k,parallel_20) ;;
	*) echo "STEALTH_PILOT_WORKLOADS must be an ordered unique subset of idle,download_1k,parallel_20" >&2; exit 2 ;;
esac
for tool in "$docker_bin" python3 go git grep sed date mkdir chmod id chown mktemp rm sleep cp dirname basename; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required command not found: $tool" >&2; exit 2; }
done

# Refuse a remote Docker endpoint before creating any resource.
docker_context=$($docker_bin context show)
docker_endpoint=$($docker_bin context inspect "$docker_context" --format '{{ (index .Endpoints "docker").Host }}')
case "$docker_endpoint" in
	unix://*|npipe://*) ;;
	*) echo "remote Docker contexts are refused: $docker_endpoint" >&2; exit 2 ;;
esac

# Images are inputs, never pulled by this script. Explicit inspect calls make a
# missing local prerequisite fail before docker run/build could resolve it.
resolve_local_image() {
	reference=$1
	if $docker_bin image inspect "$reference" >/dev/null 2>&1; then
		printf '%s\n' "$reference"
		return 0
	fi
	# Docker Desktop's containerd image view can occasionally list a tagged
	# image while name-based inspect fails. Resolve that already-local tag to its
	# unique immutable ID; image ls never pulls.
	identifiers=$($docker_bin image ls --no-trunc --filter "reference=$reference" --format '{{.ID}}')
	if [ -z "$identifiers" ] || [ -n "$(printf '%s\n' "$identifiers" | sed -n '2p')" ]; then
		return 1
	fi
	case "$identifiers" in sha256:*) ;; *) return 1 ;; esac
	$docker_bin image inspect "$identifiers" >/dev/null 2>&1 || return 1
	printf '%s\n' "$identifiers"
}

capture_image_requested=$capture_image
capture_image=$(resolve_local_image "$capture_image_requested") || {
	echo "missing local capture image: $capture_image_requested" >&2
	echo "prepare it separately with scripts/stealth-capture.Dockerfile" >&2
	exit 2
}
if [ -n "$hysteria_binary_input" ]; then
	[ -f "$hysteria_binary_input" ] || { echo "STEALTH_PILOT_HYSTERIA_BINARY is not a file" >&2; exit 2; }
	hysteria_binary_input=$(CDPATH= cd -- "$(dirname "$hysteria_binary_input")" && printf '%s/%s\n' "$PWD" "$(basename "$hysteria_binary_input")")
else
	hysteria_image_requested=$hysteria_source_image
	hysteria_source_image=$(resolve_local_image "$hysteria_image_requested") || {
		echo "missing local pinned Hysteria image: $hysteria_image_requested" >&2
		echo "set STEALTH_PILOT_HYSTERIA_BINARY to a previously verified local binary" >&2
		echo "the pilot refuses to fetch or pull from the public network" >&2
		exit 2
	}
fi

engine_arch=$($docker_bin info --format '{{.Architecture}}')
case "$engine_arch" in
	arm64|aarch64) goarch=arm64 ;;
	amd64|x86_64) goarch=amd64 ;;
	*) echo "unsupported Docker architecture: $engine_arch" >&2; exit 2 ;;
esac
if [ -z "$hysteria_binary_input" ]; then
	image_arch=$($docker_bin image inspect "$hysteria_source_image" --format '{{.Architecture}}')
	case "$image_arch:$goarch" in
		arm64:arm64|aarch64:arm64|amd64:amd64|x86_64:amd64) ;;
		*) echo "Hysteria image architecture $image_arch does not match Docker $engine_arch" >&2; exit 2 ;;
	esac
fi
expected_hysteria_sha=$(python3 - "$goarch" <<'PY'
import json, sys
value = json.load(open("testdata/stealth/preregistration.json", encoding="utf-8"))["baseline"]
print(value["linux_" + sys.argv[1] + "_sha256"])
PY
)

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
suffix="pilot-${timestamp}-$$"
campaign_id="$suffix"
label_key=com.cppla.autocar.stealth-campaign
label_value=$campaign_id
label="$label_key=$label_value"
network="autocar-stealth-$suffix"
runner_image="autocar-stealth-pilot:$suffix"

configured_output=${AUTOCAR_STEALTH_PILOT_DIR:-}
if [ -n "$configured_output" ]; then
	artifact_dir=$configured_output
else
	artifact_dir="$repo_root/artifacts/stealth-pilot/$suffix"
fi
if [ -e "$artifact_dir" ]; then
	echo "refusing to overwrite existing pilot artifact path: $artifact_dir" >&2
	exit 2
fi
mkdir -p "$artifact_dir"
artifact_dir=$(CDPATH= cd -- "$artifact_dir" && pwd -P)
chmod 0700 "$artifact_dir"

pilot_tmp=$(mktemp -d "${TMPDIR:-/tmp}/autocar-stealth-pilot.XXXXXX")
inputs="$pilot_tmp/inputs"
mkdir -p "$inputs"
chmod 0700 "$inputs"

origin="autocar-pilot-origin-$suffix"
control="autocar-pilot-control-$suffix"
autocar_server="autocar-pilot-relay-$suffix"
hysteria_server="autocar-pilot-hysteria-$suffix"
extractor="autocar-pilot-extract-$suffix"
generator_token="autocar-pilot-token-$suffix"
generator_cert="autocar-pilot-cert-$suffix"
servers="$origin $control $autocar_server $hysteria_server"

cleanup_container() {
	name=$1
	[ -n "$($docker_bin container ls -aq --filter "name=^${name}$")" ] || return 0
	actual=$($docker_bin container inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$name" 2>/dev/null || true)
	if [ "$actual" != "$label_value" ]; then
		echo "refusing to remove container with mismatched ownership: $name" >&2
		return 1
	fi
	$docker_bin container rm -f "$name" >/dev/null
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	for name in $servers "$extractor" "$generator_token" "$generator_cert"; do
		cleanup_container "$name" || status=1
	done
	if [ -n "$($docker_bin network ls -q --filter "name=^${network}$")" ]; then
		actual=$($docker_bin network inspect --format "{{ index .Labels \"$label_key\" }}" "$network" 2>/dev/null || true)
		if [ "$actual" = "$label_value" ]; then
			$docker_bin network rm "$network" >/dev/null || status=1
		else
			echo "refusing to remove network with mismatched ownership: $network" >&2
			status=1
		fi
	fi
	if [ -n "$($docker_bin image ls -q "$runner_image" 2>/dev/null)" ]; then
		actual=$($docker_bin image inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$runner_image" 2>/dev/null || true)
		if [ "$actual" = "$label_value" ]; then
			$docker_bin image rm "$runner_image" >/dev/null 2>&1 || true
		else
			echo "refusing to remove image with mismatched ownership: $runner_image" >&2
			status=1
		fi
	fi
	case "$pilot_tmp" in
		*/autocar-stealth-pilot.*) rm -rf -- "$pilot_tmp" ;;
		*) echo "refusing to remove unexpected temporary path: $pilot_tmp" >&2; status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

for name in $servers "$extractor" "$generator_token" "$generator_cert"; do
	if [ -n "$($docker_bin container ls -aq --filter "name=^${name}$")" ]; then
		echo "refusing to reuse existing container: $name" >&2
		exit 2
	fi
done
if [ -n "$($docker_bin network ls -q --filter "name=^${network}$")" ]; then
	echo "refusing to reuse existing network: $network" >&2
	exit 2
fi
if [ -n "$($docker_bin image ls -q "$runner_image" 2>/dev/null)" ]; then
	echo "refusing to overwrite existing runner image: $runner_image" >&2
	exit 2
fi

# Compile from the current v1.0.1 worktree with dependency fetching disabled.
# The resulting Linux binaries are frozen before any capture begins.
git_head=$(git rev-parse --verify HEAD)
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath \
	-ldflags="-s -w -X github.com/cppla/autocar/internal/version.Version=v1.0.1-pilot -X github.com/cppla/autocar/internal/version.Commit=$git_head -X github.com/cppla/autocar/internal/version.Date=$build_date" \
	-o "$inputs/autocar" ./cmd/autocar
GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath \
	-o "$inputs/stealth-pilot" ./scripts/stealth-pilot
chmod 0755 "$inputs/autocar" "$inputs/stealth-pilot"

# Stage an already-local official binary and verify both its metadata and
# preregistered release checksum. No curl, registry pull, or public endpoint is
# used by the pilot.
if [ -n "$hysteria_binary_input" ]; then
	cp "$hysteria_binary_input" "$inputs/hysteria"
else
	$docker_bin create --name "$extractor" --label "$label" --entrypoint /hysteria \
		"$hysteria_source_image" version >/dev/null
	$docker_bin cp "$extractor:/hysteria" "$inputs/hysteria"
	cleanup_container "$extractor"
fi
chmod 0755 "$inputs/hysteria"
actual_hysteria_sha=$(python3 - "$inputs/hysteria" <<'PY'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())
PY
)
if [ "$actual_hysteria_sha" != "$expected_hysteria_sha" ]; then
	echo "official Hysteria checksum mismatch: got $actual_hysteria_sha" >&2
	exit 1
fi
# A scratch image assembled only from the frozen local binaries cannot resolve
# a package mirror or registry during RUN steps.
$docker_bin build --network none --label "$label" --build-arg "REVISION=$git_head" \
	-f scripts/stealth-pilot.Dockerfile -t "$runner_image" "$inputs" \
	>"$artifact_dir/runner-build.log"

$docker_bin run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges \
	--mount "type=bind,src=$inputs/hysteria,dst=/hysteria,readonly" \
	--entrypoint /hysteria "$runner_image" version >"$artifact_dir/hysteria-version.txt" 2>&1
grep -F 'Version:' "$artifact_dir/hysteria-version.txt" | grep -F 'v2.12.2' >/dev/null
grep -F 'CommitHash:' "$artifact_dir/hysteria-version.txt" | grep -F '619a6f856b69fb7ee6a7a379e810e68b84004605' >/dev/null

host_uid=$(id -u)
host_gid=$(id -g)
if [ "$host_uid" -eq 0 ] || [ "$host_gid" -eq 0 ]; then
	runtime_user=65532:65532
	chown 65532:65532 "$inputs" "$inputs/autocar" "$inputs/stealth-pilot" "$inputs/hysteria"
else
	runtime_user="$host_uid:$host_gid"
fi

$docker_bin run --rm --name "$generator_token" --label "$label" --network none \
	--read-only --cap-drop ALL --security-opt no-new-privileges --user "$runtime_user" \
	--mount "type=bind,src=$inputs,dst=/pilot" --entrypoint /autocar "$runner_image" \
	token --out /pilot/token
$docker_bin run --rm --name "$generator_cert" --label "$label" --network none \
	--read-only --cap-drop ALL --security-opt no-new-privileges --user "$runtime_user" \
	--mount "type=bind,src=$inputs,dst=/pilot" --entrypoint /autocar "$runner_image" \
	cert --hosts cover.test --organization "Pilot Ordinary Site" \
	--cert /pilot/server.crt --key /pilot/server.key >"$artifact_dir/certificate.log"

$docker_bin network ls -q | while IFS= read -r network_id; do
	[ -n "$network_id" ] && printf '%s\n' "$network_id"
done >"$pilot_tmp/network-ids"
if [ -s "$pilot_tmp/network-ids" ]; then
	# shellcheck disable=SC2046
	$docker_bin network inspect $(sed -n '1,10000p' "$pilot_tmp/network-ids") >"$pilot_tmp/networks.json"
else
	printf '[]\n' >"$pilot_tmp/networks.json"
fi
subnet=$(python3 scripts/stealth-pilot-config.py select-subnet --networks-json "$pilot_tmp/networks.json")
case "$subnet" in
	10.242.*.0/24) ;;
	*) echo "unsafe subnet selector output: $subnet" >&2; exit 1 ;;
esac
prefix=${subnet%0/24}
control_ip=${prefix}10
autocar_ip=${prefix}20
hysteria_ip=${prefix}30
origin_ip=${prefix}40

password=$(sed -n '1p' "$inputs/token")
scripts/stealth-hysteria.sh server-config "$inputs/hysteria-server.yaml" \
	/pilot/server.crt /pilot/server.key "$password" "http://$origin_ip:8080" standard
scripts/stealth-hysteria.sh client-config "$inputs/hysteria-client.yaml" \
	"$hysteria_ip:8443" cover.test /pilot/server.crt "$password" 127.0.0.1:18080 standard
chmod 0600 "$inputs/token" "$inputs/server.key" "$inputs/hysteria-server.yaml" "$inputs/hysteria-client.yaml"
chmod 0644 "$inputs/server.crt"
if [ "$host_uid" -eq 0 ] || [ "$host_gid" -eq 0 ]; then
	chown 65532:65532 "$inputs/token" "$inputs/server.key" "$inputs/server.crt" \
		"$inputs/hysteria-server.yaml" "$inputs/hysteria-client.yaml"
fi

$docker_bin network create --internal --driver bridge --subnet "$subnet" \
	--label "$label" "$network" >/dev/null

run_server() {
	name=$1
	ip=$2
	shift 2
	$docker_bin run -d --name "$name" --label "$label" --network "$network" --ip "$ip" \
		--read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 \
		--memory 512m "$@" >/dev/null
}

run_server "$origin" "$origin_ip" "$runner_image" serve-origin --listen :8080
run_server "$control" "$control_ip" --user "$runtime_user" \
	--mount "type=bind,src=$inputs,dst=/pilot,readonly" "$runner_image" \
	serve-h3 --listen :8443 --cert /pilot/server.crt --key /pilot/server.key
run_server "$autocar_server" "$autocar_ip" --user "$runtime_user" \
	--mount "type=bind,src=$inputs,dst=/pilot,readonly" --entrypoint /autocar "$runner_image" \
	server --protocol web --listen :8443 --tcp-listen :8443 \
	--cert /pilot/server.crt --key /pilot/server.key --token-file /pilot/token \
	--cover-upstream "http://$origin_ip:8080" --allow-private --deny-ports none
run_server "$hysteria_server" "$hysteria_ip" --user "$runtime_user" \
	--mount "type=bind,src=$inputs,dst=/pilot,readonly" \
	--mount "type=bind,src=$inputs/hysteria,dst=/hysteria,readonly" \
	--entrypoint /hysteria "$runner_image" server --disable-update-check \
	-c /pilot/hysteria-server.yaml

assert_only_lab_network() {
	name=$1
	actual=$($docker_bin container inspect --format '{{range $key, $value := .NetworkSettings.Networks}}{{println $key}}{{end}}' "$name")
	if [ "$actual" != "$network" ]; then
		echo "$name is attached outside the dedicated pilot bridge" >&2
		exit 1
	fi
}
for name in $servers; do assert_only_lab_network "$name"; done

wait_http_origin() {
	attempts=80
	while [ "$attempts" -gt 0 ]; do
		if $docker_bin run --rm --label "$label" --network "$network" --read-only \
			--cap-drop ALL --security-opt no-new-privileges "$runner_image" \
			probe-http --url "http://$origin_ip:8080/health" >/dev/null 2>&1; then
			return 0
		fi
		attempts=$((attempts - 1))
		sleep 0.1
	done
	echo "origin readiness timeout" >&2
	return 1
}

wait_log() {
	name=$1
	text=$2
	attempts=100
	while [ "$attempts" -gt 0 ]; do
		if $docker_bin logs "$name" 2>&1 | grep -F "$text" >/dev/null; then return 0; fi
		if [ "$($docker_bin inspect --format '{{.State.Running}}' "$name" 2>/dev/null || true)" != true ]; then
			echo "$name exited before readiness" >&2
			return 1
		fi
		attempts=$((attempts - 1))
		sleep 0.1
	done
	echo "$name readiness timeout: $text" >&2
	return 1
}

wait_http_origin
wait_log "$autocar_server" 'transport=h3'
wait_log "$hysteria_server" 'server up and running'
# Exercise the standard H3 control before campaign capture so configuration or
# certificate failures cannot consume a scheduled sample.
$docker_bin run --rm --label "$label" --network "$network" --read-only \
	--cap-drop ALL --security-opt no-new-privileges --user "$runtime_user" \
	--mount "type=bind,src=$inputs,dst=/pilot,readonly" "$runner_image" \
	h3-workload --server "$control_ip:8443" --server-name cover.test \
	--ca /pilot/server.crt --workload download_1k --seed 1 >/dev/null

autocar_version=$($docker_bin run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --entrypoint /autocar "$runner_image" version)
hysteria_version=v2.12.2-619a6f856b69fb7ee6a7a379e810e68b84004605
python3 scripts/stealth-pilot-config.py prepare \
	--output "$inputs/campaign.json" \
	--autocar-effective-output "$inputs/autocar-effective.json" \
	--hysteria-effective-output "$inputs/hysteria-effective.json" \
	--campaign-id "$campaign_id" --network "$network" \
	--capture-image "$capture_image" --runner-image "$runner_image" \
	--capture-host local-docker-internal-pilot --inputs-root "$inputs" --user "$runtime_user" \
	--control-container "$control" --control-ip "$control_ip" \
	--autocar-container "$autocar_server" --autocar-ip "$autocar_ip" \
	--hysteria-container "$hysteria_server" --hysteria-ip "$hysteria_ip" \
	--origin-ip "$origin_ip" --cert "$inputs/server.crt" --key "$inputs/server.key" \
	--token "$inputs/token" --autocar-binary "$inputs/autocar" \
	--hysteria-binary "$inputs/hysteria" \
	--hysteria-client-config "$inputs/hysteria-client.yaml" \
	--hysteria-server-config "$inputs/hysteria-server.yaml" \
	--autocar-version "$autocar_version" --hysteria-version "$hysteria_version" \
	--hysteria-expected-sha256 "$expected_hysteria_sha"

set -- --mode calibration --groups 1 --samples-per-group "$samples"
old_ifs=$IFS
IFS=,
for workload in $pilot_workloads; do
	set -- "$@" --cell "healthy_h3/$workload"
done
IFS=$old_ifs
set -- "$@" --config "$inputs/campaign.json" --output "$artifact_dir/campaign"
python3 scripts/stealth-campaign.py "$@"

offline_dir="$artifact_dir/offline"
mkdir -p "$offline_dir"
set +e
$docker_bin run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --entrypoint tshark "$capture_image" --version \
	>"$offline_dir/tshark-container-probe.txt" 2>&1
container_tshark_exit=$?
python3 scripts/stealth-features.py \
	--manifest "$artifact_dir/campaign/capture-manifest.csv" \
	--output "$offline_dir/features.csv" \
	--status-output "$offline_dir/extraction.json" \
	>"$offline_dir/extraction.stdout.json" 2>"$offline_dir/extraction.stderr.log"
extraction_exit=$?
classification_arg=
if [ "$extraction_exit" -eq 0 ]; then
	python3 scripts/stealth-classify.py \
		--features "$offline_dir/features.csv" \
		--preregistration testdata/stealth/preregistration.json \
		--output "$offline_dir/scores.json" \
		>"$offline_dir/classification.stdout.json" 2>"$offline_dir/classification.stderr.log"
	classification_exit=$?
	if [ -f "$offline_dir/scores.json" ]; then
		classification_arg=$offline_dir/scores.json
	fi
else
	classification_exit=not-run
fi
set -e
python3 - "$offline_dir/tool-status.json" "$container_tshark_exit" "$extraction_exit" "$classification_exit" <<'PY'
import json, os, sys, tempfile
path, container_exit, extraction_exit, classification_exit = sys.argv[1:]
value = {
    "schema_version": 1,
    "container_tshark_exit": int(container_exit),
    "container_tshark_available": container_exit == "0",
    "extraction_exit": int(extraction_exit),
    "classification_exit": classification_exit,
}
fd, temporary = tempfile.mkstemp(prefix=".tool-status.", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(temporary, path)
PY

set -- --campaign-dir "$artifact_dir/campaign" --output "$artifact_dir/pilot-summary.json" \
	--samples-per-cell "$samples" --workloads "$pilot_workloads" \
	--autocar-version "$autocar_version" --hysteria-version "$hysteria_version" \
	--extraction-status "$offline_dir/extraction.json"
if [ -n "$classification_arg" ]; then
	set -- "$@" --classification-status "$classification_arg"
fi
python3 scripts/stealth-pilot-config.py finalize \
	"$@"

printf 'real-product pilot completed as calibration/insufficient_evidence: %s\n' "$artifact_dir"
