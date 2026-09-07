#!/bin/sh
set -eu
umask 077

# Isolated Docker active-probe and UDP-blackhole suite. All impairment happens
# in an ordinary user-space gateway container; this script never changes host
# firewall, routing, qdisc, or network namespaces.

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"

docker_bin=${DOCKER_BIN:-docker}
iterations=${STEALTH_ITERATIONS:-3}
release_gate=${STEALTH_RELEASE_GATE:-0}
run_gecko=${STEALTH_RUN_GECKO:-1}
run_role=${STEALTH_RUN_ROLE:-unspecified}
execution_host=${STEALTH_EXECUTION_HOST:-}
prebuilt_autocar_image=${STEALTH_AUTOCAR_IMAGE:-}
prebuilt_lab_image=${STEALTH_LAB_IMAGE:-}

case "$iterations" in
	''|*[!0-9]*|0) echo "STEALTH_ITERATIONS must be a positive integer" >&2; exit 2 ;;
esac
case "$release_gate" in 0|1) ;; *) echo "STEALTH_RELEASE_GATE must be 0 or 1" >&2; exit 2 ;; esac
case "$run_gecko" in 0|1) ;; *) echo "STEALTH_RUN_GECKO must be 0 or 1" >&2; exit 2 ;; esac
case "$run_role" in local-docker|remote-linux|unspecified) ;; *) echo "STEALTH_RUN_ROLE must be local-docker, remote-linux, or unspecified" >&2; exit 2 ;; esac
case "$run_role" in
	local-docker)
		if [ -n "$execution_host" ] && [ "$execution_host" != local-docker ]; then
			echo "local-docker evidence requires STEALTH_EXECUTION_HOST=local-docker or unset" >&2
			exit 2
		fi
		execution_host=local-docker
		;;
	unspecified)
		if [ -n "$execution_host" ] && [ "$execution_host" != unspecified ]; then
			echo "unspecified evidence requires STEALTH_EXECUTION_HOST=unspecified or unset" >&2
			exit 2
		fi
		execution_host=unspecified
		;;
	remote-linux)
		if [ -z "$execution_host" ]; then
			echo "STEALTH_EXECUTION_HOST is required for remote-linux evidence" >&2
			exit 2
		fi
		;;
esac
case "$execution_host" in
	*[!A-Za-z0-9._:-]*|'')
		echo "STEALTH_EXECUTION_HOST must contain only letters, digits, dot, colon, underscore, or hyphen" >&2
		exit 2
		;;
esac
if [ "${#execution_host}" -gt 300 ]; then
	echo "STEALTH_EXECUTION_HOST is too long" >&2
	exit 2
fi
if [ "$run_role" = remote-linux ]; then
	execution_host_name=${execution_host%%:*}
	case "$execution_host" in
		*:*:*)
			echo "remote-linux STEALTH_EXECUTION_HOST must name the direct non-loopback host" >&2
			exit 2
			;;
	esac
	case "$execution_host_name" in
		localhost|*.localhost|unspecified|local-docker|127.*|0.0.0.0)
			echo "remote-linux STEALTH_EXECUTION_HOST must name the direct non-loopback host" >&2
			exit 2
			;;
	esac
	case "$execution_host" in
		*:*)
			execution_port=${execution_host##*:}
			case "$execution_port" in ''|*[!0-9]*) echo "STEALTH_EXECUTION_HOST has an invalid port" >&2; exit 2 ;; esac
			if [ "$execution_port" -eq 0 ] || [ "$execution_port" -gt 65535 ]; then
				echo "STEALTH_EXECUTION_HOST has an invalid port" >&2
				exit 2
			fi
			;;
	esac
fi
if [ "$release_gate" -eq 1 ] && [ "$iterations" -lt 100 ]; then
	echo "release gate requires STEALTH_ITERATIONS >= 100" >&2
	exit 2
fi
if [ "$release_gate" -eq 1 ] && [ "$run_gecko" -ne 1 ]; then
	echo "release gate requires STEALTH_RUN_GECKO=1" >&2
	exit 2
fi
if [ "$release_gate" -eq 1 ] && [ "$run_role" = unspecified ]; then
	echo "release gate requires STEALTH_RUN_ROLE=local-docker or remote-linux" >&2
	exit 2
fi
if [ "$run_role" = remote-linux ] && [ "$(uname -s)" != Linux ]; then
	echo "STEALTH_RUN_ROLE=remote-linux requires a Linux host" >&2
	exit 2
fi
execution_host_ssh_key_sha256=not-applicable
if [ "$run_role" = remote-linux ]; then
	command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen is required for remote host identity" >&2; exit 2; }
	host_key_file=/etc/ssh/ssh_host_ed25519_key.pub
	if [ ! -r "$host_key_file" ]; then
		echo "readable $host_key_file is required for remote host identity" >&2
		exit 2
	fi
	execution_host_ssh_key_sha256=$(ssh-keygen -E sha256 -lf "$host_key_file" | awk 'NR == 1 { print $2 }')
	case "$execution_host_ssh_key_sha256" in
		SHA256:*) ;;
		*) echo "could not derive the remote ED25519 SSH host-key fingerprint" >&2; exit 2 ;;
	esac
fi
if { [ -n "$prebuilt_autocar_image" ] && [ -z "$prebuilt_lab_image" ]; } || \
	{ [ -z "$prebuilt_autocar_image" ] && [ -n "$prebuilt_lab_image" ]; }; then
	echo "STEALTH_AUTOCAR_IMAGE and STEALTH_LAB_IMAGE must be supplied together" >&2
	exit 2
fi
if [ "$release_gate" -eq 1 ] && [ -n "$prebuilt_autocar_image" ]; then
	echo "release gate requires images built from the frozen Git archive by this run" >&2
	exit 2
fi
for command in "$docker_bin" git curl sed awk grep cp id date sleep tar uname; do
	command -v "$command" >/dev/null 2>&1 || { echo "required command not found: $command" >&2; exit 2; }
done
git_head_start=$(git rev-parse --verify HEAD)
git_tree_start=$(git rev-parse "${git_head_start}^{tree}")
worktree_state_start=$(git status --porcelain=v1 --untracked-files=all)
worktree_clean_start=true
if [ -n "$worktree_state_start" ]; then worktree_clean_start=false; fi
if [ "$release_gate" -eq 1 ] && [ "$worktree_clean_start" != true ]; then
	echo "release gate requires a clean Git worktree so the tested commit identifies the exact source" >&2
	exit 2
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/autocar-stealth-active.XXXXXX")
suffix="${tmp##*.}-$$-$(date +%s)"
artifact_root=${AUTOCAR_STEALTH_ARTIFACT_DIR:-artifacts/stealth-active}
artifact_dir="$artifact_root/$suffix"
mkdir -p "$artifact_dir"
artifact_dir=$(cd "$artifact_dir" && pwd -P)
chmod 0755 "$artifact_dir"

build_context=$repo_root
build_context_source=worktree
if [ "$release_gate" -eq 1 ]; then
	# Freeze the release build context to the exact clean commit checked above.
	# Later worktree changes therefore cannot alter either image under test.
	mkdir -p "$tmp/source"
	git archive --format=tar "$git_head_start" | tar -xf - -C "$tmp/source"
	build_context=$tmp/source
	build_context_source=git_archive
fi

label_key=com.cppla.autocar.stealth-run
label_value=$suffix
label="$label_key=$label_value"
network=autocar-stealth-$suffix
autocar_image=autocar:stealth-$suffix
lab_image=autocar-stealth-lab:$suffix
images_owned=true
if [ -n "$prebuilt_autocar_image" ]; then
	autocar_image=$prebuilt_autocar_image
	lab_image=$prebuilt_lab_image
	images_owned=false
	build_context_source=prebuilt_images
fi

origin=autocar-stealth-origin-$suffix
target=autocar-stealth-target-$suffix
control=autocar-stealth-control-$suffix
hy_control=autocar-stealth-hy2-control-$suffix
token_generator=autocar-stealth-token-$suffix
cert_generator=autocar-stealth-cert-$suffix
relay=autocar-stealth-relay-$suffix
edge=autocar-stealth-edge-$suffix
hy_relay=autocar-stealth-hy2-$suffix
hy_edge=autocar-stealth-hy2-edge-$suffix
hy_client_ok=autocar-stealth-hy2-client-ok-$suffix
hy_client_blocked=autocar-stealth-hy2-client-blocked-$suffix
gecko_relay=autocar-stealth-gecko-$suffix
gecko_client=autocar-stealth-gecko-client-$suffix

containers="$origin $target $control $hy_control $token_generator $cert_generator $relay $edge $hy_relay $hy_edge $hy_client_ok $hy_client_blocked $gecko_relay $gecko_client"

cleanup_container() {
	name=$1
	[ -n "$($docker_bin container ls -aq --filter "name=^${name}$")" ] || return 0
	actual=$($docker_bin container inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$name" 2>/dev/null || true)
	if [ "$actual" != "$label_value" ]; then
		echo "refusing to remove container with mismatched ownership label: $name" >&2
		return 1
	fi
	$docker_bin container rm -f "$name" >/dev/null 2>&1 || true
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -ne 0 ]; then
		for name in $containers; do
			if [ -n "$($docker_bin container ls -aq --filter "name=^${name}$")" ]; then
				echo "logs from $name:" >&2
				$docker_bin logs --tail 80 "$name" >&2 || true
			fi
		done
	fi
	for name in $containers; do cleanup_container "$name" || status=1; done
	if [ -n "$($docker_bin network ls -q --filter "name=^${network}$")" ]; then
		actual=$($docker_bin network inspect --format "{{ index .Labels \"$label_key\" }}" "$network" 2>/dev/null || true)
		if [ "$actual" = "$label_value" ]; then
			$docker_bin network rm "$network" >/dev/null 2>&1 || status=1
		else
			echo "refusing to remove network with mismatched ownership label: $network" >&2
			status=1
		fi
	fi
	if [ "$images_owned" = true ]; then
		for image in "$autocar_image" "$lab_image"; do
			if [ -n "$($docker_bin image ls -q "$image" 2>/dev/null)" ]; then
				actual=$($docker_bin image inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$image" 2>/dev/null || true)
				if [ "$actual" = "$label_value" ]; then
					$docker_bin image rm "$image" >/dev/null 2>&1 || true
				else
					echo "refusing to remove image with mismatched ownership label: $image" >&2
					status=1
				fi
			fi
		done
	fi
	case "$tmp" in
		*/autocar-stealth-active.*) rm -rf -- "$tmp" ;;
		*) echo "refusing to remove unexpected temporary directory: $tmp" >&2; status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

run_detached() {
	name=$1
	shift
	$docker_bin run -d --name "$name" --label "$label" --network "$network" "$@" >/dev/null
}

wait_http() {
	url=$1
	attempts=60
	while [ "$attempts" -gt 0 ]; do
		if $docker_bin run --rm --network "$network" "$lab_image" fetch --url "$url" --timeout 1s >/dev/null 2>&1; then
			return 0
		fi
		attempts=$((attempts - 1))
		sleep 0.2
	done
	echo "timed out waiting for $url" >&2
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
		sleep 0.2
	done
	echo "timed out waiting for $name log: $text" >&2
	return 1
}

wait_proxy_fetch() {
	proxy=$1
	url=$2
	attempts=${3:-60}
	while [ "$attempts" -gt 0 ]; do
		if $docker_bin run --rm --network "$network" "$lab_image" fetch --proxy "$proxy" --url "$url" --timeout 2s >/dev/null 2>&1; then
			return 0
		fi
		attempts=$((attempts - 1))
		sleep 0.25
	done
	return 1
}

if [ "$images_owned" = true ]; then
	echo "building isolated AutoCAR and stealth-lab images"
	$docker_bin build --label "$label" --label "org.opencontainers.image.revision=$git_head_start" \
		--build-arg "COMMIT=$git_head_start" -f "$build_context/Dockerfile" -t "$autocar_image" "$build_context" \
		>"$artifact_dir/autocar-build.log"
	$docker_bin build --label "$label" --label "org.opencontainers.image.revision=$git_head_start" \
		-f "$build_context/scripts/stealth-lab.Dockerfile" -t "$lab_image" "$build_context" \
		>"$artifact_dir/lab-build.log"
else
	echo "using caller-supplied prebuilt AutoCAR and stealth-lab images"
	$docker_bin image inspect "$autocar_image" "$lab_image" >/dev/null
fi
$docker_bin network create --internal --label "$label" "$network" >/dev/null
lab_cidr=$($docker_bin network inspect --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' "$network" | sed -n '1p')
if [ -z "$lab_cidr" ]; then
	echo "isolated Docker network did not report an allowlist CIDR" >&2
	exit 1
fi
docker_engine_id=$($docker_bin info --format '{{.ID}}')
if [ -z "$docker_engine_id" ]; then
	echo "Docker engine did not report a stable ID" >&2
	exit 1
fi
docker_engine_fingerprint=$(printf '%s' "$docker_engine_id" | git hash-object --stdin)

host_user="$(id -u):$(id -g)"
$docker_bin run --rm --name "$token_generator" --label "$label" \
	--network none --read-only --user "$host_user" \
	-v "$tmp:/run/stealth" \
	"$autocar_image" token --out /run/stealth/token
$docker_bin run --rm --name "$cert_generator" --label "$label" \
	--network none --read-only --user "$host_user" \
	-v "$tmp:/run/stealth" \
	"$autocar_image" cert \
	--hosts cover.test \
	--organization "Ordinary Site" \
	--cert /run/stealth/server.crt \
	--key /run/stealth/server.key >"$artifact_dir/certificate.log"

run_detached "$origin" "$lab_image" origin --listen :8080
run_detached "$target" "$lab_image" echo-server --listen :9000 --metrics :9001
wait_http http://"$origin":8080/
wait_http http://"$target":9001/

run_detached "$control" \
	--user "$host_user" \
	-v "$tmp:/run/stealth:ro" \
	"$lab_image" cover-server --listen :8443 --cert /run/stealth/server.crt --key /run/stealth/server.key --origin http://"$origin":8080
run_detached "$hy_control" \
	--user "$host_user" \
	-v "$tmp:/run/stealth:ro" \
	"$lab_image" cover-server --listen :8443 --cert /run/stealth/server.crt --key /run/stealth/server.key \
	--origin http://"$origin":8080 --alt-svc-max-age 2592000

run_detached "$relay" \
	--user "$host_user" \
	-v "$tmp:/run/stealth:ro" \
	"$autocar_image" server \
	--protocol web --listen :8443 --tcp-listen :8443 \
	--cert /run/stealth/server.crt --key /run/stealth/server.key --token-file /run/stealth/token \
	--cover-upstream http://"$origin":8080 --allow-private --deny-ports none
wait_log "$relay" 'transport=h3'
wait_log "$relay" 'transport=h2'

release_arg=
if [ "$release_gate" -eq 1 ]; then release_arg=--release-gate; fi
$docker_bin run --rm --network "$network" --user "$host_user" \
	-v "$tmp:/run/stealth:ro" -v "$artifact_dir:/artifacts" \
	"$lab_image" active \
	--product autocar --relay "$relay":8443 --control "$control":8443 \
	--server-name cover.test --ca /run/stealth/server.crt --token-file /run/stealth/token \
	--target "$target":9000 --dial-count-url http://"$target":9001/ \
	--isolated-lab --allow-net "$lab_cidr" \
	--iterations "$iterations" --seed 20260904 $release_arg \
	--output /artifacts/autocar-active.jsonl >"$artifact_dir/autocar-active-summary.json"
autocar_summary_line=$(sed -n '$p' "$artifact_dir/autocar-active.jsonl")
autocar_active_status=$(printf '%s\n' "$autocar_summary_line" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
if [ "$autocar_active_status" != pass ]; then
	echo "AutoCAR active probe did not produce a passing summary" >&2
	exit 1
fi

run_detached "$edge" "$lab_image" gateway --listen :9443 --backend "$relay":8443 --control :9090 --udp-enabled=false
wait_http http://"$edge":9090/state
$docker_bin run --rm --network "$network" --user "$host_user" \
	-v "$tmp:/run/stealth:ro" -v "$artifact_dir:/artifacts" \
	"$lab_image" transition \
	--server "$edge":9443 --server-name cover.test --ca /run/stealth/server.crt --token-file /run/stealth/token \
	--target "$target":9000 --gateway-control http://"$edge":9090 \
	--isolated-lab --allow-net "$lab_cidr" \
	--primary-timeout 800ms --fallback-cooldown 1200ms \
	--output /artifacts/autocar-transition.json >"$artifact_dir/autocar-transition-summary.json"
autocar_transition_status=$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$artifact_dir/autocar-transition.json" | sed -n '1p')
if [ "$autocar_transition_status" != pass ]; then
	echo "AutoCAR transition probe did not produce a passing summary" >&2
	exit 1
fi

# Pinned Hysteria baseline. The downloaded official binary is verified before
# being mounted into the otherwise package-free lab image.
case "$($docker_bin info --format '{{.Architecture}}')" in
	x86_64|amd64) hy_arch=amd64 ;;
	aarch64|arm64) hy_arch=arm64 ;;
	*) echo "unsupported Docker architecture" >&2; exit 2 ;;
esac
hy_bin=$(scripts/stealth-hysteria.sh fetch "$tmp/hysteria" "$hy_arch")
cp "$tmp/hysteria/provenance.json" "$artifact_dir/hysteria-provenance.json"
hy_password=$(sed -n '1p' "$tmp/token")
scripts/stealth-hysteria.sh server-config "$tmp/hysteria-server.yaml" \
	/run/stealth/server.crt /run/stealth/server.key "$hy_password" "http://$origin:8080" standard
scripts/stealth-hysteria.sh client-config "$tmp/hysteria-client.yaml" \
	"$hy_edge:9443" cover.test /run/stealth/server.crt "$hy_password" :8080 standard

run_detached "$hy_relay" \
	--user "$host_user" --entrypoint /hysteria \
	-v "$tmp:/run/stealth:ro" -v "$hy_bin:/hysteria:ro" \
	"$lab_image" server --disable-update-check -c /run/stealth/hysteria-server.yaml
wait_log "$hy_relay" 'server up and running'

# Hysteria's active equivalence result is comparator evidence, not a condition
# engineered to fail. Its status is retained even when it differs from the
# cover-only control.
set +e
$docker_bin run --rm --network "$network" --user "$host_user" \
	-v "$tmp:/run/stealth:ro" -v "$artifact_dir:/artifacts" \
	"$lab_image" active \
	--product hysteria2 --relay "$hy_relay":8443 --control "$hy_control":8443 \
	--server-name cover.test --ca /run/stealth/server.crt \
	--isolated-lab --allow-net "$lab_cidr" \
	--iterations "$iterations" --seed 20260904 $release_arg \
	--output /artifacts/hysteria2-active.jsonl >"$artifact_dir/hysteria2-active-summary.json" 2>"$artifact_dir/hysteria2-active.stderr.log"
hy_active_exit=$?
set -e
hy_active_status=insufficient_evidence
hy_active_observed_status=missing
if [ -f "$artifact_dir/hysteria2-active.jsonl" ]; then
	hy_summary_line=$(sed -n '$p' "$artifact_dir/hysteria2-active.jsonl")
	case "$hy_summary_line" in
		*'"type":"summary"'*'"product":"hysteria2"'*)
			parsed_hy_status=$(printf '%s\n' "$hy_summary_line" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
			hy_active_observed_status=$parsed_hy_status
			case "$parsed_hy_status:$hy_active_exit" in
				pass:0) hy_active_status=pass ;;
				fail:1) hy_active_status=insufficient_evidence ;;
				*) echo "Hysteria active comparator status/exit mismatch: $parsed_hy_status/$hy_active_exit" >&2 ;;
			esac
			;;
		*) echo "Hysteria active comparator did not produce a complete summary" >&2 ;;
	esac
else
	echo "Hysteria active comparator did not write JSONL evidence" >&2
fi

run_detached "$hy_edge" "$lab_image" gateway --listen :9443 --backend "$hy_relay":8443 --control :9090 --udp-enabled=true
wait_http http://"$hy_edge":9090/state
run_detached "$hy_client_ok" \
	--user "$host_user" --entrypoint /hysteria \
	-v "$tmp:/run/stealth:ro" -v "$hy_bin:/hysteria:ro" \
	"$lab_image" client --disable-update-check -c /run/stealth/hysteria-client.yaml
if ! wait_proxy_fetch "http://$hy_client_ok:8080" "http://$origin:8080/healthy" 80; then
	echo "pinned Hysteria healthy-path control did not become usable" >&2
	exit 1
fi

cleanup_container "$hy_client_ok"
$docker_bin run --rm --network "$network" "$lab_image" gateway-control --url http://"$hy_edge":9090 --action disable \
	>"$artifact_dir/hysteria2-blackhole-gateway.json"
run_detached "$hy_client_blocked" \
	--user "$host_user" --entrypoint /hysteria \
	-v "$tmp:/run/stealth:ro" -v "$hy_bin:/hysteria:ro" \
	"$lab_image" client --disable-update-check -c /run/stealth/hysteria-client.yaml
sleep 0.5
set +e
$docker_bin run --rm --network "$network" "$lab_image" fetch \
	--proxy "http://$hy_client_blocked:8080" --url "http://$origin:8080/blackhole" --timeout 4s \
	>"$artifact_dir/hysteria2-blackhole-fetch.stdout.log" 2>"$artifact_dir/hysteria2-blackhole-fetch.stderr.log"
hy_blackhole_exit=$?
set -e
if [ "$hy_blackhole_exit" -eq 0 ]; then
	echo "Hysteria unexpectedly carried a new proxied flow while all gateway UDP was blackholed" >&2
	exit 1
fi
$docker_bin run --rm --network "$network" "$lab_image" gateway-control --url http://"$hy_edge":9090 --action state \
	>"$artifact_dir/hysteria2-blackhole-gateway-after.json"
hy_tcp_attempts=$(sed -n 's/.*"tcp_accepted":\([0-9][0-9]*\).*/\1/p' "$artifact_dir/hysteria2-blackhole-gateway-after.json")
hy_udp_drops=$(sed -n 's/.*"udp_dropped":\([0-9][0-9]*\).*/\1/p' "$artifact_dir/hysteria2-blackhole-gateway-after.json")
if [ "${hy_tcp_attempts:-invalid}" != 0 ] || [ "${hy_udp_drops:-0}" -le 0 ]; then
	echo "Hysteria blackhole evidence did not show UDP-only client behavior" >&2
	exit 1
fi

# Prove that the same blackholed gateway still carries ordinary H1/H2 cover
# traffic. This is a standards compatibility check inside the private lab.
$docker_bin run --rm --network "$network" --user "$host_user" \
	-v "$tmp:/run/stealth:ro" -v "$artifact_dir:/artifacts" \
	"$lab_image" active \
	--product hysteria2 --relay "$hy_edge":9443 --control "$hy_control":8443 \
	--server-name cover.test --ca /run/stealth/server.crt --isolated-lab --allow-net "$lab_cidr" \
	--protocols h1,h2 --iterations 1 --seed 20260904 \
	--output /artifacts/hysteria2-blackhole-cover.jsonl >"$artifact_dir/hysteria2-blackhole-cover-summary.json"
hysteria_cover_summary_line=$(sed -n '$p' "$artifact_dir/hysteria2-blackhole-cover.jsonl")
hysteria_cover_status=$(printf '%s\n' "$hysteria_cover_summary_line" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
if [ "$hysteria_cover_status" != pass ]; then
	echo "Hysteria TCP cover probe did not produce a passing summary" >&2
	exit 1
fi

gecko_status=insufficient_evidence
if [ "$run_gecko" -eq 1 ]; then
	obfs_password="gecko-$hy_password"
	scripts/stealth-hysteria.sh server-config "$tmp/gecko-server.yaml" \
		/run/stealth/server.crt /run/stealth/server.key "$hy_password" "http://$origin:8080" gecko "$obfs_password"
	scripts/stealth-hysteria.sh client-config "$tmp/gecko-client.yaml" \
		"$gecko_relay:8443" cover.test /run/stealth/server.crt "$hy_password" :8080 gecko "$obfs_password"
	run_detached "$gecko_relay" \
		--user "$host_user" --entrypoint /hysteria \
		-v "$tmp:/run/stealth:ro" -v "$hy_bin:/hysteria:ro" \
		"$lab_image" server --disable-update-check -c /run/stealth/gecko-server.yaml
	wait_log "$gecko_relay" 'server up and running'
	run_detached "$gecko_client" \
		--user "$host_user" --entrypoint /hysteria \
		-v "$tmp:/run/stealth:ro" -v "$hy_bin:/hysteria:ro" \
		"$lab_image" client --disable-update-check -c /run/stealth/gecko-client.yaml
	if wait_proxy_fetch "http://$gecko_client:8080" "http://$origin:8080/gecko" 80; then
		gecko_status=pass
	else
		gecko_status=insufficient_evidence
	fi
fi

git_head_end=$(git rev-parse --verify HEAD)
git_tree_end=$(git rev-parse "${git_head_end}^{tree}")
worktree_state_end=$(git status --porcelain=v1 --untracked-files=all)
worktree_clean_end=true
if [ -n "$worktree_state_end" ]; then worktree_clean_end=false; fi
source_state_unchanged=false
if [ "$git_head_start" = "$git_head_end" ] && [ "$git_tree_start" = "$git_tree_end" ] && [ "$worktree_state_start" = "$worktree_state_end" ]; then
	source_state_unchanged=true
fi

harness_status=pass
evidence_status=pass
if [ "$hy_active_status" != pass ] || [ "$gecko_status" != pass ]; then
	evidence_status=insufficient_evidence
fi
if [ "$source_state_unchanged" != true ] || { [ "$release_gate" -eq 1 ] && [ "$worktree_clean_end" != true ]; }; then
	harness_status=fail
	evidence_status=fail
fi
release_evidence_complete=false
if [ "$release_gate" -eq 1 ] && [ "$iterations" -ge 100 ] && [ "$worktree_clean_start" = true ] && \
	[ "$worktree_clean_end" = true ] && [ "$source_state_unchanged" = true ] && [ "$evidence_status" = pass ]; then
	release_evidence_complete=true
fi

autocar_image_id=$($docker_bin image inspect --format '{{.Id}}' "$autocar_image")
lab_image_id=$($docker_bin image inspect --format '{{.Id}}' "$lab_image")
cat >"$artifact_dir/manifest.json" <<EOF
{
  "schema_version": 3,
  "status": "$evidence_status",
  "harness_status": "$harness_status",
  "scope": "active_probe_and_userspace_udp_blackhole",
  "run_role": "$run_role",
  "execution_host": "$execution_host",
  "execution_host_ssh_key_ed25519_sha256": "$execution_host_ssh_key_sha256",
  "host_os": "$(uname -s)",
  "host_architecture": "$(uname -m)",
  "autocar_commit": "$git_head_start",
  "autocar_commit_start": "$git_head_start",
  "autocar_commit_end": "$git_head_end",
  "autocar_tree_start": "$git_tree_start",
  "autocar_tree_end": "$git_tree_end",
  "build_context_source": "$build_context_source",
  "autocar_image": "$autocar_image_id",
  "lab_image": "$lab_image_id",
  "docker_network_internal": true,
  "docker_network_allow_cidr": "$lab_cidr",
  "docker_engine_fingerprint": "$docker_engine_fingerprint",
  "hysteria2_version": "v2.12.2",
  "hysteria2_active_probe_exit": $hy_active_exit,
  "hysteria2_active_probe_status": "$hy_active_status",
  "hysteria2_active_probe_observed_status": "$hy_active_observed_status",
  "hysteria2_healthy_path": "pass",
  "hysteria2_udp_blackhole_new_flow": "pass",
  "hysteria2_tcp_cover": "$hysteria_cover_status",
  "hysteria2_gecko": "$gecko_status",
  "autocar_active": "$autocar_active_status",
  "autocar_transition": "$autocar_transition_status",
  "iterations": $iterations,
  "release_gate": $release_gate,
  "release_evidence_complete": $release_evidence_complete,
  "worktree_clean": $worktree_clean_start,
  "worktree_clean_start": $worktree_clean_start,
  "worktree_clean_end": $worktree_clean_end,
  "source_state_unchanged": $source_state_unchanged,
  "host_firewall_or_qdisc_modified": false,
  "secrets_in_artifacts": false
}
EOF

case "$evidence_status" in
	pass)
	echo "stealth active suite passed; evidence: $artifact_dir"
	;;
	insufficient_evidence)
	echo "stealth active suite has insufficient comparator evidence: $artifact_dir" >&2
	exit 2
	;;
	*)
	echo "stealth active suite failed: $artifact_dir" >&2
	exit 1
	;;
esac
