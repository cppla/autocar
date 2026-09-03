#!/bin/sh
set -eu

docker_bin=${DOCKER_BIN:-docker}
integration_tmp=""

early_cleanup() {
	early_status=$?
	trap - EXIT HUP INT TERM
	case "$integration_tmp" in
		*/autocar-docker-integration.*) rm -rf -- "$integration_tmp" ;;
		"") ;;
		*) echo "refusing to remove unexpected temporary path: $integration_tmp" >&2 ;;
	esac
	exit "$early_status"
}
trap early_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

integration_tmp=$(mktemp -d "${TMPDIR:-/tmp}/autocar-docker-integration.XXXXXX")
integration_suffix="${integration_tmp##*.}-$$-$(date +%s)"
integration_image_base=${AUTOCAR_INTEGRATION_IMAGE:-autocar:integration}
case "${integration_image_base##*/}" in
	*:*) integration_image_tag="${integration_image_base}-${integration_suffix}" ;;
	*) integration_image_tag="${integration_image_base}:integration-${integration_suffix}" ;;
esac
integration_image_id=""
integration_label_key="com.cppla.autocar.integration.run"
integration_label="${integration_label_key}=${integration_suffix}"
integration_network="autocar-integration-${integration_suffix}"
integration_network_id=""
relay_volume="autocar-integration-relay-secrets-${integration_suffix}"
valid_client_volume="autocar-integration-valid-client-${integration_suffix}"
invalid_client_volume="autocar-integration-invalid-client-${integration_suffix}"
target_container="autocar-integration-target-${integration_suffix}"
relay_container="autocar-integration-relay-${integration_suffix}"
volume_init_container="autocar-integration-volume-init-${integration_suffix}"
cert_container="autocar-integration-cert-${integration_suffix}"
token_container="autocar-integration-token-${integration_suffix}"
wrong_token_container="autocar-integration-wrong-token-${integration_suffix}"
credential_copy_container="autocar-integration-credential-copy-${integration_suffix}"
benchmark_container="autocar-integration-benchmark-${integration_suffix}"
doctor_container="autocar-integration-doctor-${integration_suffix}"
auth_quic_container="autocar-integration-auth-quic-${integration_suffix}"
auth_tls_container="autocar-integration-auth-tls-${integration_suffix}"
target_container_id=""
relay_container_id=""
integration_passed=0
docker_cleanup_armed=0
docker_cleanup_timeout=${AUTOCAR_DOCKER_CLEANUP_TIMEOUT:-5}
alpine_image="alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

case "$docker_cleanup_timeout" in
	""|*[!0-9]*|0)
		echo "AUTOCAR_DOCKER_CLEANUP_TIMEOUT must be a positive integer number of seconds" >&2
		exit 2
		;;
esac

# Linux CI and production-like test hosts provide GNU timeout. macOS does not
# ship it, so local cleanup falls back to the Docker CLI's own cancellation;
# the CI job still has a hard workflow timeout in either case.
cleanup_timeout_bin=""
if command -v timeout >/dev/null 2>&1; then
	cleanup_timeout_bin=timeout
elif command -v gtimeout >/dev/null 2>&1; then
	cleanup_timeout_bin=gtimeout
fi

cleanup_docker() {
	if [ -n "$cleanup_timeout_bin" ]; then
		"$cleanup_timeout_bin" -k 2 "$docker_cleanup_timeout" "$docker_bin" "$@"
	else
		"$docker_bin" "$@"
	fi
}

container_ref() {
	container_id=$1
	container_name=$2
	for container_candidate in "$container_id" "$container_name"; do
		[ -n "$container_candidate" ] || continue
		container_label=$(cleanup_docker container inspect \
			--format '{{ index .Config.Labels "com.cppla.autocar.integration.run" }}' \
			"$container_candidate" 2>/dev/null) || continue
		if [ "$container_label" = "$integration_suffix" ]; then
			printf '%s\n' "$container_candidate"
			return 0
		fi
	done
	return 1
}

inspect_run_label() {
	inspect_kind=$1
	inspect_ref=$2
	case "$inspect_kind" in
		container|image) inspect_format='{{ index .Config.Labels "com.cppla.autocar.integration.run" }}' ;;
		network|volume) inspect_format='{{ index .Labels "com.cppla.autocar.integration.run" }}' ;;
		*) return 2 ;;
	esac
	cleanup_docker "$inspect_kind" inspect --format "$inspect_format" "$inspect_ref" 2>/dev/null
}

list_named_resource() {
	list_kind=$1
	list_ref=$2
	case "$list_kind" in
		container) cleanup_docker container ls -aq --filter "name=^${list_ref}$" ;;
		network) cleanup_docker network ls -q --filter "name=^${list_ref}$" ;;
		volume) cleanup_docker volume ls -q --filter "name=^${list_ref}$" ;;
		image) cleanup_docker image ls -q --filter "reference=${list_ref}" ;;
		*) return 2 ;;
	esac
}

cleanup_owned_resource() {
	cleanup_kind=$1
	cleanup_ref=$2
	cleanup_ids=$(list_named_resource "$cleanup_kind" "$cleanup_ref") || return 2
	[ -z "$cleanup_ids" ] && return 0
	cleanup_label=$(inspect_run_label "$cleanup_kind" "$cleanup_ref") || return 2
	if [ "$cleanup_label" != "$integration_suffix" ]; then
		echo "refusing to remove ${cleanup_kind} with mismatched integration label: ${cleanup_ref}" >&2
		return 3
	fi
	cleanup_sweep_removed=1
	case "$cleanup_kind" in
		container) cleanup_docker container rm -f "$cleanup_ref" >/dev/null 2>&1 ;;
		network) cleanup_docker network rm "$cleanup_ref" >/dev/null 2>&1 ;;
		volume) cleanup_docker volume rm "$cleanup_ref" >/dev/null 2>&1 ;;
		# Remove only this invocation's tag. Never force-delete an image another
		# actor may have tagged or started using on a shared daemon.
		image) cleanup_docker image rm "$cleanup_ref" >/dev/null 2>&1 ;;
	esac
}

assert_owned_resource_absent() {
	check_kind=$1
	check_ref=$2
	check_ids=$(list_named_resource "$check_kind" "$check_ref") || return 2
	[ -z "$check_ids" ] && return 0
	check_label=$(inspect_run_label "$check_kind" "$check_ref") || return 2
	if [ "$check_label" != "$integration_suffix" ]; then
		echo "integration name was replaced by a differently labeled ${check_kind}: ${check_ref}" >&2
		return 3
	fi
	return 1
}

docker_cleanup_sweep() {
	cleanup_docker info >/dev/null 2>&1 || return 2
	cleanup_sweep_removed=0
	cleanup_sweep_failed=0
	for cleanup_ref in \
		"$target_container" \
		"$relay_container" \
		"$volume_init_container" \
		"$cert_container" \
		"$token_container" \
		"$wrong_token_container" \
		"$credential_copy_container" \
		"$benchmark_container" \
		"$doctor_container" \
		"$auth_quic_container" \
		"$auth_tls_container"; do
		cleanup_owned_resource container "$cleanup_ref" || cleanup_sweep_failed=1
	done
	cleanup_owned_resource network "$integration_network" || cleanup_sweep_failed=1
	cleanup_owned_resource volume "$relay_volume" || cleanup_sweep_failed=1
	cleanup_owned_resource volume "$valid_client_volume" || cleanup_sweep_failed=1
	cleanup_owned_resource volume "$invalid_client_volume" || cleanup_sweep_failed=1
	cleanup_owned_resource image "$integration_image_tag" || cleanup_sweep_failed=1
	[ "$cleanup_sweep_failed" -eq 0 ]
}

docker_cleanup_empty() {
	cleanup_docker info >/dev/null 2>&1 || return 2
	cleanup_empty=1
	for cleanup_ref in \
		"$target_container" \
		"$relay_container" \
		"$volume_init_container" \
		"$cert_container" \
		"$token_container" \
		"$wrong_token_container" \
		"$credential_copy_container" \
		"$benchmark_container" \
		"$doctor_container" \
		"$auth_quic_container" \
		"$auth_tls_container"; do
		assert_owned_resource_absent container "$cleanup_ref" || cleanup_empty=0
	done
	assert_owned_resource_absent network "$integration_network" || cleanup_empty=0
	assert_owned_resource_absent volume "$relay_volume" || cleanup_empty=0
	assert_owned_resource_absent volume "$valid_client_volume" || cleanup_empty=0
	assert_owned_resource_absent volume "$invalid_client_volume" || cleanup_empty=0
	assert_owned_resource_absent image "$integration_image_tag" || cleanup_empty=0
	[ "$cleanup_empty" -eq 1 ]
}

cleanup() {
	cleanup_status=$?
	trap - EXIT
	# Preserve the first exit status and give the short cleanup window a chance
	# to finish if an interactive or CI cancellation sends a second signal. A
	# caught signal resets to the default across exec, unlike an ignored signal,
	# so cleanup subprocesses remain independently terminable.
	trap ':' HUP INT TERM
	cleanup_failed=0

	if [ "$docker_cleanup_armed" -eq 1 ] && { [ "$cleanup_status" -ne 0 ] || [ "$integration_passed" -ne 1 ]; }; then
		for diagnostic_pair in "$relay_container_id:$relay_container" "$target_container_id:$target_container"; do
			diagnostic_id=${diagnostic_pair%%:*}
			diagnostic_name=${diagnostic_pair#*:}
			if diagnostic_ref=$(container_ref "$diagnostic_id" "$diagnostic_name"); then
				echo "logs from container ${diagnostic_name}:" >&2
				cleanup_docker logs "$diagnostic_ref" >&2 || true
			fi
		done
	fi

	if [ "$docker_cleanup_armed" -eq 1 ]; then
		# A canceled create/start/build can briefly finish daemon-side. Sweep only
		# the exact reserved names whose labels still prove ownership, and require
		# them to remain absent for three full seconds. A late object resets the
		# quiet window.
		cleanup_attempt=0
		cleanup_clean_streak=0
		cleanup_verified=0
		while [ "$cleanup_attempt" -lt 12 ]; do
			if docker_cleanup_sweep && docker_cleanup_empty; then
				if [ "$cleanup_sweep_removed" -eq 1 ]; then
					# This empty observation begins a new quiet window after the
					# latest object was removed; earlier observations no longer count.
					cleanup_clean_streak=1
				else
					cleanup_clean_streak=$((cleanup_clean_streak + 1))
				fi
				if [ "$cleanup_clean_streak" -ge 4 ]; then
					cleanup_verified=1
					break
				fi
			else
				cleanup_clean_streak=0
			fi
			cleanup_attempt=$((cleanup_attempt + 1))
			if [ "$cleanup_attempt" -lt 12 ]; then
				if ! sleep 1; then
					cleanup_failed=1
					cleanup_clean_streak=0
				fi
			fi
		done
		if [ "$cleanup_verified" -ne 1 ]; then
			echo "unable to verify removal of all Docker resources for integration run $integration_suffix" >&2
			cleanup_failed=1
		fi
	fi

	case "$integration_tmp" in
		*/autocar-docker-integration.*)
			if ! rm -rf -- "$integration_tmp"; then
				echo "failed to remove integration temporary directory: $integration_tmp" >&2
				cleanup_failed=1
			fi
			;;
		*)
			echo "refusing to remove unexpected temporary path: $integration_tmp" >&2
			cleanup_failed=1
			;;
	esac

	if [ "$integration_passed" -ne 1 ] && [ "$cleanup_status" -eq 0 ]; then
		cleanup_status=1
	fi
	if [ "$cleanup_failed" -ne 0 ] && [ "$cleanup_status" -eq 0 ]; then
		cleanup_status=1
	fi
	exit "$cleanup_status"
}
trap cleanup EXIT

assert_name_available() {
	resource_type=$1
	resource_name=$2
	if "$docker_bin" "$resource_type" inspect "$resource_name" >/dev/null 2>&1; then
		echo "integration resource name already exists: ${resource_type} ${resource_name}" >&2
		exit 1
	fi
}

create_secret_volume() {
	secret_volume=$1
	"$docker_bin" volume create --label "$integration_label" "$secret_volume" >/dev/null
	secret_volume_label=$("$docker_bin" volume inspect \
		--format '{{ index .Labels "com.cppla.autocar.integration.run" }}' \
		"$secret_volume")
	if [ "$secret_volume_label" != "$integration_suffix" ]; then
		echo "integration secret volume label mismatch: $secret_volume" >&2
		exit 1
	fi
}

assert_services_running() {
	for service_container_id in "$relay_container_id" "$target_container_id"; do
		if [ -z "$service_container_id" ] || ! "$docker_bin" inspect --format '{{.State.Running}}' "$service_container_id" | grep -qx true; then
			echo "integration service stopped: ${service_container_id:-missing container ID}" >&2
			return 1
		fi
	done
}

run_benchmark() {
	expected_transport=$1
	shift
	if benchmark_output=$("$docker_bin" run --rm \
		--name "$benchmark_container" \
		--label "$integration_label" \
		--network "$integration_network_id" \
		--read-only \
		--cap-drop=ALL \
		--security-opt no-new-privileges:true \
		--mount "type=volume,src=${valid_client_volume},dst=/run/autocar,readonly" \
		"$integration_image_id" bench-client \
		--server-name=relay \
		--ca=/run/autocar/server.crt \
		--token-file=/run/autocar/relay-token \
		--target=target:9000 \
		--bytes=1048576 \
		--iterations=1 \
		--warmup=0 \
		--timeout=20s \
		--json \
		"$@"); then
		:
	else
		benchmark_status=$?
		printf '%s\n' "$benchmark_output" >&2
		return "$benchmark_status"
	fi
	printf '%s\n' "$benchmark_output"
	if ! printf '%s\n' "$benchmark_output" | grep -q "\"selected_transport\": \"${expected_transport}\""; then
		echo "benchmark selected an unexpected transport; expected ${expected_transport}" >&2
		return 1
	fi
}

expect_auth_rejected() {
	rejected_transport=$1
	rejected_server=$2
	rejected_log="${integration_tmp}/wrong-token-${rejected_transport}.log"
	case "$rejected_transport" in
		quic) rejected_container=$auth_quic_container ;;
		tls) rejected_container=$auth_tls_container ;;
		*) echo "unsupported rejected transport: $rejected_transport" >&2; return 1 ;;
	esac
	if "$docker_bin" run --rm \
		--name "$rejected_container" \
		--label "$integration_label" \
		--network "$integration_network_id" \
		--read-only \
		--cap-drop=ALL \
		--security-opt no-new-privileges:true \
		--mount "type=volume,src=${invalid_client_volume},dst=/run/autocar,readonly" \
		"$integration_image_id" bench-client \
		--transport="$rejected_transport" \
		--server="$rejected_server" \
		--server-name=relay \
		--ca=/run/autocar/server.crt \
		--token-file=/run/autocar/wrong-token \
		--target=target:9000 \
		--bytes=1 \
		--iterations=1 \
		--warmup=0 \
		--timeout=5s >"$rejected_log" 2>&1; then
		echo "relay accepted an invalid token over ${rejected_transport}" >&2
		sed -n '1,120p' "$rejected_log" >&2
		return 1
	fi
	if ! grep -Eq 'authentication failed.*status 2' "$rejected_log"; then
		echo "invalid-token ${rejected_transport} probe failed for an unexpected reason:" >&2
		sed -n '1,120p' "$rejected_log" >&2
		return 1
	fi
}

assert_name_available image "$integration_image_tag"
assert_name_available network "$integration_network"
assert_name_available volume "$relay_volume"
assert_name_available volume "$valid_client_volume"
assert_name_available volume "$invalid_client_volume"
for reserved_container in \
	"$target_container" \
	"$relay_container" \
	"$volume_init_container" \
	"$cert_container" \
	"$token_container" \
	"$wrong_token_container" \
	"$credential_copy_container" \
	"$benchmark_container" \
	"$doctor_container" \
	"$auth_quic_container" \
	"$auth_tls_container"; do
	assert_name_available container "$reserved_container"
done

# From this point onward every Docker object carries the unique run label and
# belongs to this invocation. Earlier assertion failures must never clean a
# pre-existing object that merely collided with a reserved name.
docker_cleanup_armed=1

echo "building ${integration_image_tag}"
"$docker_bin" build \
	--label "$integration_label" \
	--build-arg VERSION=integration \
	--build-arg COMMIT=local \
	--build-arg BUILD_DATE=unknown \
	-t "$integration_image_tag" .
integration_image_id=$("$docker_bin" image inspect --format '{{.Id}}' "$integration_image_tag")
if [ -z "$integration_image_id" ]; then
	echo "built integration image has no image ID" >&2
	exit 1
fi

image_user=$("$docker_bin" image inspect --format '{{.Config.User}}' "$integration_image_id")
if [ "$image_user" != "65532:65532" ]; then
	echo "unexpected runtime image user: ${image_user}" >&2
	exit 1
fi

create_secret_volume "$relay_volume"
create_secret_volume "$valid_client_volume"
create_secret_volume "$invalid_client_volume"

"$docker_bin" run --rm \
	--name "$volume_init_container" \
	--label "$integration_label" \
	--network none \
	--read-only \
	--cap-drop=ALL \
	--cap-add=CHOWN \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${relay_volume},dst=/run/relay" \
	--mount "type=volume,src=${valid_client_volume},dst=/run/valid-client" \
	--mount "type=volume,src=${invalid_client_volume},dst=/run/invalid-client" \
	"$alpine_image" /bin/sh -eu -c '
		for directory in /run/relay /run/valid-client /run/invalid-client; do
			chmod 0700 "$directory"
			chown 65532:65532 "$directory"
		done
	'

"$docker_bin" run --rm \
	--name "$cert_container" \
	--label "$integration_label" \
	--network none \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${relay_volume},dst=/run/autocar" \
	"$integration_image_id" cert \
	--hosts=relay \
	--cert=/run/autocar/server.crt \
	--key=/run/autocar/server.key
"$docker_bin" run --rm \
	--name "$token_container" \
	--label "$integration_label" \
	--network none \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${relay_volume},dst=/run/autocar" \
	"$integration_image_id" token \
	--out=/run/autocar/relay-token
"$docker_bin" run --rm \
	--name "$wrong_token_container" \
	--label "$integration_label" \
	--network none \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${invalid_client_volume},dst=/run/autocar" \
	"$integration_image_id" token \
	--out=/run/autocar/wrong-token

"$docker_bin" run --rm \
	--name "$credential_copy_container" \
	--label "$integration_label" \
	--user 65532:65532 \
	--network none \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${relay_volume},dst=/run/relay,readonly" \
	--mount "type=volume,src=${valid_client_volume},dst=/run/valid-client" \
	--mount "type=volume,src=${invalid_client_volume},dst=/run/invalid-client" \
	"$alpine_image" /bin/sh -eu -c '
		cp /run/relay/server.crt /run/valid-client/server.crt
		cp /run/relay/relay-token /run/valid-client/relay-token
		cp /run/relay/server.crt /run/invalid-client/server.crt
		chmod 0600 /run/valid-client/server.crt /run/valid-client/relay-token
		chmod 0600 /run/invalid-client/server.crt /run/invalid-client/wrong-token
		test -r /run/relay/server.key
		test ! -e /run/relay/wrong-token
		test ! -e /run/valid-client/server.key
		test ! -e /run/valid-client/wrong-token
		test ! -e /run/invalid-client/server.key
		test ! -e /run/invalid-client/relay-token
	'

integration_network_id=$("$docker_bin" network create --label "$integration_label" "$integration_network")
network_label=$("$docker_bin" network inspect \
	--format '{{ index .Labels "com.cppla.autocar.integration.run" }}' \
	"$integration_network_id")
if [ "$network_label" != "$integration_suffix" ]; then
	echo "integration network label mismatch" >&2
	exit 1
fi

target_container_id=$("$docker_bin" run -d \
	--name "$target_container" \
	--label "$integration_label" \
	--network "$integration_network_id" \
	--network-alias target \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	"$integration_image_id" bench-server \
	--listen=:9000 \
	--allow-public-benchmark \
	--max-bytes=2097152 \
	--max-connections=4)

relay_container_id=$("$docker_bin" run -d \
	--name "$relay_container" \
	--label "$integration_label" \
	--network "$integration_network_id" \
	--network-alias relay \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${relay_volume},dst=/run/autocar,readonly" \
	"$integration_image_id" server \
	--listen=:8443 \
	--tcp-listen=:8443 \
	--cert=/run/autocar/server.crt \
	--key=/run/autocar/server.key \
	--token-file=/run/autocar/relay-token \
	--allow-private \
	--max-streams=8 \
	--max-connections=4 \
	--max-client-connections=4)

attempt=0
until run_benchmark quic --transport=quic --server=relay:8443; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 20 ]; then
		echo "QUIC integration did not become ready" >&2
		exit 1
	fi
	sleep 1
done

run_benchmark tls --transport=tls --server=relay:8443
run_benchmark quic --transport=auto --server=relay:8443
run_benchmark tls \
	--transport=auto \
	--server=relay:9443 \
	--fallback-server=relay:8443 \
	--dial-timeout=1s \
	--quic-attempt-timeout=750ms \
	--open-timeout=5s \
	--fallback-cooldown=1s

if doctor_output=$("$docker_bin" run --rm \
	--name "$doctor_container" \
	--label "$integration_label" \
	--network "$integration_network_id" \
	--read-only \
	--cap-drop=ALL \
	--security-opt no-new-privileges:true \
	--mount "type=volume,src=${valid_client_volume},dst=/run/autocar,readonly" \
	"$integration_image_id" doctor \
	--transport=auto \
	--server=relay:9443 \
	--fallback-server=relay:8443 \
	--server-name=relay \
	--ca=/run/autocar/server.crt \
	--token-file=/run/autocar/relay-token \
	--target=target:9000 \
	--dial-timeout=1s \
	--quic-attempt-timeout=750ms \
	--open-timeout=5s \
	--fallback-cooldown=1s \
	--json); then
	:
else
	doctor_status=$?
	printf '%s\n' "$doctor_output" >&2
	exit "$doctor_status"
fi
printf '%s\n' "$doctor_output"
printf '%s\n' "$doctor_output" | grep -q '"status": "ok"'
printf '%s\n' "$doctor_output" | grep -q '"selected_transport": "tls"'
printf '%s\n' "$doctor_output" | grep -q '"kind": "transport_fallback"'

assert_services_running
expect_auth_rejected quic relay:8443
expect_auth_rejected tls relay:8443
assert_services_running

integration_passed=1
echo "docker integration passed: QUIC, TLS, auto fallback, doctor, token rejection, non-root read-only containers"
