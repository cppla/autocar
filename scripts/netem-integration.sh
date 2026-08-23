#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

# Artifacts contain diagnostics, not credentials, and must remain readable by
# the non-root GitHub Actions runner after this privileged suite exits. Secrets
# stay under mktemp's mode-0700 work directory.
umask 022

# Reproducible functional and security smoke test for Linux. This script uses
# network namespaces and tc netem, so it intentionally requires root.

if [[ ${EUID} -ne 0 ]]; then
  echo "error: run this script as root (for example, sudo $0 ./bin/autocar)" >&2
  exit 1
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/autocar" >&2
  exit 1
fi

for command in ip tc ethtool iptables tcpdump curl python3 grep readlink awk; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: required command not found: ${command}" >&2
    exit 1
  fi
done

AUTOCAR_BIN=$(readlink -f "$1")
if [[ ! -x ${AUTOCAR_BIN} ]]; then
  echo "error: not an executable file: ${AUTOCAR_BIN}" >&2
  exit 1
fi

ARTIFACT_DIR=${AUTOCAR_ARTIFACT_DIR:-artifacts/netem}
mkdir -p "${ARTIFACT_DIR}"
ARTIFACT_DIR=$(readlink -f "${ARTIFACT_DIR}")
if [[ ${ARTIFACT_DIR} == / ]]; then
  echo "error: refusing to use the filesystem root as AUTOCAR_ARTIFACT_DIR" >&2
  exit 1
fi
IPTABLES_VERSION=$(iptables --version)
printf '%s\n' "${IPTABLES_VERSION}" >"${ARTIFACT_DIR}/iptables-version.txt"
if [[ ${IPTABLES_VERSION} != *"(nf_tables)"* ]]; then
  echo "error: this regression suite requires the nft-backed iptables frontend" >&2
  exit 1
fi

RUN_ID=$$
CLIENT_NS="autocar-client-${RUN_ID}"
SERVER_NS="autocar-server-${RUN_ID}"
CLIENT_DEV="acc${RUN_ID}"
SERVER_DEV="acs${RUN_ID}"
CLIENT_IP=10.203.0.1
SERVER_IP=10.203.0.2
RELAY_PORT=7443
ADAPTIVE_RELAY_PORT=7445
RENO_RELAY_PORT=7446
UNUSED_QUIC_PORT=7444
BENCH_PORT=9000
ORIGIN_PORT=9080
PROXY_PORT=18080

DELAY_MS=${AUTOCAR_NETEM_DELAY_MS:-35}
LOSS=${AUTOCAR_NETEM_LOSS:-0.5%}
RATE=${AUTOCAR_NETEM_RATE:-50mbit}
BENCH_BYTES=${AUTOCAR_BENCH_BYTES:-1048576}
BENCH_ITERATIONS=${AUTOCAR_BENCH_ITERATIONS:-5}
BENCH_WARMUP=${AUTOCAR_BENCH_WARMUP:-1}
PACING_DROP_EVERY=${AUTOCAR_PACING_DROP_EVERY:-200}
PACING_BYTES=${AUTOCAR_PACING_BYTES:-1048576}
PACING_ITERATIONS=${AUTOCAR_PACING_ITERATIONS:-3}
PACING_WARMUP=${AUTOCAR_PACING_WARMUP:-1}
FIXED_ACCURACY_BYTES=${AUTOCAR_FIXED_ACCURACY_BYTES:-4194304}
FIXED_ACCURACY_ITERATIONS=${AUTOCAR_FIXED_ACCURACY_ITERATIONS:-3}
FIXED_ACCURACY_WARMUP=${AUTOCAR_FIXED_ACCURACY_WARMUP:-1}
SHORT_FLOW_BYTES=${AUTOCAR_SHORT_FLOW_BYTES:-131072}
SHORT_FLOW_ITERATIONS=${AUTOCAR_SHORT_FLOW_ITERATIONS:-9}
SHORT_FLOW_WARMUP=${AUTOCAR_SHORT_FLOW_WARMUP:-3}
FIXED_RATE_MIN_RATIO=${AUTOCAR_FIXED_RATE_MIN_RATIO:-0.82}
FIXED_RATE_MAX_RATIO=${AUTOCAR_FIXED_RATE_MAX_RATIO:-1.08}
FIXED_RATE_SERVER_UPLOAD_MBPS=11
FIXED_RATE_SERVER_DOWNLOAD_MBPS=17
FIXED_RATE_CLIENT_UPLOAD_MBPS=19
FIXED_RATE_CLIENT_DOWNLOAD_MBPS=13
FIXED_RATE_EXPECTED_UPLOAD_BYTES_SEC=1375000
FIXED_RATE_EXPECTED_DOWNLOAD_BYTES_SEC=1625000
PACING_LOSS_CHAIN=AUTOCAR_PACING_LOSS

if ! [[ ${PACING_DROP_EVERY} =~ ^[0-9]+$ ]] || \
   (( PACING_DROP_EVERY < 2 )); then
  echo "error: AUTOCAR_PACING_DROP_EVERY must be an integer of at least 2" >&2
  exit 1
fi
PACING_INITIAL_PACKET=$((PACING_DROP_EVERY - 1))
WORK_DIR=$(mktemp -d -t autocar-netem.XXXXXX)

PIDS=()

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" >/dev/null 2>&1 || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "${pid}" >/dev/null 2>&1 || true
  done

  for namespace in "${CLIENT_NS}" "${SERVER_NS}"; do
    if ip netns list | grep -Fq "${namespace}"; then
      while read -r pid; do
        [[ -n ${pid} ]] && kill "${pid}" >/dev/null 2>&1 || true
      done < <(ip netns pids "${namespace}" 2>/dev/null || true)
      ip netns delete "${namespace}" >/dev/null 2>&1 || true
    fi
  done

  rm -rf "${WORK_DIR}"

  if [[ ${status} -ne 0 ]]; then
    echo "netem integration failed; recent logs:" >&2
    for log in "${ARTIFACT_DIR}"/*.log; do
      [[ -f ${log} ]] || continue
      echo "--- ${log}" >&2
      tail -n 40 "${log}" >&2 || true
    done
  fi
  return "${status}"
}
trap cleanup EXIT INT TERM

start_background() {
  local log=$1
  shift
  "$@" >"${log}" 2>&1 &
  STARTED_PID=$!
  PIDS+=("${STARTED_PID}")
}

wait_for_log() {
  local pid=$1
  local log=$2
  local pattern=$3
  local attempts=100
  while (( attempts > 0 )); do
    if grep -Fq "${pattern}" "${log}" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      echo "error: process ${pid} exited before logging ${pattern}" >&2
      return 1
    fi
    sleep 0.1
    attempts=$((attempts - 1))
  done
  echo "error: timed out waiting for ${pattern} in ${log}" >&2
  return 1
}

run_client() {
  ip netns exec "${CLIENT_NS}" "${AUTOCAR_BIN}" bench-client "$@"
}

# Disabling UDP GSO for pacing-mode senders makes one statistic-matcher
# packet correspond to one QUIC datagram instead of a host-dependent GSO batch.
run_pacing_client() {
  ip netns exec "${CLIENT_NS}" env QUIC_GO_DISABLE_GSO=true \
    "${AUTOCAR_BIN}" bench-client "$@"
}

reset_upload_pacing_loss() {
  # The client is the upload sender, so loss belongs on the server receiver's
  # INPUT hook. An OUTPUT drop can make sendmsg return EPERM on nft-backed
  # iptables instead of behaving like path loss.
  ip netns exec "${SERVER_NS}" iptables -F "${PACING_LOSS_CHAIN}"
  # libxt_statistic stores --every N as N-1 and initializes the kernel counter
  # to (every - packet). Starting at N-1 therefore drops the Nth eligible
  # datagram. --packet 0 would drop the first eligible QUIC Initial instead.
  ip netns exec "${SERVER_NS}" iptables -A "${PACING_LOSS_CHAIN}" \
    -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" \
    -m length --length 1000:65535 \
    -m statistic --mode nth --every "${PACING_DROP_EVERY}" \
    --packet "${PACING_INITIAL_PACKET}" -j DROP
  # Count every other eligible datagram. DROP + RETURN counters therefore give
  # the actual denominator, rather than assuming that the matcher was active.
  ip netns exec "${SERVER_NS}" iptables -A "${PACING_LOSS_CHAIN}" \
    -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" \
    -m length --length 1000:65535 -j RETURN
}

reset_download_pacing_loss() {
  local source_port=$1
  # The relay is the download sender, so loss belongs on the client receiver's
  # INPUT hook. Keep every synthetic path-loss rule away from sender OUTPUT.
  ip netns exec "${CLIENT_NS}" iptables -F "${PACING_LOSS_CHAIN}"
  ip netns exec "${CLIENT_NS}" iptables -A "${PACING_LOSS_CHAIN}" \
    -p udp -s "${SERVER_IP}" --sport "${source_port}" -d "${CLIENT_IP}" \
    -m length --length 1000:65535 \
    -m statistic --mode nth --every "${PACING_DROP_EVERY}" \
    --packet "${PACING_INITIAL_PACKET}" -j DROP
  ip netns exec "${CLIENT_NS}" iptables -A "${PACING_LOSS_CHAIN}" \
    -p udp -s "${SERVER_IP}" --sport "${source_port}" -d "${CLIENT_IP}" \
    -m length --length 1000:65535 -j RETURN
}

snapshot_pacing_loss() {
  local namespace=$1
  local dropped_variable=$2
  local eligible_variable=$3
  local counters dropped eligible snapshot_file

  snapshot_file="${ARTIFACT_DIR}/iptables-${dropped_variable,,}.txt"
  ip netns exec "${namespace}" iptables -L "${PACING_LOSS_CHAIN}" \
    --verbose --numeric --exact --line-numbers >"${snapshot_file}"
  counters=$(awk '
      $4 == "DROP" { dropped += $2 }
      $4 == "RETURN" { returned += $2 }
      END { printf "%.0f %.0f%c", dropped, dropped + returned, 10 }
    ' "${snapshot_file}")
  read -r dropped eligible <<<"${counters}"
  if ! [[ ${dropped} =~ ^[0-9]+$ && ${eligible} =~ ^[0-9]+$ ]]; then
    echo "error: could not read deterministic-loss counters in ${namespace}" >&2
    return 1
  fi
  printf -v "${dropped_variable}" '%s' "${dropped}"
  printf -v "${eligible_variable}" '%s' "${eligible}"
}

assert_receiver_input_only() {
  local namespace=$1
  local artifact_name=$2

  ip netns exec "${namespace}" iptables -C INPUT -j "${PACING_LOSS_CHAIN}"
  if ip netns exec "${namespace}" iptables -C OUTPUT -j "${PACING_LOSS_CHAIN}"; then
    echo "error: synthetic path loss is attached to sender OUTPUT in ${namespace}" >&2
    return 1
  fi
  ip netns exec "${namespace}" iptables -S \
    >"${ARTIFACT_DIR}/iptables-${artifact_name}-hooks.txt"
}

expect_failure() {
  local name=$1
  shift
  if "$@" >"${ARTIFACT_DIR}/${name}.stdout.log" 2>"${ARTIFACT_DIR}/${name}.stderr.log"; then
    echo "error: ${name} unexpectedly succeeded" >&2
    return 1
  fi
}

ip netns add "${CLIENT_NS}"
ip netns add "${SERVER_NS}"
ip link add "${CLIENT_DEV}" type veth peer name "${SERVER_DEV}"
ip link set "${CLIENT_DEV}" netns "${CLIENT_NS}"
ip link set "${SERVER_DEV}" netns "${SERVER_NS}"

ip -n "${CLIENT_NS}" link set lo up
ip -n "${SERVER_NS}" link set lo up
ip -n "${CLIENT_NS}" address add "${CLIENT_IP}/24" dev "${CLIENT_DEV}"
ip -n "${SERVER_NS}" address add "${SERVER_IP}/24" dev "${SERVER_DEV}"
ip -n "${CLIENT_NS}" link set "${CLIENT_DEV}" up
ip -n "${SERVER_NS}" link set "${SERVER_DEV}" up

# Make netfilter counters represent individual UDP datagrams instead of
# host-dependent veth GRO/GSO/TSO aggregates.
ip netns exec "${CLIENT_NS}" ethtool -K "${CLIENT_DEV}" gro off gso off tso off
ip netns exec "${SERVER_NS}" ethtool -K "${SERVER_DEV}" gro off gso off tso off
ip netns exec "${CLIENT_NS}" ethtool -k "${CLIENT_DEV}" >"${ARTIFACT_DIR}/ethtool-client.txt"
ip netns exec "${SERVER_NS}" ethtool -k "${SERVER_DEV}" >"${ARTIFACT_DIR}/ethtool-server.txt"
for feature_file in "${ARTIFACT_DIR}/ethtool-client.txt" "${ARTIFACT_DIR}/ethtool-server.txt"; do
  for feature in generic-receive-offload generic-segmentation-offload tcp-segmentation-offload; do
    if ! grep -Eq "^${feature}: off([[:space:]]|$)" "${feature_file}"; then
      echo "error: ${feature} remains enabled according to ${feature_file}" >&2
      exit 1
    fi
  done
done

ip netns exec "${CLIENT_NS}" tc qdisc add dev "${CLIENT_DEV}" root netem \
  delay "${DELAY_MS}ms" loss "${LOSS}" rate "${RATE}" limit 10000
ip netns exec "${SERVER_NS}" tc qdisc add dev "${SERVER_DEV}" root netem \
  delay "${DELAY_MS}ms" loss "${LOSS}" rate "${RATE}" limit 10000

"${AUTOCAR_BIN}" token --out "${WORK_DIR}/relay-token"
"${AUTOCAR_BIN}" cert --hosts "${SERVER_IP}" --cert "${WORK_DIR}/server.crt" --key "${WORK_DIR}/server.key"
"${AUTOCAR_BIN}" cert --hosts "${SERVER_IP}" --cert "${WORK_DIR}/wrong.crt" --key "${WORK_DIR}/wrong.key"
printf '%s\n' 'definitely-the-wrong-shared-token' >"${WORK_DIR}/wrong-token"
chmod 0600 "${WORK_DIR}/wrong-token"

start_background "${ARTIFACT_DIR}/bench-server.log" \
  ip netns exec "${SERVER_NS}" "${AUTOCAR_BIN}" bench-server \
  --listen="${SERVER_IP}:${BENCH_PORT}" --allow-public-benchmark \
  --max-bytes=67108864
BENCH_PID=${STARTED_PID}
wait_for_log "${BENCH_PID}" "${ARTIFACT_DIR}/bench-server.log" "benchmark server listening"

start_background "${ARTIFACT_DIR}/relay.log" \
  ip netns exec "${SERVER_NS}" env QUIC_GO_DISABLE_GSO=true \
  "${AUTOCAR_BIN}" server \
  --listen="${SERVER_IP}:${RELAY_PORT}" \
  --tcp-listen="${SERVER_IP}:${RELAY_PORT}" \
  --cert="${WORK_DIR}/server.crt" \
  --key="${WORK_DIR}/server.key" \
  --token-file="${WORK_DIR}/relay-token" \
  --pacing=adaptive --pacing-profile=balanced \
  --max-upload-mbps="${FIXED_RATE_SERVER_UPLOAD_MBPS}" \
  --max-download-mbps="${FIXED_RATE_SERVER_DOWNLOAD_MBPS}" \
  --allow-client-rates \
  --allow-private --deny-ports=none
RELAY_PID=${STARTED_PID}
wait_for_log "${RELAY_PID}" "${ARTIFACT_DIR}/relay.log" "transport=quic"
wait_for_log "${RELAY_PID}" "${ARTIFACT_DIR}/relay.log" "transport=tls"

# Dedicated adaptive and reno relays let download proofs exercise the remote
# sender. GSO is disabled so the deterministic receiver-side matcher observes
# individual QUIC datagrams on every path.
start_background "${ARTIFACT_DIR}/relay-adaptive.log" \
  ip netns exec "${SERVER_NS}" env QUIC_GO_DISABLE_GSO=true \
  "${AUTOCAR_BIN}" server \
  --listen="${SERVER_IP}:${ADAPTIVE_RELAY_PORT}" \
  --tcp-listen="${SERVER_IP}:${ADAPTIVE_RELAY_PORT}" \
  --cert="${WORK_DIR}/server.crt" \
  --key="${WORK_DIR}/server.key" \
  --token-file="${WORK_DIR}/relay-token" \
  --pacing=adaptive --pacing-profile=balanced \
  --allow-private --deny-ports=none
ADAPTIVE_RELAY_PID=${STARTED_PID}
wait_for_log "${ADAPTIVE_RELAY_PID}" "${ARTIFACT_DIR}/relay-adaptive.log" "transport=quic"

start_background "${ARTIFACT_DIR}/relay-reno.log" \
  ip netns exec "${SERVER_NS}" env QUIC_GO_DISABLE_GSO=true \
  "${AUTOCAR_BIN}" server \
  --listen="${SERVER_IP}:${RENO_RELAY_PORT}" \
  --tcp-listen="${SERVER_IP}:${RENO_RELAY_PORT}" \
  --cert="${WORK_DIR}/server.crt" \
  --key="${WORK_DIR}/server.key" \
  --token-file="${WORK_DIR}/relay-token" \
  --pacing=reno \
  --allow-private --deny-ports=none
RENO_RELAY_PID=${STARTED_PID}
wait_for_log "${RENO_RELAY_PID}" "${ARTIFACT_DIR}/relay-reno.log" "transport=quic"

COMMON_BENCH=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=download
  --bytes="${BENCH_BYTES}"
  --iterations="${BENCH_ITERATIONS}"
  --warmup="${BENCH_WARMUP}"
  --timeout=60s
  --json
)
TUNNEL_AUTH=(
  --server="${SERVER_IP}:${RELAY_PORT}"
  --server-name="${SERVER_IP}"
  --ca="${WORK_DIR}/server.crt"
  --token-file="${WORK_DIR}/relay-token"
  --dial-timeout=3s
  --open-timeout=5s
)
TUNNEL_AUTH_RENO=(
  --server="${SERVER_IP}:${RENO_RELAY_PORT}"
  --server-name="${SERVER_IP}"
  --ca="${WORK_DIR}/server.crt"
  --token-file="${WORK_DIR}/relay-token"
  --dial-timeout=3s
  --open-timeout=5s
)
TUNNEL_AUTH_ADAPTIVE=(
  --server="${SERVER_IP}:${ADAPTIVE_RELAY_PORT}"
  --server-name="${SERVER_IP}"
  --ca="${WORK_DIR}/server.crt"
  --token-file="${WORK_DIR}/relay-token"
  --dial-timeout=3s
  --open-timeout=5s
)

run_client --transport=direct "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/direct.json"
run_client --transport=quic "${TUNNEL_AUTH[@]}" "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/quic.json"
run_client --transport=tls "${TUNNEL_AUTH[@]}" "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/tls.json"

# Use a separately declared deterministic pacing profile. The bulk stage sees
# random netem loss; mode proofs instead drop every Nth large sender datagram at
# the receiver and reset the matcher before every run. Acceptance is based on
# activation, negotiation, direction and counters, never on one mode beating
# another on a shared CI host.
ip netns exec "${CLIENT_NS}" tc qdisc replace dev "${CLIENT_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000
ip netns exec "${SERVER_NS}" tc qdisc replace dev "${SERVER_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000
ip netns exec "${CLIENT_NS}" iptables -N "${PACING_LOSS_CHAIN}"
ip netns exec "${CLIENT_NS}" iptables -I INPUT 1 -j "${PACING_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -N "${PACING_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -I INPUT 1 -j "${PACING_LOSS_CHAIN}"
assert_receiver_input_only "${CLIENT_NS}" client
assert_receiver_input_only "${SERVER_NS}" server

# Exercise every AutoCAR pacing mode with authenticated transfers. Adaptive and
# Reno negotiate no fixed rate. Fixed-rate deliberately uses asymmetric client
# requests and relay caps so swapped upload/download fields cannot pass. This
# lossy phase proves wiring, sender identity and receiver counters—not a minimum
# throughput under Reno loss recovery.
MODE_PROOF_BENCH=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=upload
  --bytes="${PACING_BYTES}"
  --iterations="${PACING_ITERATIONS}"
  --warmup="${PACING_WARMUP}"
  --timeout=60s
  --json
)
reset_upload_pacing_loss
run_pacing_client --transport=quic --pacing=adaptive --pacing-profile=balanced \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/adaptive-upload.json"
snapshot_pacing_loss "${SERVER_NS}" ADAPTIVE_UPLOAD_DROPS ADAPTIVE_UPLOAD_ELIGIBLE
reset_upload_pacing_loss
run_pacing_client --transport=quic --pacing=reno \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/reno-upload.json"
snapshot_pacing_loss "${SERVER_NS}" RENO_UPLOAD_DROPS RENO_UPLOAD_ELIGIBLE
reset_upload_pacing_loss
run_pacing_client --transport=quic --pacing=fixed-rate \
  --upload-mbps="${FIXED_RATE_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${FIXED_RATE_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/fixed-rate-loss-upload.json"
snapshot_pacing_loss "${SERVER_NS}" FIXED_RATE_UPLOAD_DROPS FIXED_RATE_UPLOAD_ELIGIBLE
ip netns exec "${SERVER_NS}" iptables -F "${PACING_LOSS_CHAIN}"

# Repeat the proof with the relay as payload sender. Download loss is always
# injected at the client receiver's INPUT hook. Remote sender metadata proves
# which relay mode was active rather than inferring it from command arguments.
MODE_PROOF_DOWNLOAD=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=download
  --bytes="${PACING_BYTES}"
  --iterations="${PACING_ITERATIONS}"
  --warmup="${PACING_WARMUP}"
  --timeout=60s
  --json
)
reset_download_pacing_loss "${RENO_RELAY_PORT}"
run_pacing_client --transport=quic --pacing=adaptive --pacing-profile=balanced \
  "${TUNNEL_AUTH_RENO[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/reno-download.json"
snapshot_pacing_loss "${CLIENT_NS}" RENO_DOWNLOAD_DROPS RENO_DOWNLOAD_ELIGIBLE
reset_download_pacing_loss "${ADAPTIVE_RELAY_PORT}"
run_pacing_client --transport=quic --pacing=adaptive --pacing-profile=balanced \
  "${TUNNEL_AUTH_ADAPTIVE[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/adaptive-download.json"
snapshot_pacing_loss "${CLIENT_NS}" ADAPTIVE_DOWNLOAD_DROPS ADAPTIVE_DOWNLOAD_ELIGIBLE
reset_download_pacing_loss "${RELAY_PORT}"
run_pacing_client --transport=quic --pacing=fixed-rate \
  --upload-mbps="${FIXED_RATE_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${FIXED_RATE_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/fixed-rate-loss-download.json"
snapshot_pacing_loss "${CLIENT_NS}" FIXED_RATE_DOWNLOAD_DROPS FIXED_RATE_DOWNLOAD_ELIGIBLE
ip netns exec "${CLIENT_NS}" iptables -F "${PACING_LOSS_CHAIN}"

# Measure token-bucket accuracy separately with all deterministic loss rules
# empty. Fixed-rate is an upper-bound application pacer; a lower-bound gate on a
# lossy Reno path would test recovery luck rather than the pacer.
FIXED_ACCURACY_UPLOAD=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=upload
  --bytes="${FIXED_ACCURACY_BYTES}"
  --iterations="${FIXED_ACCURACY_ITERATIONS}"
  --warmup="${FIXED_ACCURACY_WARMUP}"
  --timeout=60s
  --json
)
FIXED_ACCURACY_DOWNLOAD=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=download
  --bytes="${FIXED_ACCURACY_BYTES}"
  --iterations="${FIXED_ACCURACY_ITERATIONS}"
  --warmup="${FIXED_ACCURACY_WARMUP}"
  --timeout=60s
  --json
)
run_pacing_client --transport=quic --pacing=fixed-rate \
  --upload-mbps="${FIXED_RATE_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${FIXED_RATE_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${FIXED_ACCURACY_UPLOAD[@]}" \
  >"${ARTIFACT_DIR}/fixed-rate-upload.json"
run_pacing_client --transport=quic --pacing=fixed-rate \
  --upload-mbps="${FIXED_RATE_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${FIXED_RATE_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${FIXED_ACCURACY_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/fixed-rate-download.json"

# Keep a diagnostic warm-payload profile without turning it into a speed gate.
# Every direct iteration creates a fresh TCP flow while sequential QUIC streams
# reuse one warm connection. Loss is disabled so the recorded ratio describes
# the intended profile instead of a coincidental recovery event.
ip netns exec "${CLIENT_NS}" tc qdisc replace dev "${CLIENT_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000
ip netns exec "${SERVER_NS}" tc qdisc replace dev "${SERVER_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000

# Test cold QUIC-to-TLS fallback after the lossy throughput profile has
# completed. Keeping the latency and rate constraints while removing random
# loss isolates the fallback state machine from a coincidental dropped TLS
# handshake. The deadlines remain finite and the command must still succeed
# on its first attempt.
sleep 0.25
run_client --transport=auto \
  --server="${SERVER_IP}:${UNUSED_QUIC_PORT}" \
  --fallback-server="${SERVER_IP}:${RELAY_PORT}" \
  --server-name="${SERVER_IP}" \
  --ca="${WORK_DIR}/server.crt" \
  --token-file="${WORK_DIR}/relay-token" \
  --dial-timeout=3s --quic-attempt-timeout=2s --open-timeout=8s \
  --target="${SERVER_IP}:${BENCH_PORT}" --mode=download \
  --bytes=131072 --iterations=2 --warmup=0 --timeout=30s --json \
  >"${ARTIFACT_DIR}/auto-fallback.json"

SHORT_BENCH=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=download
  --bytes="${SHORT_FLOW_BYTES}"
  --iterations="${SHORT_FLOW_ITERATIONS}"
  --warmup="${SHORT_FLOW_WARMUP}"
  --timeout=30s
  --json
)
run_client --transport=direct "${SHORT_BENCH[@]}" >"${ARTIFACT_DIR}/short-direct.json"
run_client --transport=quic "${TUNNEL_AUTH[@]}" "${SHORT_BENCH[@]}" >"${ARTIFACT_DIR}/short-quic.json"

expect_failure wrong-ca run_client --transport=tls \
  --server="${SERVER_IP}:${RELAY_PORT}" --server-name="${SERVER_IP}" \
  --ca="${WORK_DIR}/wrong.crt" --token-file="${WORK_DIR}/relay-token" \
  --dial-timeout=2s --open-timeout=3s \
  --target="${SERVER_IP}:${BENCH_PORT}" --bytes=1024 --iterations=1 --warmup=0

expect_failure wrong-token run_client --transport=tls \
  --server="${SERVER_IP}:${RELAY_PORT}" --server-name="${SERVER_IP}" \
  --ca="${WORK_DIR}/server.crt" --token-file="${WORK_DIR}/wrong-token" \
  --dial-timeout=2s --open-timeout=3s \
  --target="${SERVER_IP}:${BENCH_PORT}" --bytes=1024 --iterations=1 --warmup=0

if ! grep -Eiq 'certificate|unknown authority' "${ARTIFACT_DIR}/wrong-ca.stderr.log"; then
  echo "error: wrong-CA test failed for an unexpected reason" >&2
  exit 1
fi
if ! grep -Fiq 'authentication failed' "${ARTIFACT_DIR}/wrong-token.stderr.log"; then
  echo "error: wrong-token test failed for an unexpected reason" >&2
  exit 1
fi

SENTINEL="AUTOCAR-PLAINTEXT-MUST-NOT-CROSS-TUNNEL-${RUN_ID}"
mkdir -p "${WORK_DIR}/origin"
printf '%s\n' "${SENTINEL}" >"${WORK_DIR}/origin/sentinel.txt"
start_background "${ARTIFACT_DIR}/origin.log" \
  ip netns exec "${SERVER_NS}" python3 -m http.server "${ORIGIN_PORT}" \
  --bind "${SERVER_IP}" --directory "${WORK_DIR}/origin"
ORIGIN_PID=${STARTED_PID}
ORIGIN_READY=false
for ((attempt = 0; attempt < 100; attempt++)); do
  if ip netns exec "${SERVER_NS}" env -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY \
    curl --fail --silent --noproxy '*' \
    "http://${SERVER_IP}:${ORIGIN_PORT}/sentinel.txt" >/dev/null; then
    ORIGIN_READY=true
    break
  fi
  if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [[ ${ORIGIN_READY} != true ]]; then
  echo "error: origin server did not become ready" >&2
  exit 1
fi

start_background "${ARTIFACT_DIR}/client-proxy.log" \
  ip netns exec "${CLIENT_NS}" "${AUTOCAR_BIN}" client \
  --transport=auto "${TUNNEL_AUTH[@]}" \
  --dial-timeout=2s --quic-attempt-timeout=2s --open-timeout=6s \
  --socks= --http="127.0.0.1:${PROXY_PORT}" --https=
PROXY_PID=${STARTED_PID}
wait_for_log "${PROXY_PID}" "${ARTIFACT_DIR}/client-proxy.log" "local proxy started"

QUIC_CAPTURE_FILE="${ARTIFACT_DIR}/quic-tunnel.pcap"
start_background "${ARTIFACT_DIR}/tcpdump.log" \
  ip netns exec "${CLIENT_NS}" tcpdump --immediate-mode -i "${CLIENT_DEV}" -s 0 -U -w "${QUIC_CAPTURE_FILE}" \
  "host ${SERVER_IP} and (udp port ${RELAY_PORT} or tcp port ${RELAY_PORT})"
CAPTURE_PID=${STARTED_PID}
wait_for_log "${CAPTURE_PID}" "${ARTIFACT_DIR}/tcpdump.log" "listening on"

QUIC_RESPONSE=$(ip netns exec "${CLIENT_NS}" env \
  -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY -u no_proxy \
  curl --fail --silent --show-error --max-time 15 --noproxy '' \
  --proxy "http://127.0.0.1:${PROXY_PORT}" \
  "http://${SERVER_IP}:${ORIGIN_PORT}/sentinel.txt")
if [[ ${QUIC_RESPONSE} != "${SENTINEL}" ]]; then
  echo "error: initial auto/QUIC proxy response did not match the sentinel" >&2
  exit 1
fi

# Give tcpdump a scheduling turn before interrupting it. Immediate mode avoids
# leaving already-filtered packets in libpcap's kernel buffer on busy CI hosts.
sleep 0.5
kill -INT "${CAPTURE_PID}" >/dev/null 2>&1 || true
wait "${CAPTURE_PID}" >/dev/null 2>&1 || true
if ! tcpdump -nn -r "${QUIC_CAPTURE_FILE}" "udp port ${RELAY_PORT}" 2>/dev/null | grep . >/dev/null; then
  echo "error: initial auto proxy request did not establish QUIC" >&2
  exit 1
fi
if tcpdump -nn -r "${QUIC_CAPTURE_FILE}" "tcp port ${RELAY_PORT}" 2>/dev/null | grep . >/dev/null; then
  echo "error: initial auto proxy request unexpectedly used TLS fallback" >&2
  exit 1
fi

# Silently blackhole the established UDP path at both receivers only after a
# successful QUIC request. Sender-side OUTPUT drops can make nft-backed
# iptables return EPERM from sendmsg, which proves a local firewall error rather
# than a dead network path. Keep TCP untouched for the authenticated fallback.
ip netns exec "${SERVER_NS}" iptables -F "${PACING_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -A "${PACING_LOSS_CHAIN}" \
  -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" -j DROP
ip netns exec "${CLIENT_NS}" iptables -F "${PACING_LOSS_CHAIN}"
ip netns exec "${CLIENT_NS}" iptables -A "${PACING_LOSS_CHAIN}" \
  -p udp -s "${SERVER_IP}" --sport "${RELAY_PORT}" -d "${CLIENT_IP}" -j DROP

# Exercise the same syscall family quic-go uses while the server receiver is
# dropping the datagram. A sender OUTPUT rule on nft-backed iptables would make
# this fail immediately with EPERM instead of returning the payload length.
ip netns exec "${CLIENT_NS}" python3 -c '
import socket
import sys

payload = b"autocar-sendmsg-eperm-probe"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sent = sock.sendmsg([payload], [], 0, (sys.argv[1], int(sys.argv[2])))
if sent != len(payload):
    raise SystemExit(f"sendmsg returned {sent}, want {len(payload)}")
' "${SERVER_IP}" "${RELAY_PORT}"

# The standalone syscall probe intentionally hits the upstream receiver rule.
# Clear its evidence before the live fallback request so that the counter below
# is causally tied to the QUIC attempt captured in tls-fallback.pcap.
ip netns exec "${SERVER_NS}" iptables -Z "${PACING_LOSS_CHAIN}"
ip netns exec "${CLIENT_NS}" iptables -Z "${PACING_LOSS_CHAIN}"

FALLBACK_CAPTURE_FILE="${ARTIFACT_DIR}/tls-fallback.pcap"
start_background "${ARTIFACT_DIR}/fallback-tcpdump.log" \
  ip netns exec "${CLIENT_NS}" tcpdump --immediate-mode -i "${CLIENT_DEV}" -s 0 -U -w "${FALLBACK_CAPTURE_FILE}" \
  "host ${SERVER_IP} and (udp port ${RELAY_PORT} or tcp port ${RELAY_PORT})"
CAPTURE_PID=${STARTED_PID}
wait_for_log "${CAPTURE_PID}" "${ARTIFACT_DIR}/fallback-tcpdump.log" "listening on"

FALLBACK_START_MS=$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')
FALLBACK_RESPONSE=$(ip netns exec "${CLIENT_NS}" env \
  -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY -u no_proxy \
  curl --fail --silent --show-error --max-time 10 --noproxy '' \
  --header 'Connection: close' \
  --proxy "http://127.0.0.1:${PROXY_PORT}" \
  "http://${SERVER_IP}:${ORIGIN_PORT}/sentinel.txt")
FALLBACK_END_MS=$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')
FALLBACK_ELAPSED_MS=$((FALLBACK_END_MS - FALLBACK_START_MS))
if [[ ${FALLBACK_RESPONSE} != "${SENTINEL}" ]]; then
  echo "error: auto/TLS fallback proxy response did not match the sentinel" >&2
  exit 1
fi
if (( FALLBACK_ELAPSED_MS > 10000 )); then
  echo "error: auto/TLS fallback exceeded the 10-second bound" >&2
  exit 1
fi
if (( FALLBACK_ELAPSED_MS < 1000 )); then
  echo "error: auto/TLS fallback completed too quickly to prove a silent UDP blackhole" >&2
  exit 1
fi

sleep 0.5
kill -INT "${CAPTURE_PID}" >/dev/null 2>&1 || true
wait "${CAPTURE_PID}" >/dev/null 2>&1 || true
if ! tcpdump -nn -r "${FALLBACK_CAPTURE_FILE}" "tcp port ${RELAY_PORT}" 2>/dev/null | grep . >/dev/null; then
  echo "error: request after UDP loss did not use the TCP/TLS fallback" >&2
  exit 1
fi
if ! tcpdump -nn -r "${FALLBACK_CAPTURE_FILE}" "udp port ${RELAY_PORT}" 2>/dev/null | grep . >/dev/null; then
  echo "error: silent-blackhole fallback capture contains no UDP attempt" >&2
  exit 1
fi
ip netns exec "${SERVER_NS}" iptables \
  -L "${PACING_LOSS_CHAIN}" --verbose --numeric --exact --line-numbers \
  >"${ARTIFACT_DIR}/iptables-live-blackhole.txt"
LIVE_UPSTREAM_DROPS=$(awk '
  $4 == "DROP" { dropped += $2 }
  END { printf "%.0f%c", dropped, 10 }
' "${ARTIFACT_DIR}/iptables-live-blackhole.txt")
if ! [[ ${LIVE_UPSTREAM_DROPS} =~ ^[0-9]+$ ]] || (( LIVE_UPSTREAM_DROPS == 0 )); then
  echo "error: silent UDP blackhole did not drop an upstream datagram" >&2
  exit 1
fi
if grep -Eiq 'operation not permitted|sendmsg.*permission denied|(^|[^[:alnum:]_])EPERM([^[:alnum:]_]|$)' \
  "${ARTIFACT_DIR}/client-proxy.log"; then
  echo "error: live-path fallback was triggered by local sendmsg EPERM" >&2
  exit 1
fi
if grep -aFq "${SENTINEL}" "${QUIC_CAPTURE_FILE}" || \
   grep -aFq "${SENTINEL}" "${FALLBACK_CAPTURE_FILE}"; then
  echo "error: plaintext sentinel was visible on a tunnel link" >&2
  exit 1
fi

python3 - "${ARTIFACT_DIR}/direct.json" "${ARTIFACT_DIR}/quic.json" \
    "${ARTIFACT_DIR}/tls.json" "${ARTIFACT_DIR}/short-direct.json" \
    "${ARTIFACT_DIR}/short-quic.json" "${ARTIFACT_DIR}/adaptive-upload.json" \
    "${ARTIFACT_DIR}/reno-upload.json" "${ARTIFACT_DIR}/fixed-rate-loss-upload.json" \
    "${ARTIFACT_DIR}/adaptive-download.json" "${ARTIFACT_DIR}/reno-download.json" \
    "${ARTIFACT_DIR}/fixed-rate-loss-download.json" \
    "${ARTIFACT_DIR}/fixed-rate-upload.json" "${ARTIFACT_DIR}/fixed-rate-download.json" \
    "${ARTIFACT_DIR}/summary.json" \
    "${DELAY_MS}" "${LOSS}" "${RATE}" "${IPTABLES_VERSION}" \
    "${PACING_DROP_EVERY}" \
    "${PACING_BYTES}" "${PACING_ITERATIONS}" \
    "${PACING_WARMUP}" "${FIXED_ACCURACY_BYTES}" \
    "${FIXED_ACCURACY_ITERATIONS}" "${FIXED_ACCURACY_WARMUP}" \
    "${SHORT_FLOW_BYTES}" "${FIXED_RATE_MIN_RATIO}" "${FIXED_RATE_MAX_RATIO}" \
    "${FIXED_RATE_SERVER_UPLOAD_MBPS}" \
    "${FIXED_RATE_SERVER_DOWNLOAD_MBPS}" "${FIXED_RATE_CLIENT_UPLOAD_MBPS}" \
    "${FIXED_RATE_CLIENT_DOWNLOAD_MBPS}" \
    "${FIXED_RATE_EXPECTED_UPLOAD_BYTES_SEC}" \
    "${FIXED_RATE_EXPECTED_DOWNLOAD_BYTES_SEC}" \
  "${ADAPTIVE_UPLOAD_DROPS}" "${ADAPTIVE_UPLOAD_ELIGIBLE}" \
  "${RENO_UPLOAD_DROPS}" "${RENO_UPLOAD_ELIGIBLE}" \
  "${FIXED_RATE_UPLOAD_DROPS}" "${FIXED_RATE_UPLOAD_ELIGIBLE}" \
  "${ADAPTIVE_DOWNLOAD_DROPS}" "${ADAPTIVE_DOWNLOAD_ELIGIBLE}" \
  "${RENO_DOWNLOAD_DROPS}" "${RENO_DOWNLOAD_ELIGIBLE}" \
  "${FIXED_RATE_DOWNLOAD_DROPS}" "${FIXED_RATE_DOWNLOAD_ELIGIBLE}" \
  "${LIVE_UPSTREAM_DROPS}" "${FALLBACK_ELAPSED_MS}" <<'PY'
import json
import pathlib
import sys

if len(sys.argv) != 49:
    raise SystemExit(
        f"internal netem summary argument mismatch: got {len(sys.argv) - 1}, want 48"
    )

(
    direct_path,
    quic_path,
    tls_path,
    short_direct_path,
    short_quic_path,
    adaptive_upload_path,
    reno_upload_path,
    fixed_rate_loss_upload_path,
    adaptive_download_path,
    reno_download_path,
    fixed_rate_loss_download_path,
    fixed_rate_upload_path,
    fixed_rate_download_path,
    output_path,
) = map(
    pathlib.Path, sys.argv[1:15]
)
(
    delay_ms,
    loss,
    rate,
    iptables_version,
    pacing_drop_every,
    pacing_bytes,
    pacing_iterations,
    pacing_warmup,
    fixed_accuracy_bytes,
    fixed_accuracy_iterations,
    fixed_accuracy_warmup,
    short_flow_bytes,
    fixed_rate_min_ratio,
    fixed_rate_max_ratio,
    server_upload_mbps,
    server_download_mbps,
    client_upload_mbps,
    client_download_mbps,
    expected_fixed_rate_upload_tx,
    expected_fixed_rate_download_tx,
    adaptive_upload_drops,
    adaptive_upload_eligible,
    reno_upload_drops,
    reno_upload_eligible,
    fixed_rate_upload_drops,
    fixed_rate_upload_eligible,
    adaptive_download_drops,
    adaptive_download_eligible,
    reno_download_drops,
    reno_download_eligible,
    fixed_rate_download_drops,
    fixed_rate_download_eligible,
    live_upstream_drops,
    fallback_elapsed_ms,
) = sys.argv[15:49]
direct = json.loads(direct_path.read_text())
quic = json.loads(quic_path.read_text())
tls = json.loads(tls_path.read_text())
short_direct = json.loads(short_direct_path.read_text())
short_quic = json.loads(short_quic_path.read_text())
adaptive_upload = json.loads(adaptive_upload_path.read_text())
reno_upload = json.loads(reno_upload_path.read_text())
fixed_rate_loss_upload = json.loads(fixed_rate_loss_upload_path.read_text())
adaptive_download = json.loads(adaptive_download_path.read_text())
reno_download = json.loads(reno_download_path.read_text())
fixed_rate_loss_download = json.loads(fixed_rate_loss_download_path.read_text())
fixed_rate_upload = json.loads(fixed_rate_upload_path.read_text())
fixed_rate_download = json.loads(fixed_rate_download_path.read_text())

fixed_rate_min_ratio = float(fixed_rate_min_ratio)
fixed_rate_max_ratio = float(fixed_rate_max_ratio)
if not 0 < fixed_rate_min_ratio <= 1 <= fixed_rate_max_ratio:
    raise SystemExit("fixed-rate ratio bounds must satisfy 0 < minimum <= 1 <= maximum")

loss_observations = {
    "adaptive_upload": (int(adaptive_upload_drops), int(adaptive_upload_eligible)),
    "reno_upload": (int(reno_upload_drops), int(reno_upload_eligible)),
    "fixed_rate_upload": (int(fixed_rate_upload_drops), int(fixed_rate_upload_eligible)),
    "adaptive_download": (int(adaptive_download_drops), int(adaptive_download_eligible)),
    "reno_download": (int(reno_download_drops), int(reno_download_eligible)),
    "fixed_rate_download": (
        int(fixed_rate_download_drops),
        int(fixed_rate_download_eligible),
    ),
}

for name, (dropped, eligible) in loss_observations.items():
    if dropped <= 0 or eligible <= 0:
        raise SystemExit(
            f"{name} deterministic-loss rule matched {eligible} and dropped {dropped}; "
            "the pacing proof did not exercise receiver-side loss"
        )
    expected_drops = eligible // int(pacing_drop_every)
    if dropped != expected_drops:
        raise SystemExit(
            f"{name} deterministic-loss counters report {dropped}/{eligible}, "
            f"want exactly floor(eligible/{int(pacing_drop_every)})={expected_drops}"
        )

for name, result, transport in (
    ("direct", direct, "direct"),
    ("quic", quic, "quic"),
    ("tls", tls, "tls"),
):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} benchmark reported non-positive goodput")
    if (
        result.get("mode") != "download"
        or result.get("transport") != transport
        or result.get("selected_transport") != transport
    ):
        raise SystemExit(
            f"{name} benchmark metadata reported mode={result.get('mode')!r}, "
            f"transport={result.get('transport')!r}"
        )
for name, result, transport in (
    ("short direct", short_direct, "direct"),
    ("short quic", short_quic, "quic"),
):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} benchmark reported non-positive goodput")
    if (
        result.get("mode") != "download"
        or result.get("transport") != transport
        or result.get("selected_transport") != transport
    ):
        raise SystemExit(f"{name} benchmark has incorrect mode or transport metadata")
    if result.get("bytes_per_iteration") != int(short_flow_bytes):
        raise SystemExit(
            f"{name} benchmark used {result.get('bytes_per_iteration')!r} bytes, "
            f"want {int(short_flow_bytes)}"
        )

for name, result in (
    ("adaptive upload", adaptive_upload),
    ("reno upload", reno_upload),
    ("fixed-rate loss upload", fixed_rate_loss_upload),
    ("adaptive download", adaptive_download),
    ("reno download", reno_download),
    ("fixed-rate loss download", fixed_rate_loss_download),
):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} pacing proof reported non-positive goodput")
    if result.get("bytes_per_iteration") != int(pacing_bytes):
        raise SystemExit(
            f"{name} proof used {result.get('bytes_per_iteration')!r} bytes, "
            f"want {int(pacing_bytes)}"
        )
    if result.get("iterations") != int(pacing_iterations):
        raise SystemExit(
            f"{name} proof used {result.get('iterations')!r} iterations, "
            f"want {int(pacing_iterations)}"
        )

for name, result in (
    ("fixed-rate accuracy upload", fixed_rate_upload),
    ("fixed-rate accuracy download", fixed_rate_download),
):
    if result.get("bytes_per_iteration") != int(fixed_accuracy_bytes):
        raise SystemExit(
            f"{name} used {result.get('bytes_per_iteration')!r} bytes, "
            f"want {int(fixed_accuracy_bytes)}"
        )
    if result.get("iterations") != int(fixed_accuracy_iterations):
        raise SystemExit(
            f"{name} used {result.get('iterations')!r} iterations, "
            f"want {int(fixed_accuracy_iterations)}"
        )


def aggregate_goodput(name, result, expected_iterations):
    """Return total equal-size bytes divided by total measured elapsed time."""
    values = result.get("results_mbps")
    if not isinstance(values, list) or len(values) != int(expected_iterations):
        raise SystemExit(
            f"{name} proof has {len(values) if isinstance(values, list) else 'invalid'} "
            f"raw results, want {int(expected_iterations)}"
        )
    if any(not isinstance(value, (int, float)) or value <= 0 for value in values):
        raise SystemExit(f"{name} proof contains a non-positive raw goodput value")
    # Every transfer has the same byte count, so this harmonic mean is exactly
    # aggregate goodput: total bytes divided by total transfer time.
    return len(values) / sum(1.0 / value for value in values)


adaptive_upload_aggregate_mbps = aggregate_goodput("adaptive upload", adaptive_upload, pacing_iterations)
reno_upload_aggregate_mbps = aggregate_goodput("reno upload", reno_upload, pacing_iterations)
fixed_rate_loss_upload_aggregate_mbps = aggregate_goodput(
    "fixed-rate loss upload", fixed_rate_loss_upload, pacing_iterations
)
fixed_rate_upload_aggregate_mbps = aggregate_goodput(
    "fixed-rate accuracy upload", fixed_rate_upload, fixed_accuracy_iterations
)
adaptive_download_aggregate_mbps = aggregate_goodput("adaptive download", adaptive_download, pacing_iterations)
reno_download_aggregate_mbps = aggregate_goodput("reno download", reno_download, pacing_iterations)
fixed_rate_loss_download_aggregate_mbps = aggregate_goodput(
    "fixed-rate loss download", fixed_rate_loss_download, pacing_iterations
)
fixed_rate_download_aggregate_mbps = aggregate_goodput(
    "fixed-rate accuracy download", fixed_rate_download, fixed_accuracy_iterations
)

for name, result, mode, sender in (
    ("adaptive upload", adaptive_upload, "upload", "client"),
    ("reno upload", reno_upload, "upload", "client"),
    ("fixed-rate loss upload", fixed_rate_loss_upload, "upload", "client"),
    ("adaptive download", adaptive_download, "download", "relay"),
    ("reno download", reno_download, "download", "relay"),
    ("fixed-rate loss download", fixed_rate_loss_download, "download", "relay"),
    ("fixed-rate accuracy upload", fixed_rate_upload, "upload", "client"),
    ("fixed-rate accuracy download", fixed_rate_download, "download", "relay"),
):
    if (
        result.get("mode") != mode
        or result.get("transport") != "quic"
        or result.get("selected_transport") != "quic"
    ):
        raise SystemExit(
            f"{name} metadata reported mode={result.get('mode')!r}, "
            f"transport={result.get('transport')!r}; want {mode!r}, 'quic'"
        )
    if result.get("tunnel_sender_endpoint") != sender:
        raise SystemExit(
            f"{name} reported tunnel sender "
            f"{result.get('tunnel_sender_endpoint')!r}, want {sender!r}"
        )

expected_fixed_rate_upload_tx = int(expected_fixed_rate_upload_tx)
expected_fixed_rate_download_tx = int(expected_fixed_rate_download_tx)
fixed_rate_targets_mbps = {
    "upload": expected_fixed_rate_upload_tx * 8 / 1_000_000,
    "download": expected_fixed_rate_download_tx * 8 / 1_000_000,
}


def require_sender_metadata(name, result, acceleration, negotiated_tx):
    if result.get("payload_sender_acceleration") != acceleration:
        raise SystemExit(
            f"{name} reported payload sender acceleration="
            f"{result.get('payload_sender_acceleration')!r}, want {acceleration!r}"
        )
    actual_tx = result.get("payload_sender_negotiated_tx_bytes_per_second", 0)
    if actual_tx != negotiated_tx:
        raise SystemExit(
            f"{name} reported payload sender negotiated Tx={actual_tx!r}, "
            f"want {negotiated_tx} bytes/s"
        )


for name, result, acceleration, negotiated_tx in (
    ("adaptive upload", adaptive_upload, "adaptive-balanced", 0),
    ("reno upload", reno_upload, "reno", 0),
    ("fixed-rate loss upload", fixed_rate_loss_upload, "fixed-rate", expected_fixed_rate_upload_tx),
    ("adaptive download", adaptive_download, "adaptive-balanced", 0),
    ("reno download", reno_download, "reno", 0),
    ("fixed-rate loss download", fixed_rate_loss_download, "fixed-rate", expected_fixed_rate_download_tx),
    ("fixed-rate accuracy upload", fixed_rate_upload, "fixed-rate", expected_fixed_rate_upload_tx),
    ("fixed-rate accuracy download", fixed_rate_download, "fixed-rate", expected_fixed_rate_download_tx),
):
    require_sender_metadata(name, result, acceleration, negotiated_tx)

for name, result, acceleration, negotiated_tx in (
    ("adaptive upload", adaptive_upload, "adaptive-balanced", 0),
    ("reno upload", reno_upload, "reno", 0),
    ("fixed-rate loss upload", fixed_rate_loss_upload, "fixed-rate", expected_fixed_rate_upload_tx),
    ("adaptive download client", adaptive_download, "adaptive-balanced", 0),
    ("reno download client", reno_download, "adaptive-balanced", 0),
    ("fixed-rate loss download client", fixed_rate_loss_download, "fixed-rate", expected_fixed_rate_upload_tx),
    ("fixed-rate accuracy upload client", fixed_rate_upload, "fixed-rate", expected_fixed_rate_upload_tx),
    ("fixed-rate accuracy download client", fixed_rate_download, "fixed-rate", expected_fixed_rate_upload_tx),
):
    if result.get("local_tx_acceleration") != acceleration:
        raise SystemExit(
            f"{name} reported local Tx acceleration="
            f"{result.get('local_tx_acceleration')!r}, want {acceleration!r}"
        )
    actual_tx = result.get("local_negotiated_tx_bytes_per_second", 0)
    if actual_tx != negotiated_tx:
        raise SystemExit(
            f"{name} reported local negotiated Tx={actual_tx!r}, "
            f"want {negotiated_tx} bytes/s"
        )

fixed_rate_accuracy_mbps = {
    "upload": fixed_rate_upload_aggregate_mbps,
    "download": fixed_rate_download_aggregate_mbps,
}
for direction, measured_mbps in fixed_rate_accuracy_mbps.items():
    ratio = measured_mbps / fixed_rate_targets_mbps[direction]
    if not fixed_rate_min_ratio <= ratio <= fixed_rate_max_ratio:
        raise SystemExit(
            f"loss-free fixed-rate {direction} aggregate goodput {measured_mbps:.3f} Mbit/s "
            f"is {ratio:.3f}x target, outside "
            f"[{fixed_rate_min_ratio:.3f}, {fixed_rate_max_ratio:.3f}]"
        )

short_ratio = short_quic["median_mbps"] / short_direct["median_mbps"]

summary = {
    "netem": {
        "one_way_delay_ms": int(delay_ms),
        "loss_each_direction": loss,
        "rate_each_direction": rate,
        "iptables_version": iptables_version,
    },
    "median_mbps": {
        "direct": direct["median_mbps"],
        "quic": quic["median_mbps"],
        "tls": tls["median_mbps"],
    },
    "ratio_to_direct": {
        "quic": quic["median_mbps"] / direct["median_mbps"],
        "tls": tls["median_mbps"] / direct["median_mbps"],
    },
    "pacing_proof": {
        "acceptance_basis": [
            "observed sender mode and negotiated rate metadata",
            "observed upload/client and download/relay sender direction",
            "exact receiver INPUT eligible and DROP packet counters",
            "loss-free fixed-rate aggregate goodput within a declared target ratio",
        ],
        "network_profile": {
            "one_way_delay_ms": int(delay_ms),
            "rate_each_direction": rate,
            "random_loss_each_direction": "0%",
            "loss_hooks": {
                "upload": "server INPUT",
                "download": "client INPUT",
            },
            "receiver_input_large_udp_drop_every": int(pacing_drop_every),
            "actual_loss": {
                name: {
                    "receiver_hook": (
                        "server INPUT" if name.endswith("_upload") else "client INPUT"
                    ),
                    "eligible_packets": eligible,
                    "dropped_packets": dropped,
                    "drop_rate": dropped / eligible,
                }
                for name, (dropped, eligible) in loss_observations.items()
            },
            "bytes_per_iteration": int(pacing_bytes),
            "measured_iterations": int(pacing_iterations),
            "warmup_iterations": int(pacing_warmup),
        },
        "adaptive": {
            "upload": {
                "artifact": adaptive_upload_path.name,
                "observed_sender": adaptive_upload["tunnel_sender_endpoint"],
                "observed_sender_acceleration": adaptive_upload[
                    "payload_sender_acceleration"
                ],
                "observed_sender_negotiated_tx_bytes_per_second": adaptive_upload.get(
                    "payload_sender_negotiated_tx_bytes_per_second", 0
                ),
                "median_mbps": adaptive_upload["median_mbps"],
                "aggregate_mbps": adaptive_upload_aggregate_mbps,
            },
            "download": {
                "artifact": adaptive_download_path.name,
                "observed_sender": adaptive_download["tunnel_sender_endpoint"],
                "observed_sender_acceleration": adaptive_download[
                    "payload_sender_acceleration"
                ],
                "observed_sender_negotiated_tx_bytes_per_second": adaptive_download.get(
                    "payload_sender_negotiated_tx_bytes_per_second", 0
                ),
                "median_mbps": adaptive_download["median_mbps"],
                "aggregate_mbps": adaptive_download_aggregate_mbps,
            },
        },
        "reno": {
            "upload": {
                "artifact": reno_upload_path.name,
                "observed_sender": reno_upload["tunnel_sender_endpoint"],
                "observed_sender_acceleration": reno_upload[
                    "payload_sender_acceleration"
                ],
                "observed_sender_negotiated_tx_bytes_per_second": reno_upload.get(
                    "payload_sender_negotiated_tx_bytes_per_second", 0
                ),
                "median_mbps": reno_upload["median_mbps"],
                "aggregate_mbps": reno_upload_aggregate_mbps,
            },
            "download": {
                "artifact": reno_download_path.name,
                "observed_sender": reno_download["tunnel_sender_endpoint"],
                "observed_sender_acceleration": reno_download[
                    "payload_sender_acceleration"
                ],
                "observed_sender_negotiated_tx_bytes_per_second": reno_download.get(
                    "payload_sender_negotiated_tx_bytes_per_second", 0
                ),
                "median_mbps": reno_download["median_mbps"],
                "aggregate_mbps": reno_download_aggregate_mbps,
            },
        },
        "fixed-rate": {
            "loss_free_accuracy": {
                "accepted_ratio": {
                    "minimum": fixed_rate_min_ratio,
                    "maximum": fixed_rate_max_ratio,
                },
                "bytes_per_iteration": int(fixed_accuracy_bytes),
                "measured_iterations": int(fixed_accuracy_iterations),
                "warmup_iterations": int(fixed_accuracy_warmup),
            },
            "upload": {
                "target_mbps": fixed_rate_targets_mbps["upload"],
                "loss_proof_artifact": fixed_rate_loss_upload_path.name,
                "loss_proof_aggregate_mbps": fixed_rate_loss_upload_aggregate_mbps,
                "artifact": fixed_rate_upload_path.name,
                "observed_sender": fixed_rate_upload["tunnel_sender_endpoint"],
                "observed_sender_acceleration": fixed_rate_upload[
                    "payload_sender_acceleration"
                ],
                "observed_sender_negotiated_tx_bytes_per_second": fixed_rate_upload[
                    "payload_sender_negotiated_tx_bytes_per_second"
                ],
                "median_mbps": fixed_rate_upload["median_mbps"],
                "aggregate_mbps": fixed_rate_upload_aggregate_mbps,
            },
            "download": {
                "target_mbps": fixed_rate_targets_mbps["download"],
                "loss_proof_artifact": fixed_rate_loss_download_path.name,
                "loss_proof_aggregate_mbps": fixed_rate_loss_download_aggregate_mbps,
                "artifact": fixed_rate_download_path.name,
                "observed_sender": fixed_rate_download["tunnel_sender_endpoint"],
                "observed_sender_acceleration": fixed_rate_download[
                    "payload_sender_acceleration"
                ],
                "observed_sender_negotiated_tx_bytes_per_second": fixed_rate_download[
                    "payload_sender_negotiated_tx_bytes_per_second"
                ],
                "median_mbps": fixed_rate_download["median_mbps"],
                "aggregate_mbps": fixed_rate_download_aggregate_mbps,
            },
            "client_upload_mbps": int(client_upload_mbps),
            "client_download_mbps": int(client_download_mbps),
            "server_upload_cap_mbps": int(server_upload_mbps),
            "server_download_cap_mbps": int(server_download_mbps),
        },
    },
    "warm_payload_profile": {
        "description": "sequential short payload phases over a loss-free high-RTT path; tunnel setup is excluded and QUIC uses declared warmups",
        "payload_bytes": int(short_flow_bytes),
        "one_way_delay_ms": int(delay_ms),
        "loss_each_direction": "0%",
        "rate_each_direction": rate,
        "direct_median_mbps": short_direct["median_mbps"],
        "quic_median_mbps": short_quic["median_mbps"],
        "quic_to_direct_ratio": short_ratio,
        "acceptance_gate": "metadata and positive goodput only",
    },
    "security_smoke": {
        "wrong_ca_rejected": True,
        "wrong_token_rejected": True,
        "plaintext_sentinel_absent_from_tunnel_capture": True,
        "auto_initial_quic_request_succeeded": True,
        "auto_tls_request_after_silent_udp_blackhole_succeeded": True,
        "silent_blackhole_receiver_input_udp_drops": int(live_upstream_drops),
        "silent_blackhole_fallback_elapsed_ms": int(fallback_elapsed_ms),
        "synthetic_loss_hooks_exclude_output": True,
        "receiver_input_sendmsg_probe_succeeded": True,
        "sendmsg_eperm_absent": True,
    },
}
output_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

echo "netem integration passed"
echo "results: ${ARTIFACT_DIR}/summary.json"
