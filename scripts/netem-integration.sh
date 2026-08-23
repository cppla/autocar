#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

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

for command in ip tc iptables tcpdump curl python3 grep readlink awk; do
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
IPTABLES_VERSION=$(iptables --version)
printf '%s\n' "${IPTABLES_VERSION}" >"${ARTIFACT_DIR}/iptables-version.txt"

RUN_ID=$$
CLIENT_NS="autocar-client-${RUN_ID}"
SERVER_NS="autocar-server-${RUN_ID}"
CLIENT_DEV="acc${RUN_ID}"
SERVER_DEV="acs${RUN_ID}"
CLIENT_IP=10.203.0.1
SERVER_IP=10.203.0.2
RELAY_PORT=7443
BBR_RELAY_PORT=7445
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
CONTROLLER_DROP_EVERY=${AUTOCAR_CONTROLLER_DROP_EVERY:-200}
CONTROLLER_BYTES=${AUTOCAR_CONTROLLER_BYTES:-4194304}
CONTROLLER_ITERATIONS=${AUTOCAR_CONTROLLER_ITERATIONS:-5}
CONTROLLER_WARMUP=${AUTOCAR_CONTROLLER_WARMUP:-2}
SHORT_FLOW_BYTES=${AUTOCAR_SHORT_FLOW_BYTES:-131072}
SHORT_FLOW_ITERATIONS=${AUTOCAR_SHORT_FLOW_ITERATIONS:-9}
SHORT_FLOW_WARMUP=${AUTOCAR_SHORT_FLOW_WARMUP:-3}
MIN_SHORT_FLOW_RATIO=${AUTOCAR_MIN_SHORT_FLOW_RATIO:-1.10}
MIN_BBR_RENO_RATIO=${AUTOCAR_MIN_BBR_RENO_RATIO:-1.10}
MIN_BRUTAL_TARGET_RATIO=${AUTOCAR_MIN_BRUTAL_TARGET_RATIO:-0.80}
MAX_BRUTAL_TARGET_RATIO=${AUTOCAR_MAX_BRUTAL_TARGET_RATIO:-1.15}
BRUTAL_SERVER_UPLOAD_MBPS=15
BRUTAL_SERVER_DOWNLOAD_MBPS=15
BRUTAL_CLIENT_UPLOAD_MBPS=20
BRUTAL_CLIENT_DOWNLOAD_MBPS=20
BRUTAL_EXPECTED_TX_BYTES_SEC=1875000
CONTROLLER_LOSS_CHAIN=AUTOCAR_CC_LOSS

if ! [[ ${CONTROLLER_DROP_EVERY} =~ ^[0-9]+$ ]] || \
   (( CONTROLLER_DROP_EVERY < 2 )); then
  echo "error: AUTOCAR_CONTROLLER_DROP_EVERY must be an integer of at least 2" >&2
  exit 1
fi
CONTROLLER_INITIAL_PACKET=$((CONTROLLER_DROP_EVERY - 1))
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
  chmod -R a+rX "${ARTIFACT_DIR}" >/dev/null 2>&1 || true

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

# Disabling UDP GSO for controller A/B senders makes one statistic-matcher
# packet correspond to one QUIC datagram instead of a host-dependent GSO batch.
run_controller_client() {
  ip netns exec "${CLIENT_NS}" env QUIC_GO_DISABLE_GSO=true \
    "${AUTOCAR_BIN}" bench-client "$@"
}

reset_upload_controller_loss() {
  # Drop at the receiver's INPUT hook. An OUTPUT drop can make sendmsg return
  # EPERM on nft-backed iptables instead of behaving like path loss.
  ip netns exec "${SERVER_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"
  # libxt_statistic stores --every N as N-1 and initializes the kernel counter
  # to (every - packet). Starting at N-1 therefore drops the Nth eligible
  # datagram. --packet 0 would drop the first eligible QUIC Initial instead.
  ip netns exec "${SERVER_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
    -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" \
    -m length --length 1000:65535 \
    -m statistic --mode nth --every "${CONTROLLER_DROP_EVERY}" \
    --packet "${CONTROLLER_INITIAL_PACKET}" -j DROP
  # Count every other eligible datagram. DROP + RETURN counters therefore give
  # the actual denominator, rather than assuming that the matcher was active.
  ip netns exec "${SERVER_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
    -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" \
    -m length --length 1000:65535 -j RETURN
}

reset_download_controller_loss() {
  local source_port=$1
  ip netns exec "${CLIENT_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"
  ip netns exec "${CLIENT_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
    -p udp -s "${SERVER_IP}" --sport "${source_port}" -d "${CLIENT_IP}" \
    -m length --length 1000:65535 \
    -m statistic --mode nth --every "${CONTROLLER_DROP_EVERY}" \
    --packet "${CONTROLLER_INITIAL_PACKET}" -j DROP
  ip netns exec "${CLIENT_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
    -p udp -s "${SERVER_IP}" --sport "${source_port}" -d "${CLIENT_IP}" \
    -m length --length 1000:65535 -j RETURN
}

snapshot_controller_loss() {
  local namespace=$1
  local dropped_variable=$2
  local eligible_variable=$3
  local counters dropped eligible snapshot_file

  snapshot_file="${ARTIFACT_DIR}/iptables-${dropped_variable,,}.txt"
  ip netns exec "${namespace}" iptables -L "${CONTROLLER_LOSS_CHAIN}" \
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

expect_failure() {
  local name=$1
  shift
  if "$@" >"${ARTIFACT_DIR}/${name}.stdout.log" 2>"${ARTIFACT_DIR}/${name}.stderr.log"; then
    echo "error: ${name} unexpectedly succeeded" >&2
    return 1
  fi
}

umask 077

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
  --max-upload-mbps="${BRUTAL_SERVER_UPLOAD_MBPS}" \
  --max-download-mbps="${BRUTAL_SERVER_DOWNLOAD_MBPS}" \
  --allow-client-bandwidth \
  --allow-private --deny-ports=none
RELAY_PID=${STARTED_PID}
wait_for_log "${RELAY_PID}" "${ARTIFACT_DIR}/relay.log" "transport=hy2"
wait_for_log "${RELAY_PID}" "${ARTIFACT_DIR}/relay.log" "transport=tls"

# Two otherwise identical, controller-only relays make the download comparison
# exercise the relay-side sender. GSO is disabled on both so the deterministic
# packet-loss matcher observes individual QUIC datagrams on either path.
start_background "${ARTIFACT_DIR}/relay-bbr-controller.log" \
  ip netns exec "${SERVER_NS}" env QUIC_GO_DISABLE_GSO=true \
  "${AUTOCAR_BIN}" server \
  --listen="${SERVER_IP}:${BBR_RELAY_PORT}" \
  --tcp-listen="${SERVER_IP}:${BBR_RELAY_PORT}" \
  --cert="${WORK_DIR}/server.crt" \
  --key="${WORK_DIR}/server.key" \
  --token-file="${WORK_DIR}/relay-token" \
  --congestion=bbr --bbr-profile=standard \
  --allow-private --deny-ports=none
BBR_RELAY_PID=${STARTED_PID}
wait_for_log "${BBR_RELAY_PID}" "${ARTIFACT_DIR}/relay-bbr-controller.log" "transport=hy2"

start_background "${ARTIFACT_DIR}/relay-reno.log" \
  ip netns exec "${SERVER_NS}" env QUIC_GO_DISABLE_GSO=true \
  "${AUTOCAR_BIN}" server \
  --listen="${SERVER_IP}:${RENO_RELAY_PORT}" \
  --tcp-listen="${SERVER_IP}:${RENO_RELAY_PORT}" \
  --cert="${WORK_DIR}/server.crt" \
  --key="${WORK_DIR}/server.key" \
  --token-file="${WORK_DIR}/relay-token" \
  --congestion=reno \
  --allow-private --deny-ports=none
RENO_RELAY_PID=${STARTED_PID}
wait_for_log "${RENO_RELAY_PID}" "${ARTIFACT_DIR}/relay-reno.log" "transport=hy2"

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
TUNNEL_AUTH_BBR=(
  --server="${SERVER_IP}:${BBR_RELAY_PORT}"
  --server-name="${SERVER_IP}"
  --ca="${WORK_DIR}/server.crt"
  --token-file="${WORK_DIR}/relay-token"
  --dial-timeout=3s
  --open-timeout=5s
)

run_client --transport=direct "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/direct.json"
run_client --transport=quic "${TUNNEL_AUTH[@]}" "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/quic.json"
run_client --transport=tls "${TUNNEL_AUTH[@]}" "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/tls.json"

# Use a separately declared, deterministic controller profile. The bulk stage
# intentionally observes random loss; controller A/B instead drops every Nth
# large sender datagram and resets the matcher before every run. That gives BBR
# and Reno the same repeatable loss sequence. Two warmups and five measured
# transfers span multiple recovery epochs. This is a narrow regression
# scenario, not a universal speed claim.
ip netns exec "${CLIENT_NS}" tc qdisc replace dev "${CLIENT_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000
ip netns exec "${SERVER_NS}" tc qdisc replace dev "${SERVER_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000
ip netns exec "${CLIENT_NS}" iptables -N "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${CLIENT_NS}" iptables -I INPUT 1 -j "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -N "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -I INPUT 1 -j "${CONTROLLER_LOSS_CHAIN}"

# Prove both controller paths with real authenticated transfers. The BBR run
# declares no bandwidth and therefore must negotiate a zero Tx rate. The
# Brutal run declares 20 Mbit/s in both directions, while the relay's 15
# Mbit/s upload cap deterministically limits client-to-relay Tx to 1,875,000
# bytes/s. Repeated, warmed uploads isolate the client-side sender so the
# congestion flag deterministically selects the controller under comparison.
MODE_PROOF_BENCH=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=upload
  --bytes="${CONTROLLER_BYTES}"
  --iterations="${CONTROLLER_ITERATIONS}"
  --warmup="${CONTROLLER_WARMUP}"
  --timeout=60s
  --json
)
reset_upload_controller_loss
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/bbr.json"
snapshot_controller_loss "${SERVER_NS}" BBR_UPLOAD_DROPS BBR_UPLOAD_ELIGIBLE
reset_upload_controller_loss
run_controller_client --transport=quic --congestion=reno \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/reno.json"
snapshot_controller_loss "${SERVER_NS}" RENO_UPLOAD_DROPS RENO_UPLOAD_ELIGIBLE
reset_upload_controller_loss
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  --upload-mbps="${BRUTAL_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${BRUTAL_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/brutal.json"
snapshot_controller_loss "${SERVER_NS}" BRUTAL_UPLOAD_DROPS BRUTAL_UPLOAD_ELIGIBLE
ip netns exec "${SERVER_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"

# Repeat the BBR/Reno proof in the opposite direction. Both clients use the
# same configuration; only the relay sender differs (default BBR vs the
# explicitly configured Reno relay above).
MODE_PROOF_DOWNLOAD=(
  --target="${SERVER_IP}:${BENCH_PORT}"
  --mode=download
  --bytes="${CONTROLLER_BYTES}"
  --iterations="${CONTROLLER_ITERATIONS}"
  --warmup="${CONTROLLER_WARMUP}"
  --timeout=60s
  --json
)
# Reverse the BBR/Reno order for relay-sender downloads to reduce monotonic
# host-load bias without sharing controller state between runs. Brutal follows
# each direction's paired comparison and is judged against its own rate window.
reset_download_controller_loss "${RENO_RELAY_PORT}"
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  "${TUNNEL_AUTH_RENO[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/reno-download.json"
snapshot_controller_loss "${CLIENT_NS}" RENO_DOWNLOAD_DROPS RENO_DOWNLOAD_ELIGIBLE
reset_download_controller_loss "${BBR_RELAY_PORT}"
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  "${TUNNEL_AUTH_BBR[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/bbr-download.json"
snapshot_controller_loss "${CLIENT_NS}" BBR_DOWNLOAD_DROPS BBR_DOWNLOAD_ELIGIBLE
reset_download_controller_loss "${RELAY_PORT}"
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  --upload-mbps="${BRUTAL_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${BRUTAL_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/brutal-download.json"
snapshot_controller_loss "${CLIENT_NS}" BRUTAL_DOWNLOAD_DROPS BRUTAL_DOWNLOAD_ELIGIBLE
ip netns exec "${CLIENT_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"

# This intentionally narrow acceleration profile isolates the benefit of a
# warm, shared congestion-control context. Every direct iteration creates a
# fresh TCP flow across a high-RTT path; sequential QUIC streams reuse the
# connection warmed by the declared warmup iterations. Loss is disabled for
# this profile so random recovery events do not dominate its CI acceptance.
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
sleep 0.3
kill -0 "${ORIGIN_PID}"

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
ip netns exec "${SERVER_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
  -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" -j DROP
ip netns exec "${CLIENT_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${CLIENT_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
  -p udp -s "${SERVER_IP}" --sport "${RELAY_PORT}" -d "${CLIENT_IP}" -j DROP

FALLBACK_CAPTURE_FILE="${ARTIFACT_DIR}/tls-fallback.pcap"
start_background "${ARTIFACT_DIR}/fallback-tcpdump.log" \
  ip netns exec "${CLIENT_NS}" tcpdump --immediate-mode -i "${CLIENT_DEV}" -s 0 -U -w "${FALLBACK_CAPTURE_FILE}" \
  "host ${SERVER_IP} and (udp port ${RELAY_PORT} or tcp port ${RELAY_PORT})"
CAPTURE_PID=${STARTED_PID}
wait_for_log "${CAPTURE_PID}" "${ARTIFACT_DIR}/fallback-tcpdump.log" "listening on"

FALLBACK_START=${SECONDS}
FALLBACK_RESPONSE=$(ip netns exec "${CLIENT_NS}" env \
  -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY -u no_proxy \
  curl --fail --silent --show-error --max-time 10 --noproxy '' \
  --header 'Connection: close' \
  --proxy "http://127.0.0.1:${PROXY_PORT}" \
  "http://${SERVER_IP}:${ORIGIN_PORT}/sentinel.txt")
FALLBACK_ELAPSED=$((SECONDS - FALLBACK_START))
if [[ ${FALLBACK_RESPONSE} != "${SENTINEL}" ]]; then
  echo "error: auto/TLS fallback proxy response did not match the sentinel" >&2
  exit 1
fi
if (( FALLBACK_ELAPSED > 10 )); then
  echo "error: auto/TLS fallback exceeded the 10-second bound" >&2
  exit 1
fi
if (( FALLBACK_ELAPSED < 1 )); then
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
  -L "${CONTROLLER_LOSS_CHAIN}" --verbose --numeric --exact --line-numbers \
  >"${ARTIFACT_DIR}/iptables-live-blackhole.txt"
LIVE_UPSTREAM_DROPS=$(awk '
  $4 == "DROP" { dropped += $2 }
  END { printf "%.0f%c", dropped, 10 }
' "${ARTIFACT_DIR}/iptables-live-blackhole.txt")
if ! [[ ${LIVE_UPSTREAM_DROPS} =~ ^[0-9]+$ ]] || (( LIVE_UPSTREAM_DROPS == 0 )); then
  echo "error: silent UDP blackhole did not drop an upstream datagram" >&2
  exit 1
fi
if grep -Fqi 'operation not permitted' "${ARTIFACT_DIR}/client-proxy.log"; then
  echo "error: live-path fallback was triggered by local sendmsg EPERM" >&2
  exit 1
fi
if ! grep -Eiq 'deadline exceeded|timed out|timeout' "${ARTIFACT_DIR}/client-proxy.log"; then
  echo "error: live-path fallback did not report a timeout-class QUIC failure" >&2
  exit 1
fi
if grep -aFq "${SENTINEL}" "${QUIC_CAPTURE_FILE}" || \
   grep -aFq "${SENTINEL}" "${FALLBACK_CAPTURE_FILE}"; then
  echo "error: plaintext sentinel was visible on a tunnel link" >&2
  exit 1
fi

python3 - "${ARTIFACT_DIR}/direct.json" "${ARTIFACT_DIR}/quic.json" \
  "${ARTIFACT_DIR}/tls.json" "${ARTIFACT_DIR}/short-direct.json" \
  "${ARTIFACT_DIR}/short-quic.json" "${ARTIFACT_DIR}/bbr.json" \
  "${ARTIFACT_DIR}/reno.json" "${ARTIFACT_DIR}/brutal.json" \
  "${ARTIFACT_DIR}/bbr-download.json" "${ARTIFACT_DIR}/reno-download.json" \
  "${ARTIFACT_DIR}/brutal-download.json" "${ARTIFACT_DIR}/summary.json" \
  "${DELAY_MS}" "${LOSS}" "${RATE}" "${IPTABLES_VERSION}" \
  "${CONTROLLER_DROP_EVERY}" \
  "${CONTROLLER_BYTES}" "${CONTROLLER_ITERATIONS}" \
  "${CONTROLLER_WARMUP}" "${SHORT_FLOW_BYTES}" \
  "${MIN_SHORT_FLOW_RATIO}" "${MIN_BBR_RENO_RATIO}" \
  "${MIN_BRUTAL_TARGET_RATIO}" "${MAX_BRUTAL_TARGET_RATIO}" \
  "${BRUTAL_SERVER_UPLOAD_MBPS}" \
  "${BRUTAL_SERVER_DOWNLOAD_MBPS}" "${BRUTAL_CLIENT_UPLOAD_MBPS}" \
  "${BRUTAL_CLIENT_DOWNLOAD_MBPS}" "${BRUTAL_EXPECTED_TX_BYTES_SEC}" \
  "${BBR_UPLOAD_DROPS}" "${BBR_UPLOAD_ELIGIBLE}" \
  "${RENO_UPLOAD_DROPS}" "${RENO_UPLOAD_ELIGIBLE}" \
  "${BRUTAL_UPLOAD_DROPS}" "${BRUTAL_UPLOAD_ELIGIBLE}" \
  "${BBR_DOWNLOAD_DROPS}" "${BBR_DOWNLOAD_ELIGIBLE}" \
  "${RENO_DOWNLOAD_DROPS}" "${RENO_DOWNLOAD_ELIGIBLE}" \
  "${BRUTAL_DOWNLOAD_DROPS}" "${BRUTAL_DOWNLOAD_ELIGIBLE}" \
  "${LIVE_UPSTREAM_DROPS}" <<'PY'
import json
import pathlib
import sys

if len(sys.argv) != 44:
    raise SystemExit(
        f"internal netem summary argument mismatch: got {len(sys.argv) - 1}, want 43"
    )

(
    direct_path,
    quic_path,
    tls_path,
    short_direct_path,
    short_quic_path,
    bbr_path,
    reno_path,
    brutal_path,
    bbr_download_path,
    reno_download_path,
    brutal_download_path,
    output_path,
) = map(
    pathlib.Path, sys.argv[1:13]
)
(
    delay_ms,
    loss,
    rate,
    iptables_version,
    controller_drop_every,
    controller_bytes,
    controller_iterations,
    controller_warmup,
    short_flow_bytes,
    minimum_ratio,
    minimum_bbr_reno_ratio,
    minimum_brutal_target_ratio,
    maximum_brutal_target_ratio,
    server_upload_mbps,
    server_download_mbps,
    client_upload_mbps,
    client_download_mbps,
    expected_brutal_tx,
    bbr_upload_drops,
    bbr_upload_eligible,
    reno_upload_drops,
    reno_upload_eligible,
    brutal_upload_drops,
    brutal_upload_eligible,
    bbr_download_drops,
    bbr_download_eligible,
    reno_download_drops,
    reno_download_eligible,
    brutal_download_drops,
    brutal_download_eligible,
    live_upstream_drops,
) = sys.argv[13:44]
direct = json.loads(direct_path.read_text())
quic = json.loads(quic_path.read_text())
tls = json.loads(tls_path.read_text())
short_direct = json.loads(short_direct_path.read_text())
short_quic = json.loads(short_quic_path.read_text())
bbr = json.loads(bbr_path.read_text())
reno = json.loads(reno_path.read_text())
brutal = json.loads(brutal_path.read_text())
bbr_download = json.loads(bbr_download_path.read_text())
reno_download = json.loads(reno_download_path.read_text())
brutal_download = json.loads(brutal_download_path.read_text())

minimum_ratio = float(minimum_ratio)
minimum_bbr_reno_ratio = float(minimum_bbr_reno_ratio)
minimum_brutal_target_ratio = float(minimum_brutal_target_ratio)
maximum_brutal_target_ratio = float(maximum_brutal_target_ratio)
if minimum_ratio <= 0 or minimum_bbr_reno_ratio <= 0:
    raise SystemExit("BBR/Reno and warm-payload acceptance ratios must be positive")
if not 0 < minimum_brutal_target_ratio <= maximum_brutal_target_ratio:
    raise SystemExit(
        "Brutal acceptance ratios must satisfy 0 < minimum <= maximum"
    )

loss_observations = {
    "bbr_upload": (int(bbr_upload_drops), int(bbr_upload_eligible)),
    "reno_upload": (int(reno_upload_drops), int(reno_upload_eligible)),
    "brutal_upload": (int(brutal_upload_drops), int(brutal_upload_eligible)),
    "bbr_download": (int(bbr_download_drops), int(bbr_download_eligible)),
    "reno_download": (int(reno_download_drops), int(reno_download_eligible)),
    "brutal_download": (
        int(brutal_download_drops),
        int(brutal_download_eligible),
    ),
}

for name, (dropped, eligible) in loss_observations.items():
    if dropped <= 0 or eligible <= 0:
        raise SystemExit(
            f"{name} deterministic-loss rule matched {eligible} and dropped {dropped}; "
            "the controller gate did not exercise loss"
        )
    expected_drops = eligible // int(controller_drop_every)
    if dropped != expected_drops:
        raise SystemExit(
            f"{name} deterministic-loss counters report {dropped}/{eligible}, "
            f"want exactly floor(eligible/{int(controller_drop_every)})={expected_drops}"
        )


def require_comparable_loss_volume(name, left, right):
    allowed_delta = max(2, int(max(left, right) * 0.02 + 0.999))
    if abs(left - right) > allowed_delta:
        raise SystemExit(
            f"{name} eligible packet counts {left} and {right} differ by more than "
            f"the allowed {allowed_delta}; controller loss inputs are not comparable"
        )


require_comparable_loss_volume(
    "BBR/Reno upload",
    loss_observations["bbr_upload"][1],
    loss_observations["reno_upload"][1],
)
require_comparable_loss_volume(
    "BBR/Reno download",
    loss_observations["bbr_download"][1],
    loss_observations["reno_download"][1],
)

for name, result, transport in (
    ("direct", direct, "direct"),
    ("quic", quic, "quic"),
    ("tls", tls, "tls"),
):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} benchmark reported non-positive goodput")
    if result.get("mode") != "download" or result.get("transport") != transport:
        raise SystemExit(
            f"{name} benchmark metadata reported mode={result.get('mode')!r}, "
            f"transport={result.get('transport')!r}"
        )
for name, result, transport in (
    ("short direct", short_direct, "direct"),
    ("short quic", short_quic, "quic"),
):
    if result.get("mode") != "download" or result.get("transport") != transport:
        raise SystemExit(f"{name} benchmark has incorrect mode or transport metadata")
    if result.get("bytes_per_iteration") != int(short_flow_bytes):
        raise SystemExit(
            f"{name} benchmark used {result.get('bytes_per_iteration')!r} bytes, "
            f"want {int(short_flow_bytes)}"
        )
for name, result in (("bbr", bbr), ("reno", reno), ("brutal", brutal)):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} controller proof reported non-positive goodput")
for name, result in (
    ("bbr download", bbr_download),
    ("reno download", reno_download),
    ("brutal download", brutal_download),
):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} controller proof reported non-positive goodput")

for name, result in (
    ("bbr", bbr),
    ("reno", reno),
    ("brutal", brutal),
    ("bbr download", bbr_download),
    ("reno download", reno_download),
    ("brutal download", brutal_download),
):
    if result.get("bytes_per_iteration") != int(controller_bytes):
        raise SystemExit(
            f"{name} proof used {result.get('bytes_per_iteration')!r} bytes, "
            f"want {int(controller_bytes)}"
        )
    if result.get("iterations") != int(controller_iterations):
        raise SystemExit(
            f"{name} proof used {result.get('iterations')!r} iterations, "
            f"want {int(controller_iterations)}"
        )


def aggregate_goodput(name, result):
    """Return total equal-size bytes divided by total measured elapsed time."""
    values = result.get("results_mbps")
    if not isinstance(values, list) or len(values) != int(controller_iterations):
        raise SystemExit(
            f"{name} proof has {len(values) if isinstance(values, list) else 'invalid'} "
            f"raw results, want {int(controller_iterations)}"
        )
    if any(not isinstance(value, (int, float)) or value <= 0 for value in values):
        raise SystemExit(f"{name} proof contains a non-positive raw goodput value")
    # Every transfer has the same byte count, so this harmonic mean is exactly
    # aggregate goodput: total bytes divided by total transfer time.
    return len(values) / sum(1.0 / value for value in values)


bbr_aggregate_mbps = aggregate_goodput("bbr", bbr)
reno_aggregate_mbps = aggregate_goodput("reno", reno)
brutal_aggregate_mbps = aggregate_goodput("brutal", brutal)
bbr_download_aggregate_mbps = aggregate_goodput("bbr download", bbr_download)
reno_download_aggregate_mbps = aggregate_goodput("reno download", reno_download)
brutal_download_aggregate_mbps = aggregate_goodput(
    "brutal download", brutal_download
)

for name, result, mode, sender in (
    ("bbr", bbr, "upload", "client"),
    ("reno", reno, "upload", "client"),
    ("brutal", brutal, "upload", "client"),
    ("bbr download", bbr_download, "download", "relay"),
    ("reno download", reno_download, "download", "relay"),
    ("brutal download", brutal_download, "download", "relay"),
):
    if result.get("mode") != mode or result.get("transport") != "quic":
        raise SystemExit(
            f"{name} metadata reported mode={result.get('mode')!r}, "
            f"transport={result.get('transport')!r}; want {mode!r}, 'quic'"
        )
    if result.get("tunnel_sender_endpoint") != sender:
        raise SystemExit(
            f"{name} reported tunnel sender "
            f"{result.get('tunnel_sender_endpoint')!r}, want {sender!r}"
        )

if bbr.get("payload_sender_acceleration") != "bbr-standard":
    raise SystemExit(
        "BBR upload proof reported payload sender acceleration="
        f"{bbr.get('payload_sender_acceleration')!r}, "
        "want 'bbr-standard'"
    )
if bbr.get("payload_sender_negotiated_tx_bytes_per_second", 0) != 0:
    raise SystemExit(
        "BBR proof unexpectedly negotiated a non-zero Tx bandwidth: "
        f"{bbr.get('payload_sender_negotiated_tx_bytes_per_second')!r}"
    )
if reno.get("payload_sender_acceleration") != "reno":
    raise SystemExit(
        "Reno upload proof reported payload sender acceleration="
        f"{reno.get('payload_sender_acceleration')!r}, "
        "want 'reno'"
    )
if reno.get("payload_sender_negotiated_tx_bytes_per_second", 0) != 0:
    raise SystemExit(
        "Reno proof unexpectedly negotiated a non-zero Tx bandwidth: "
        f"{reno.get('payload_sender_negotiated_tx_bytes_per_second')!r}"
    )

for name, result in (("bbr download", bbr_download), ("reno download", reno_download)):
    if result.get("local_tx_acceleration") != "bbr-standard":
        raise SystemExit(
            f"{name} local client Tx metadata changed unexpectedly: "
            f"{result.get('local_tx_acceleration')!r}"
        )
    if result.get("payload_sender_acceleration") is not None:
        raise SystemExit(
            f"{name} falsely attributed the client's controller to the relay sender"
        )

bbr_reno_ratio = bbr_aggregate_mbps / reno_aggregate_mbps
if bbr_reno_ratio < minimum_bbr_reno_ratio:
    raise SystemExit(
        f"deterministic-loss BBR/Reno upload aggregate-goodput ratio "
        f"{bbr_reno_ratio:.3f} is below "
        f"the declared acceptance threshold {minimum_bbr_reno_ratio:.3f}"
    )

bbr_reno_download_ratio = (
    bbr_download_aggregate_mbps / reno_download_aggregate_mbps
)
if bbr_reno_download_ratio < minimum_bbr_reno_ratio:
    raise SystemExit(
        f"deterministic-loss BBR/Reno download aggregate-goodput ratio "
        f"{bbr_reno_download_ratio:.3f} is below "
        f"the declared acceptance threshold {minimum_bbr_reno_ratio:.3f}"
    )

expected_brutal_tx = int(expected_brutal_tx)
if brutal.get("payload_sender_acceleration") != "brutal":
    raise SystemExit(
        "Brutal upload proof reported payload sender acceleration="
        f"{brutal.get('payload_sender_acceleration')!r}, "
        "want 'brutal'"
    )
if brutal.get("payload_sender_negotiated_tx_bytes_per_second") != expected_brutal_tx:
    raise SystemExit(
        "Brutal proof negotiated Tx bandwidth "
        f"{brutal.get('payload_sender_negotiated_tx_bytes_per_second')!r}, "
        f"want {expected_brutal_tx} bytes/s"
    )
if brutal_download.get("local_tx_acceleration") != "brutal":
    raise SystemExit("Brutal download handshake did not negotiate client-side Brutal")
if brutal_download.get("payload_sender_acceleration") is not None:
    raise SystemExit(
        "Brutal download falsely attributed the client's controller to the relay sender"
    )
brutal_target_mbps = expected_brutal_tx * 8 / 1_000_000
brutal_target_ratio = brutal_aggregate_mbps / brutal_target_mbps
brutal_download_target_ratio = (
    brutal_download_aggregate_mbps / brutal_target_mbps
)
for direction, ratio in (
    ("upload", brutal_target_ratio),
    ("download", brutal_download_target_ratio),
):
    if ratio < minimum_brutal_target_ratio:
        raise SystemExit(
            f"Brutal {direction} achieved/target ratio {ratio:.3f} is below "
            f"the declared minimum {minimum_brutal_target_ratio:.3f}"
        )
    if ratio > maximum_brutal_target_ratio:
        raise SystemExit(
            f"Brutal {direction} achieved/target ratio {ratio:.3f} is above "
            f"the declared maximum {maximum_brutal_target_ratio:.3f}; "
            "the fixed-rate controller may not be active"
        )

short_ratio = short_quic["median_mbps"] / short_direct["median_mbps"]
if short_ratio < minimum_ratio:
    raise SystemExit(
        f"warm-QUIC payload-phase ratio {short_ratio:.3f} is below "
        f"the declared acceptance threshold {minimum_ratio:.3f}"
    )

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
    "controller_proof": {
        "network_profile": {
            "one_way_delay_ms": int(delay_ms),
            "rate_each_direction": rate,
            "random_loss_each_direction": "0%",
            "loss_hook": "receiver INPUT",
            "receiver_input_large_udp_drop_every": int(controller_drop_every),
            "actual_loss": {
                name: {
                    "eligible_packets": eligible,
                    "dropped_packets": dropped,
                    "drop_rate": dropped / eligible,
                }
                for name, (dropped, eligible) in loss_observations.items()
            },
            "bytes_per_iteration": int(controller_bytes),
            "measured_iterations": int(controller_iterations),
            "warmup_iterations": int(controller_warmup),
        },
        "bbr": {
            "artifact": bbr_path.name,
            "sender_acceleration": bbr["payload_sender_acceleration"],
            "sender_negotiated_tx_bytes_per_second": bbr.get(
                "payload_sender_negotiated_tx_bytes_per_second", 0
            ),
            "median_mbps": bbr["median_mbps"],
            "aggregate_mbps": bbr_aggregate_mbps,
        },
        "reno": {
            "artifact": reno_path.name,
            "sender_acceleration": reno["payload_sender_acceleration"],
            "sender_negotiated_tx_bytes_per_second": reno.get(
                "payload_sender_negotiated_tx_bytes_per_second", 0
            ),
            "median_mbps": reno["median_mbps"],
            "aggregate_mbps": reno_aggregate_mbps,
        },
        "comparison_metric": "equal-byte aggregate goodput (harmonic mean of per-transfer Mbit/s)",
        "bbr_to_reno_ratio": bbr_reno_ratio,
        "bbr_to_reno_aggregate_ratio": bbr_reno_ratio,
        "relay_sender_download": {
            "bbr_configured_sender_acceleration": "bbr-standard",
            "reno_configured_sender_acceleration": "reno",
            "bbr_artifact": bbr_download_path.name,
            "reno_artifact": reno_download_path.name,
            "bbr_median_mbps": bbr_download["median_mbps"],
            "reno_median_mbps": reno_download["median_mbps"],
            "bbr_aggregate_mbps": bbr_download_aggregate_mbps,
            "reno_aggregate_mbps": reno_download_aggregate_mbps,
            "bbr_to_reno_ratio": bbr_reno_download_ratio,
            "bbr_to_reno_aggregate_ratio": bbr_reno_download_ratio,
            "minimum_accepted_bbr_to_reno_ratio": minimum_bbr_reno_ratio,
        },
        "minimum_accepted_bbr_to_reno_ratio": minimum_bbr_reno_ratio,
        "brutal": {
            "artifact": brutal_path.name,
            "sender_acceleration": brutal["payload_sender_acceleration"],
            "sender_negotiated_tx_bytes_per_second": brutal[
                "payload_sender_negotiated_tx_bytes_per_second"
            ],
            "median_mbps": brutal["median_mbps"],
            "aggregate_mbps": brutal_aggregate_mbps,
            "target_mbps": brutal_target_mbps,
            "achieved_to_target_ratio": brutal_target_ratio,
            "minimum_accepted_target_ratio": minimum_brutal_target_ratio,
            "maximum_accepted_target_ratio": maximum_brutal_target_ratio,
            "relay_sender_download": {
                "artifact": brutal_download_path.name,
                "configured_sender_acceleration": "brutal",
                "aggregate_mbps": brutal_download_aggregate_mbps,
                "target_mbps": brutal_target_mbps,
                "achieved_to_target_ratio": brutal_download_target_ratio,
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
        "minimum_accepted_ratio": minimum_ratio,
    },
    "security_smoke": {
        "wrong_ca_rejected": True,
        "wrong_token_rejected": True,
        "plaintext_sentinel_absent_from_tunnel_capture": True,
        "auto_initial_quic_request_succeeded": True,
        "auto_tls_request_after_silent_udp_blackhole_succeeded": True,
        "silent_blackhole_receiver_input_udp_drops": int(live_upstream_drops),
        "quic_timeout_class_failure_observed": True,
        "sendmsg_eperm_absent": True,
    },
}
output_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

echo "netem integration passed"
echo "results: ${ARTIFACT_DIR}/summary.json"
