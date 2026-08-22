#!/usr/bin/env bash
set -Eeuo pipefail

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

for command in ip tc iptables tcpdump curl python3 grep readlink; do
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
MIN_BRUTAL_TARGET_RATIO=${AUTOCAR_MIN_BRUTAL_TARGET_RATIO:-0.50}
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

reset_client_controller_loss() {
  ip netns exec "${CLIENT_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"
  # xt_statistic stores --every N as N-1; --packet 0 therefore makes the first
  # drop the Nth match. Using N-1 would drop the first QUIC Initial instead.
  ip netns exec "${CLIENT_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
    -p udp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${RELAY_PORT}" \
    -m length --length 1000:65535 \
    -m statistic --mode nth --every "${CONTROLLER_DROP_EVERY}" \
    --packet 0 -j DROP
}

reset_server_controller_loss() {
  local source_port=$1
  ip netns exec "${SERVER_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"
  ip netns exec "${SERVER_NS}" iptables -A "${CONTROLLER_LOSS_CHAIN}" \
    -p udp -s "${SERVER_IP}" --sport "${source_port}" -d "${CLIENT_IP}" \
    -m length --length 1000:65535 \
    -m statistic --mode nth --every "${CONTROLLER_DROP_EVERY}" \
    --packet 0 -j DROP
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
  ip netns exec "${SERVER_NS}" "${AUTOCAR_BIN}" server \
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
ip netns exec "${CLIENT_NS}" iptables -I OUTPUT 1 -j "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -N "${CONTROLLER_LOSS_CHAIN}"
ip netns exec "${SERVER_NS}" iptables -I OUTPUT 1 -j "${CONTROLLER_LOSS_CHAIN}"

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
reset_client_controller_loss
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/bbr.json"
reset_client_controller_loss
run_controller_client --transport=quic --congestion=reno \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/reno.json"
reset_client_controller_loss
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  --upload-mbps="${BRUTAL_CLIENT_UPLOAD_MBPS}" \
  --download-mbps="${BRUTAL_CLIENT_DOWNLOAD_MBPS}" \
  "${TUNNEL_AUTH[@]}" "${MODE_PROOF_BENCH[@]}" \
  >"${ARTIFACT_DIR}/brutal.json"
ip netns exec "${CLIENT_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"

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
# Use BBR/Reno/Reno/BBR ordering across the two directions to reduce monotonic
# host-load bias without sharing controller state between runs.
reset_server_controller_loss "${RENO_RELAY_PORT}"
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  "${TUNNEL_AUTH_RENO[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/reno-download.json"
reset_server_controller_loss "${BBR_RELAY_PORT}"
run_controller_client --transport=quic --congestion=bbr --bbr-profile=standard \
  "${TUNNEL_AUTH_BBR[@]}" "${MODE_PROOF_DOWNLOAD[@]}" \
  >"${ARTIFACT_DIR}/bbr-download.json"
ip netns exec "${SERVER_NS}" iptables -F "${CONTROLLER_LOSS_CHAIN}"

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

# Drop the established client's UDP path only after a successful QUIC request.
# A new proxy flow must detect the broken connection, open the circuit breaker,
# and complete over the same relay's TCP/TLS listener within curl's deadline.
ip netns exec "${CLIENT_NS}" iptables -I OUTPUT 1 -p udp \
  -d "${SERVER_IP}" --dport "${RELAY_PORT}" -j DROP

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

sleep 0.5
kill -INT "${CAPTURE_PID}" >/dev/null 2>&1 || true
wait "${CAPTURE_PID}" >/dev/null 2>&1 || true
if ! tcpdump -nn -r "${FALLBACK_CAPTURE_FILE}" "tcp port ${RELAY_PORT}" 2>/dev/null | grep . >/dev/null; then
  echo "error: request after UDP loss did not use the TCP/TLS fallback" >&2
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
  "${ARTIFACT_DIR}/summary.json" \
  "${DELAY_MS}" "${LOSS}" "${RATE}" "${CONTROLLER_DROP_EVERY}" \
  "${CONTROLLER_BYTES}" "${CONTROLLER_ITERATIONS}" \
  "${CONTROLLER_WARMUP}" "${SHORT_FLOW_BYTES}" \
  "${MIN_SHORT_FLOW_RATIO}" "${MIN_BBR_RENO_RATIO}" \
  "${MIN_BRUTAL_TARGET_RATIO}" "${BRUTAL_SERVER_UPLOAD_MBPS}" \
  "${BRUTAL_SERVER_DOWNLOAD_MBPS}" "${BRUTAL_CLIENT_UPLOAD_MBPS}" \
  "${BRUTAL_CLIENT_DOWNLOAD_MBPS}" "${BRUTAL_EXPECTED_TX_BYTES_SEC}" <<'PY'
import json
import pathlib
import sys

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
    output_path,
) = map(
    pathlib.Path, sys.argv[1:12]
)
(
    delay_ms,
    loss,
    rate,
    controller_drop_every,
    controller_bytes,
    controller_iterations,
    controller_warmup,
    short_flow_bytes,
    minimum_ratio,
    minimum_bbr_reno_ratio,
    minimum_brutal_target_ratio,
    server_upload_mbps,
    server_download_mbps,
    client_upload_mbps,
    client_download_mbps,
    expected_brutal_tx,
) = sys.argv[12:28]
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

for name, result in (("direct", direct), ("quic", quic), ("tls", tls)):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} benchmark reported non-positive goodput")
for name, result in (("bbr", bbr), ("reno", reno), ("brutal", brutal)):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} controller proof reported non-positive goodput")
for name, result in (("bbr download", bbr_download), ("reno download", reno_download)):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} controller proof reported non-positive goodput")

for name, result in (
    ("bbr", bbr),
    ("reno", reno),
    ("brutal", brutal),
    ("bbr download", bbr_download),
    ("reno download", reno_download),
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

if bbr.get("acceleration") != "bbr-standard":
    raise SystemExit(
        f"BBR proof reported acceleration={bbr.get('acceleration')!r}, "
        "want 'bbr-standard'"
    )
if bbr.get("negotiated_tx_bytes_per_second", 0) != 0:
    raise SystemExit(
        "BBR proof unexpectedly negotiated a non-zero Tx bandwidth: "
        f"{bbr.get('negotiated_tx_bytes_per_second')!r}"
    )
if reno.get("acceleration") != "reno":
    raise SystemExit(
        f"Reno proof reported acceleration={reno.get('acceleration')!r}, "
        "want 'reno'"
    )
if reno.get("negotiated_tx_bytes_per_second", 0) != 0:
    raise SystemExit(
        "Reno proof unexpectedly negotiated a non-zero Tx bandwidth: "
        f"{reno.get('negotiated_tx_bytes_per_second')!r}"
    )

bbr_reno_ratio = bbr_aggregate_mbps / reno_aggregate_mbps
if bbr_reno_ratio < float(minimum_bbr_reno_ratio):
    raise SystemExit(
        f"deterministic-loss BBR/Reno upload aggregate-goodput ratio "
        f"{bbr_reno_ratio:.3f} is below "
        f"the declared acceptance threshold {float(minimum_bbr_reno_ratio):.3f}"
    )

bbr_reno_download_ratio = (
    bbr_download_aggregate_mbps / reno_download_aggregate_mbps
)
if bbr_reno_download_ratio < float(minimum_bbr_reno_ratio):
    raise SystemExit(
        f"deterministic-loss BBR/Reno download aggregate-goodput ratio "
        f"{bbr_reno_download_ratio:.3f} is below "
        f"the declared acceptance threshold {float(minimum_bbr_reno_ratio):.3f}"
    )

expected_brutal_tx = int(expected_brutal_tx)
if brutal.get("acceleration") != "brutal":
    raise SystemExit(
        f"Brutal proof reported acceleration={brutal.get('acceleration')!r}, "
        "want 'brutal'"
    )
if brutal.get("negotiated_tx_bytes_per_second") != expected_brutal_tx:
    raise SystemExit(
        "Brutal proof negotiated Tx bandwidth "
        f"{brutal.get('negotiated_tx_bytes_per_second')!r}, "
        f"want {expected_brutal_tx} bytes/s"
    )
brutal_target_mbps = expected_brutal_tx * 8 / 1_000_000
brutal_target_ratio = brutal_aggregate_mbps / brutal_target_mbps
if brutal_target_ratio < float(minimum_brutal_target_ratio):
    raise SystemExit(
        f"Brutal achieved/target ratio {brutal_target_ratio:.3f} is below "
        f"the declared acceptance threshold {float(minimum_brutal_target_ratio):.3f}"
    )

short_ratio = short_quic["median_mbps"] / short_direct["median_mbps"]
if short_ratio < float(minimum_ratio):
    raise SystemExit(
        f"warm-QUIC short-flow ratio {short_ratio:.3f} is below "
        f"the declared acceptance threshold {float(minimum_ratio):.3f}"
    )

summary = {
    "netem": {
        "one_way_delay_ms": int(delay_ms),
        "loss_each_direction": loss,
        "rate_each_direction": rate,
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
            "sender_large_udp_drop_every": int(controller_drop_every),
            "bytes_per_iteration": int(controller_bytes),
            "measured_iterations": int(controller_iterations),
            "warmup_iterations": int(controller_warmup),
        },
        "bbr": {
            "artifact": bbr_path.name,
            "acceleration": bbr["acceleration"],
            "negotiated_tx_bytes_per_second": bbr.get(
                "negotiated_tx_bytes_per_second", 0
            ),
            "median_mbps": bbr["median_mbps"],
            "aggregate_mbps": bbr_aggregate_mbps,
        },
        "reno": {
            "artifact": reno_path.name,
            "acceleration": reno["acceleration"],
            "negotiated_tx_bytes_per_second": reno.get(
                "negotiated_tx_bytes_per_second", 0
            ),
            "median_mbps": reno["median_mbps"],
            "aggregate_mbps": reno_aggregate_mbps,
        },
        "comparison_metric": "equal-byte aggregate goodput (harmonic mean of per-transfer Mbit/s)",
        "bbr_to_reno_ratio": bbr_reno_ratio,
        "bbr_to_reno_aggregate_ratio": bbr_reno_ratio,
        "relay_sender_download": {
            "bbr_artifact": bbr_download_path.name,
            "reno_artifact": reno_download_path.name,
            "bbr_median_mbps": bbr_download["median_mbps"],
            "reno_median_mbps": reno_download["median_mbps"],
            "bbr_aggregate_mbps": bbr_download_aggregate_mbps,
            "reno_aggregate_mbps": reno_download_aggregate_mbps,
            "bbr_to_reno_ratio": bbr_reno_download_ratio,
            "bbr_to_reno_aggregate_ratio": bbr_reno_download_ratio,
            "minimum_accepted_bbr_to_reno_ratio": float(minimum_bbr_reno_ratio),
        },
        "minimum_accepted_bbr_to_reno_ratio": float(minimum_bbr_reno_ratio),
        "brutal": {
            "artifact": brutal_path.name,
            "acceleration": brutal["acceleration"],
            "negotiated_tx_bytes_per_second": brutal[
                "negotiated_tx_bytes_per_second"
            ],
            "median_mbps": brutal["median_mbps"],
            "aggregate_mbps": brutal_aggregate_mbps,
            "target_mbps": brutal_target_mbps,
            "achieved_to_target_ratio": brutal_target_ratio,
            "minimum_accepted_target_ratio": float(minimum_brutal_target_ratio),
            "client_upload_mbps": int(client_upload_mbps),
            "client_download_mbps": int(client_download_mbps),
            "server_upload_cap_mbps": int(server_upload_mbps),
            "server_download_cap_mbps": int(server_download_mbps),
        },
    },
    "acceleration_profile": {
        "description": "sequential short downloads over a loss-free high-RTT path; QUIC uses declared warmups",
        "payload_bytes": int(short_flow_bytes),
        "one_way_delay_ms": int(delay_ms),
        "loss_each_direction": "0%",
        "rate_each_direction": rate,
        "direct_median_mbps": short_direct["median_mbps"],
        "quic_median_mbps": short_quic["median_mbps"],
        "quic_to_direct_ratio": short_ratio,
        "minimum_accepted_ratio": float(minimum_ratio),
    },
    "security_smoke": {
        "wrong_ca_rejected": True,
        "wrong_token_rejected": True,
        "plaintext_sentinel_absent_from_tunnel_capture": True,
        "auto_initial_quic_request_succeeded": True,
        "auto_tls_request_after_udp_drop_succeeded": True,
    },
}
output_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

echo "netem integration passed"
echo "results: ${ARTIFACT_DIR}/summary.json"
