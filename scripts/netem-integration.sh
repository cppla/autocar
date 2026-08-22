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
UNUSED_QUIC_PORT=7444
BENCH_PORT=9000
ORIGIN_PORT=9080
PROXY_PORT=18080
WORK_DIR=$(mktemp -d -t autocar-netem.XXXXXX)

DELAY_MS=${AUTOCAR_NETEM_DELAY_MS:-35}
LOSS=${AUTOCAR_NETEM_LOSS:-0.5%}
RATE=${AUTOCAR_NETEM_RATE:-50mbit}
BENCH_BYTES=${AUTOCAR_BENCH_BYTES:-1048576}
BENCH_ITERATIONS=${AUTOCAR_BENCH_ITERATIONS:-5}
BENCH_WARMUP=${AUTOCAR_BENCH_WARMUP:-1}
SHORT_FLOW_BYTES=${AUTOCAR_SHORT_FLOW_BYTES:-131072}
SHORT_FLOW_ITERATIONS=${AUTOCAR_SHORT_FLOW_ITERATIONS:-9}
SHORT_FLOW_WARMUP=${AUTOCAR_SHORT_FLOW_WARMUP:-3}
MIN_SHORT_FLOW_RATIO=${AUTOCAR_MIN_SHORT_FLOW_RATIO:-1.10}

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
  --allow-private --deny-ports=none
RELAY_PID=${STARTED_PID}
wait_for_log "${RELAY_PID}" "${ARTIFACT_DIR}/relay.log" "transport=quic"
wait_for_log "${RELAY_PID}" "${ARTIFACT_DIR}/relay.log" "transport=tls"

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

run_client --transport=direct "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/direct.json"
run_client --transport=quic "${TUNNEL_AUTH[@]}" "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/quic.json"
run_client --transport=tls "${TUNNEL_AUTH[@]}" "${COMMON_BENCH[@]}" >"${ARTIFACT_DIR}/tls.json"

run_client --transport=auto \
  --server="${SERVER_IP}:${UNUSED_QUIC_PORT}" \
  --fallback-server="${SERVER_IP}:${RELAY_PORT}" \
  --server-name="${SERVER_IP}" \
  --ca="${WORK_DIR}/server.crt" \
  --token-file="${WORK_DIR}/relay-token" \
  --dial-timeout=1s --quic-attempt-timeout=1s --open-timeout=5s \
  --target="${SERVER_IP}:${BENCH_PORT}" --mode=download \
  --bytes=131072 --iterations=2 --warmup=0 --timeout=20s --json \
  >"${ARTIFACT_DIR}/auto-fallback.json"

# This intentionally narrow acceleration profile isolates the benefit of a
# warm, shared congestion-control context. Every direct iteration creates a
# fresh TCP flow across a high-RTT path; sequential QUIC streams reuse the
# connection warmed by the declared warmup iterations. Loss is disabled for
# this profile so random recovery events do not dominate its CI acceptance.
ip netns exec "${CLIENT_NS}" tc qdisc replace dev "${CLIENT_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000
ip netns exec "${SERVER_NS}" tc qdisc replace dev "${SERVER_DEV}" root netem \
  delay "${DELAY_MS}ms" rate "${RATE}" limit 10000

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
  --dial-timeout=1s --quic-attempt-timeout=1s --open-timeout=2s \
  --socks= --http="127.0.0.1:${PROXY_PORT}" --https=
PROXY_PID=${STARTED_PID}
wait_for_log "${PROXY_PID}" "${ARTIFACT_DIR}/client-proxy.log" "local proxy started"

QUIC_CAPTURE_FILE="${ARTIFACT_DIR}/quic-tunnel.pcap"
start_background "${ARTIFACT_DIR}/tcpdump.log" \
  ip netns exec "${CLIENT_NS}" tcpdump -i "${CLIENT_DEV}" -s 0 -U -w "${QUIC_CAPTURE_FILE}" \
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
  ip netns exec "${CLIENT_NS}" tcpdump -i "${CLIENT_DEV}" -s 0 -U -w "${FALLBACK_CAPTURE_FILE}" \
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
  "${ARTIFACT_DIR}/short-quic.json" "${ARTIFACT_DIR}/summary.json" \
  "${DELAY_MS}" "${LOSS}" "${RATE}" "${SHORT_FLOW_BYTES}" \
  "${MIN_SHORT_FLOW_RATIO}" <<'PY'
import json
import pathlib
import sys

direct_path, quic_path, tls_path, short_direct_path, short_quic_path, output_path = map(
    pathlib.Path, sys.argv[1:7]
)
delay_ms, loss, rate, short_flow_bytes, minimum_ratio = sys.argv[7:12]
direct = json.loads(direct_path.read_text())
quic = json.loads(quic_path.read_text())
tls = json.loads(tls_path.read_text())
short_direct = json.loads(short_direct_path.read_text())
short_quic = json.loads(short_quic_path.read_text())

for name, result in (("direct", direct), ("quic", quic), ("tls", tls)):
    if result["median_mbps"] <= 0:
        raise SystemExit(f"{name} benchmark reported non-positive goodput")

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
