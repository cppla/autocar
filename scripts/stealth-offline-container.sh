#!/bin/sh
set -eu
umask 077

# Reproducible, network-isolated wrapper for already captured campaign PCAPs.
# It never captures packets and refuses to overwrite an evidence directory.

usage() {
	cat >&2 <<'EOF'
usage: scripts/stealth-offline-container.sh CAPTURE_MANIFEST.csv NEW_OUTPUT_DIR

Build-time package access is permitted. Feature extraction, classification,
toolchain inspection, and audit generation all run with Docker --network none.
The input campaign is mounted read-only and only NEW_OUTPUT_DIR is writable.
EOF
}

[ "$#" -eq 2 ] || { usage; exit 2; }

invocation_dir=$(pwd -P)
manifest=$1
output=$2
case "$manifest" in /*) ;; *) manifest="$invocation_dir/$manifest" ;; esac
case "$output" in /*) ;; *) output="$invocation_dir/$output" ;; esac
case "$output" in ''|/) echo "refusing unsafe output directory" >&2; exit 2 ;; esac

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
dockerfile="$script_dir/stealth-offline.Dockerfile"
preregistration="$repo_root/testdata/stealth/preregistration.json"
docker_bin=${DOCKER_BIN:-docker}

for tool in "$docker_bin" dirname basename mkdir date id; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required command not found: $tool" >&2; exit 2; }
done
[ -f "$manifest" ] || { echo "capture manifest not found: $manifest" >&2; exit 2; }
[ -f "$dockerfile" ] || { echo "offline Dockerfile not found: $dockerfile" >&2; exit 2; }
[ -f "$preregistration" ] || { echo "preregistration not found: $preregistration" >&2; exit 2; }

manifest_dir=$(CDPATH='' cd -- "$(dirname "$manifest")" && pwd -P)
manifest_name=$(basename "$manifest")
manifest="$manifest_dir/$manifest_name"

if [ -e "$output" ]; then
	echo "refusing to overwrite existing evidence path: $output" >&2
	exit 2
fi
output_parent=$(dirname "$output")
mkdir -p "$output_parent"
output_parent=$(CDPATH='' cd -- "$output_parent" && pwd -P)
output="$output_parent/$(basename "$output")"
mkdir "$output"
output=$(CDPATH='' cd -- "$output" && pwd -P)

# Refuse SSH/TCP Docker endpoints before an image build or container run.
docker_context=$($docker_bin context show)
docker_endpoint=$($docker_bin context inspect "$docker_context" --format '{{ (index .Endpoints "docker").Host }}')
case "$docker_endpoint" in
	unix://*|npipe://*) ;;
	*) echo "remote Docker contexts are refused: $docker_endpoint" >&2; exit 2 ;;
esac

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_id="offline-${timestamp}-$$"
image="autocar-stealth-offline:$run_id"
label="com.cppla.autocar.stealth-offline=$run_id"

# This is the only network-enabled phase. The base manifest and direct apk
# packages are pinned in the Dockerfile, and the complete build log is kept.
$docker_bin build --pull=false --label "$label" \
	-f "$dockerfile" -t "$image" "$script_dir" \
	>"$output/image-build.log" 2>&1
image_id=$($docker_bin image inspect "$image" --format '{{.Id}}')

host_uid=$(id -u)
host_gid=$(id -g)
runtime_user="$host_uid:$host_gid"
if [ "$host_uid" -eq 0 ] || [ "$host_gid" -eq 0 ]; then
	runtime_user=65532:65532
	chown 65532:65532 "$output"
fi

run_offline() {
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --pids-limit 128 --memory 512m \
		--user "$runtime_user" --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
		-e PYTHONDONTWRITEBYTECODE=1 "$@"
}

run_offline --entrypoint /bin/sh "$image" -c \
	'python3 --version; tshark --version | sed -n "1,3p"; apk list --installed python3 tshark' \
	>"$output/toolchain.txt" 2>&1

set +e
run_offline \
	--mount "type=bind,src=$manifest_dir,dst=/input,readonly" \
	--mount "type=bind,src=$script_dir,dst=/tool,readonly" \
	--mount "type=bind,src=$output,dst=/output" \
	"$image" python3 /tool/stealth-features.py \
		--manifest "/input/$manifest_name" \
		--output /output/features.csv \
		--status-output /output/extraction.json \
	>"$output/extraction.stdout.json" 2>"$output/extraction.stderr.log"
extraction_exit=$?

classification_exit=not-run
if [ "$extraction_exit" -eq 0 ]; then
	run_offline \
		--mount "type=bind,src=$script_dir,dst=/tool,readonly" \
		--mount "type=bind,src=$preregistration,dst=/preregistration.json,readonly" \
		--mount "type=bind,src=$output,dst=/output" \
		"$image" python3 /tool/stealth-classify.py \
			--features /output/features.csv \
			--preregistration /preregistration.json \
			--output /output/scores.json \
		>"$output/classification.stdout.json" 2>"$output/classification.stderr.log"
	classification_exit=$?
fi
set -e

# Generate the audit inside the same network-none container. It independently
# checks path/content uniqueness, output lineage, absence of plaintext secret
# markers in retained metadata, and the expected calibration-only decision.
run_offline -i \
	--mount "type=bind,src=$manifest_dir,dst=/input,readonly" \
	--mount "type=bind,src=$repo_root,dst=/repo,readonly" \
	--mount "type=bind,src=$output,dst=/output" \
	"$image" python3 - "/input/$manifest_name" /output "$image" "$image_id" \
		"$docker_endpoint" "$extraction_exit" "$classification_exit" <<'PY'
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

manifest_path = Path(sys.argv[1])
output = Path(sys.argv[2])
image_ref, image_id, docker_endpoint = sys.argv[3:6]
extraction_exit, classification_exit = sys.argv[6:8]
input_root = manifest_path.parent.resolve()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


with manifest_path.open(newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))

sample_ids = []
pcap_paths = []
pcap_hashes = []
pcap_inventory = []
for row_number, row in enumerate(rows, start=2):
    sample_id = row.get("sample_id", "").strip()
    raw_path = Path(row.get("pcap", ""))
    pcap = raw_path if raw_path.is_absolute() else input_root / raw_path
    pcap = pcap.resolve(strict=True)
    try:
        pcap.relative_to(input_root)
    except ValueError as error:
        raise SystemExit(f"manifest row {row_number} PCAP escapes input root") from error
    pcap_hash = digest(pcap)
    sample_ids.append(sample_id)
    pcap_paths.append(str(pcap))
    pcap_hashes.append(pcap_hash)
    pcap_inventory.append(
        {
            "sample_id": sample_id,
            "path": str(pcap.relative_to(input_root)),
            "bytes": pcap.stat().st_size,
            "sha256": pcap_hash,
        }
    )

unique = {
    "manifest_rows": len(rows),
    "unique_sample_ids": len(set(sample_ids)),
    "unique_canonical_paths": len(set(pcap_paths)),
    "unique_pcap_sha256": len(set(pcap_hashes)),
}
unique["passed"] = all(value == len(rows) for key, value in unique.items() if key != "manifest_rows")

risky_names = []
plaintext_markers = []
name_pattern = re.compile(r"(?:^|[._-])(token|secret|password|private)(?:[._-]|$)|\.(?:key|pem|p12|pfx)$", re.I)
text_pattern = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY|authorization\s*:|bearer\s+|password\s*[:=]|secret\s*[:=]", re.I)
for path in sorted(input_root.rglob("*")):
    if not path.is_file():
        continue
    relative = str(path.relative_to(input_root))
    if name_pattern.search(path.name):
        risky_names.append(relative)
    if path.suffix.lower() in {".pcap", ".pcapng"} or path.stat().st_size > (1 << 20):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if text_pattern.search(text):
        plaintext_markers.append(relative)

extraction = json.loads((output / "extraction.json").read_text(encoding="utf-8")) if (output / "extraction.json").is_file() else {}
scores = json.loads((output / "scores.json").read_text(encoding="utf-8")) if (output / "scores.json").is_file() else {}
features_header = []
if (output / "features.csv").is_file():
    with (output / "features.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        features_header = next(reader, [])
sensitive_feature_columns = sorted(set(features_header).intersection({"pcap", "client_ip", "server_ip", "src", "dst", "port"}))

tracked_outputs = {}
for name in (
    "image-build.log",
    "toolchain.txt",
    "features.csv",
    "extraction.json",
    "extraction.stdout.json",
    "extraction.stderr.log",
    "scores.json",
    "classification.stdout.json",
    "classification.stderr.log",
):
    path = output / name
    if path.is_file():
        tracked_outputs[name] = {"bytes": path.stat().st_size, "sha256": digest(path)}

tool_inputs = {}
for path in (
    Path("/repo/scripts/stealth-offline.Dockerfile"),
    Path("/repo/scripts/stealth-offline-container.sh"),
    Path("/repo/scripts/stealth-features.py"),
    Path("/repo/scripts/stealth-classify.py"),
    Path("/repo/testdata/stealth/preregistration.json"),
):
    tool_inputs[str(path.relative_to("/repo"))] = digest(path)

expected_calibration_result = (
    len(rows) > 0
    and extraction_exit == "0"
    and extraction.get("status") == "pass"
    and extraction.get("samples") == len(rows)
    and classification_exit == "2"
    and scores.get("status") == "insufficient_evidence"
)
audit_ok = (
    unique["passed"]
    and len(rows) > 0
    and not risky_names
    and not plaintext_markers
    and not sensitive_feature_columns
    and extraction.get("address_fields_emitted") is False
    and extraction.get("decryption_used") is False
    and expected_calibration_result
)

report = {
    "schema_version": 1,
    "status": "insufficient_evidence" if audit_ok else "fail",
    "purpose": "strictly_offline_pilot_feature_extraction",
    "claim_eligible": False,
    "comparison_claim": "forbidden",
    "reason": scores.get("reason", "offline extraction or audit failed"),
    "runtime_isolation": {
        "docker_endpoint": docker_endpoint,
        "network_mode": "none",
        "input_mount_read_only": True,
        "repository_mount_read_only": True,
        "only_output_mount_writable": True,
        "container_root_read_only": True,
        "capabilities_dropped": "ALL",
        "no_new_privileges": True,
    },
    "toolchain": {
        "image_reference": image_ref,
        "image_id": image_id,
        "base_image": "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        "python_package": "python3=3.14.7-r1",
        "tshark_package": "tshark=4.6.6-r0",
        "input_sha256": tool_inputs,
    },
    "input": {
        "manifest": manifest_path.name,
        "manifest_sha256": digest(manifest_path),
        "pcaps": pcap_inventory,
        "identity_check": unique,
    },
    "privacy_check": {
        "scope": "retained campaign metadata and emitted feature evidence; encrypted PCAP payloads were not decrypted",
        "risky_retained_filenames": risky_names,
        "plaintext_secret_marker_files": plaintext_markers,
        "sensitive_feature_columns": sensitive_feature_columns,
        "address_fields_emitted": extraction.get("address_fields_emitted"),
        "decryption_used": extraction.get("decryption_used"),
        "passed": not risky_names and not plaintext_markers and not sensitive_feature_columns and extraction.get("address_fields_emitted") is False and extraction.get("decryption_used") is False,
    },
    "stages": {
        "extraction": {"exit_code": extraction_exit, "status": extraction.get("status")},
        "classification": {"exit_code": classification_exit, "status": scores.get("status"), "reason": scores.get("reason")},
    },
    "outputs": tracked_outputs,
}

fd, temporary = tempfile.mkstemp(prefix="audit.json.", dir=output)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, output / "audit.json")
raise SystemExit(0 if audit_ok else 1)
PY

printf 'offline extraction retained as calibration/insufficient_evidence: %s\n' "$output"
