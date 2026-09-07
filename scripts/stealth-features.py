#!/usr/bin/env python3
"""Extract observer-only, address-free flow features from isolated PCAPs.

The input manifest retains capture paths and endpoint addresses so extraction
can establish direction. The emitted CSV deliberately contains neither. This
tool never decrypts TLS or QUIC and exits 2 with ``insufficient_evidence`` when
the required packet evidence or tshark is unavailable.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


SCHEMA_VERSION = 1
META_COLUMNS = [
    "schema_version",
    "sample_id",
    "product",
    "scenario",
    "workload",
    "wire_profile",
    "run_id",
    "seed",
]
FEATURE_COLUMNS = [
    "packet_count",
    "duration_ms",
    "total_bytes",
    "client_packets",
    "server_packets",
    "client_bytes",
    "server_bytes",
    "client_byte_fraction",
    "udp_fraction",
    "tcp_syn_count",
    "tcp_retransmission_count",
    "quic_initial_count",
    "tls_handshake_count",
    "small_packet_fraction",
    "large_packet_fraction",
    "size_mean",
    "size_stddev",
    "size_p10",
    "size_p25",
    "size_p50",
    "size_p75",
    "size_p90",
    "iat_mean_ms",
    "iat_stddev_ms",
    "iat_p50_ms",
    "iat_p90_ms",
    "iat_max_ms",
    "direction_changes",
    "burst_count",
] + [f"first_{index:02d}_signed_bytes" for index in range(1, 21)]


class InsufficientEvidence(RuntimeError):
    pass


@dataclass(frozen=True)
class Packet:
    timestamp: float
    length: int
    source: str
    destination: str
    tcp: bool
    udp: bool
    tcp_syn: bool
    retransmission: bool
    quic_initial: bool
    tls_handshake: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", help="capture manifest CSV")
    parser.add_argument("--output", help="feature CSV")
    parser.add_argument("--status-output", help="machine-readable extraction status JSON")
    parser.add_argument("--tshark", default=os.environ.get("TSHARK", "tshark"))
    parser.add_argument("--minimum-packets", type=int, default=5)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print(json.dumps({"status": "pass", "self_test": True}, sort_keys=True))
        return 0
    if not args.manifest or not args.output or not args.status_output:
        print("--manifest, --output and --status-output are required", file=sys.stderr)
        return 2
    try:
        summary = extract_manifest(
            Path(args.manifest), Path(args.output), Path(args.status_output), args.tshark, args.minimum_packets
        )
    except InsufficientEvidence as error:
        summary = {
            "schema_version": SCHEMA_VERSION,
            "status": "insufficient_evidence",
            "reason": str(error),
        }
        write_json_atomic(Path(args.status_output), summary)
        print(json.dumps(summary, sort_keys=True))
        return 2
    except Exception as error:  # Operational failure is not missing evidence.
        summary = {"schema_version": SCHEMA_VERSION, "status": "fail", "reason": str(error)}
        write_json_atomic(Path(args.status_output), summary)
        print(json.dumps(summary, sort_keys=True))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


def extract_manifest(
    manifest_path: Path,
    output_path: Path,
    status_path: Path,
    tshark: str,
    minimum_packets: int,
) -> dict:
    if minimum_packets < 2:
        raise ValueError("--minimum-packets must be at least 2")
    if shutil.which(tshark) is None:
        raise InsufficientEvidence(f"tshark executable not found: {tshark}")
    if not manifest_path.is_file():
        raise InsufficientEvidence(f"capture manifest not found: {manifest_path}")

    manifest_sha256 = file_sha256(manifest_path)

    with manifest_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "sample_id",
            "product",
            "scenario",
            "workload",
            "wire_profile",
            "run_id",
            "seed",
            "pcap",
            "client_ip",
            "server_ip",
        }
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise InsufficientEvidence("manifest columns missing: " + ", ".join(sorted(missing)))
        rows = list(reader)
    if not rows:
        raise InsufficientEvidence("capture manifest contains no samples")

    sample_ids: set[str] = set()
    capture_paths: dict[Path, str] = {}
    capture_hashes: dict[str, str] = {}
    capture_digests: list[dict[str, object]] = []
    extracted: list[dict[str, object]] = []
    manifest_root = manifest_path.resolve().parent
    for row_number, row in enumerate(rows, start=2):
        sample_id = row["sample_id"].strip()
        if not sample_id or sample_id in sample_ids:
            raise InsufficientEvidence(f"manifest row {row_number} has empty or duplicate sample_id")
        sample_ids.add(sample_id)
        product = row["product"].strip().lower()
        if product not in {"cover", "autocar", "hysteria2"}:
            raise InsufficientEvidence(f"manifest row {row_number} has unsupported product {product!r}")
        for column in ("scenario", "workload", "wire_profile", "run_id", "seed"):
            if not row[column].strip():
                raise InsufficientEvidence(f"manifest row {row_number} has empty {column}")
        pcap_path = Path(row["pcap"])
        if not pcap_path.is_absolute():
            pcap_path = manifest_root / pcap_path
        pcap_path, pcap_sha256, pcap_bytes = register_capture_identity(
            pcap_path, sample_id, capture_paths, capture_hashes
        )
        packets = read_packets(tshark, pcap_path)
        if file_sha256(pcap_path) != pcap_sha256:
            raise InsufficientEvidence(f"sample {sample_id} PCAP changed while it was being extracted")
        relevant = [
            packet
            for packet in packets
            if {packet.source, packet.destination} == {row["client_ip"].strip(), row["server_ip"].strip()}
        ]
        if len(relevant) < minimum_packets:
            raise InsufficientEvidence(
                f"sample {sample_id} has {len(relevant)} matching IP packets; need {minimum_packets}"
            )
        features = packet_features(relevant, row["client_ip"].strip())
        extracted.append(
            {
                "schema_version": SCHEMA_VERSION,
                "sample_id": sample_id,
                "product": product,
                "scenario": row["scenario"].strip(),
                "workload": row["workload"].strip(),
                "wire_profile": row["wire_profile"].strip(),
                "run_id": row["run_id"].strip(),
                "seed": row["seed"].strip(),
                **features,
            }
        )
        capture_digests.append({"sample_id": sample_id, "sha256": pcap_sha256, "bytes": pcap_bytes})

    if file_sha256(manifest_path) != manifest_sha256:
        raise InsufficientEvidence("capture manifest changed while it was being extracted")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=output_path.name + ".", dir=output_path.parent)
    try:
        with os.fdopen(descriptor, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=META_COLUMNS + FEATURE_COLUMNS)
            writer.writeheader()
            writer.writerows(extracted)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output_path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "samples": len(extracted),
        "features": len(FEATURE_COLUMNS),
        "manifest_sha256": manifest_sha256,
        "feature_sha256": file_sha256(output_path),
        "capture_digests": capture_digests,
        "address_fields_emitted": False,
        "decryption_used": False,
    }
    write_json_atomic(status_path, summary)
    return summary


def register_capture_identity(
    path: Path,
    sample_id: str,
    seen_paths: dict[Path, str],
    seen_hashes: dict[str, str],
) -> tuple[Path, str, int]:
    try:
        canonical = path.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise InsufficientEvidence(f"sample {sample_id} has missing PCAP") from error
    if not canonical.is_file():
        raise InsufficientEvidence(f"sample {sample_id} PCAP is not a regular file")
    size = canonical.stat().st_size
    if size == 0:
        raise InsufficientEvidence(f"sample {sample_id} has empty PCAP")
    prior_path_sample = seen_paths.get(canonical)
    if prior_path_sample is not None:
        raise InsufficientEvidence(
            f"sample {sample_id} reuses the canonical PCAP path from sample {prior_path_sample}"
        )
    digest = file_sha256(canonical)
    prior_hash_sample = seen_hashes.get(digest)
    if prior_hash_sample is not None:
        raise InsufficientEvidence(
            f"sample {sample_id} reuses PCAP bytes from sample {prior_hash_sample} (sha256 {digest})"
        )
    seen_paths[canonical] = sample_id
    seen_hashes[digest] = sample_id
    return canonical, digest, size


def read_packets(tshark: str, pcap_path: Path) -> list[Packet]:
    fields = [
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "tcp.srcport",
        "udp.srcport",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.analysis.retransmission",
        "quic.long.packet_type",
        "quic.version",
        "tls.handshake.type",
    ]
    command = [
        tshark,
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        "ip or ipv6",
        "-T",
        "fields",
        "-E",
        # tshark's named tab separator is /t. Passing \t makes current
        # Wireshark releases use a literal backslash as the separator.
        "separator=/t",
        "-E",
        "occurrence=f",
        "-E",
        "quote=n",
    ]
    for field in fields:
        command.extend(["-e", field])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip().splitlines()[-1:] or ["unknown tshark error"]
        raise InsufficientEvidence(f"tshark could not parse {pcap_path.name}: {diagnostic[0]}")
    packets: list[Packet] = []
    for line in completed.stdout.splitlines():
        values = line.split("\t")
        values.extend([""] * (len(fields) - len(values)))
        try:
            timestamp = float(values[0])
            length = int(values[1])
        except (TypeError, ValueError):
            continue
        source = values[2] or values[3]
        destination = values[4] or values[5]
        if not source or not destination:
            continue
        tcp = bool(values[6])
        udp = bool(values[7])
        syn = values[8] in {"1", "True", "true"}
        ack = values[9] in {"1", "True", "true"}
        quic_types = {item.strip().lower() for item in values[11].split(",") if item.strip()}
        # Wireshark has represented Initial as both numeric 0 and descriptive
        # text across releases; accept either without depending on decryption.
        quic_initial = bool(quic_types.intersection({"0", "initial"})) and bool(values[12])
        packets.append(
            Packet(
                timestamp=timestamp,
                length=length,
                source=source,
                destination=destination,
                tcp=tcp,
                udp=udp,
                tcp_syn=syn and not ack,
                retransmission=bool(values[10]),
                quic_initial=quic_initial,
                tls_handshake=bool(values[13]),
            )
        )
    return packets


def packet_features(packets: Sequence[Packet], client_ip: str) -> dict[str, float | int]:
    ordered = sorted(packets, key=lambda packet: packet.timestamp)
    sizes = [packet.length for packet in ordered]
    directions = [1 if packet.source == client_ip else -1 for packet in ordered]
    times = [packet.timestamp for packet in ordered]
    iats = [max(0.0, (right - left) * 1000.0) for left, right in zip(times, times[1:])]
    client_sizes = [size for size, direction in zip(sizes, directions) if direction > 0]
    server_sizes = [size for size, direction in zip(sizes, directions) if direction < 0]
    total_bytes = sum(sizes)
    direction_changes = sum(left != right for left, right in zip(directions, directions[1:]))
    bursts = 1
    for index in range(1, len(ordered)):
        gap_ms = (ordered[index].timestamp - ordered[index - 1].timestamp) * 1000.0
        if directions[index] != directions[index - 1] or gap_ms > 20.0:
            bursts += 1
    result: dict[str, float | int] = {
        "packet_count": len(ordered),
        "duration_ms": max(0.0, (times[-1] - times[0]) * 1000.0),
        "total_bytes": total_bytes,
        "client_packets": len(client_sizes),
        "server_packets": len(server_sizes),
        "client_bytes": sum(client_sizes),
        "server_bytes": sum(server_sizes),
        "client_byte_fraction": safe_div(sum(client_sizes), total_bytes),
        "udp_fraction": safe_div(sum(packet.udp for packet in ordered), len(ordered)),
        "tcp_syn_count": sum(packet.tcp_syn for packet in ordered),
        "tcp_retransmission_count": sum(packet.retransmission for packet in ordered),
        "quic_initial_count": sum(packet.quic_initial for packet in ordered),
        "tls_handshake_count": sum(packet.tls_handshake for packet in ordered),
        "small_packet_fraction": safe_div(sum(size <= 128 for size in sizes), len(sizes)),
        "large_packet_fraction": safe_div(sum(size >= 1200 for size in sizes), len(sizes)),
        "size_mean": statistics.fmean(sizes),
        "size_stddev": statistics.pstdev(sizes),
        "size_p10": percentile(sizes, 0.10),
        "size_p25": percentile(sizes, 0.25),
        "size_p50": percentile(sizes, 0.50),
        "size_p75": percentile(sizes, 0.75),
        "size_p90": percentile(sizes, 0.90),
        "iat_mean_ms": statistics.fmean(iats) if iats else 0.0,
        "iat_stddev_ms": statistics.pstdev(iats) if iats else 0.0,
        "iat_p50_ms": percentile(iats, 0.50) if iats else 0.0,
        "iat_p90_ms": percentile(iats, 0.90) if iats else 0.0,
        "iat_max_ms": max(iats, default=0.0),
        "direction_changes": direction_changes,
        "burst_count": bursts,
    }
    signed = [size * direction for size, direction in zip(sizes, directions)]
    for index in range(20):
        result[f"first_{index + 1:02d}_signed_bytes"] = signed[index] if index < len(signed) else 0
    return result


def percentile(values: Sequence[float | int], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower]) * (1.0 - weight) + float(ordered[upper]) * weight


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def self_test() -> None:
    packets = [
        Packet(1.000, 1200, "client", "server", False, True, False, False, True, False),
        Packet(1.010, 1100, "server", "client", False, True, False, False, True, False),
        Packet(1.030, 100, "client", "server", False, True, False, False, False, False),
        Packet(1.031, 1400, "server", "client", False, True, False, False, False, False),
        Packet(1.060, 80, "client", "server", False, True, False, False, False, False),
    ]
    features = packet_features(packets, "client")
    assert features["packet_count"] == 5
    assert features["client_packets"] == 3
    assert features["server_packets"] == 2
    assert features["quic_initial_count"] == 2
    assert features["first_01_signed_bytes"] == 1200
    assert features["first_02_signed_bytes"] == -1100
    assert abs(float(features["duration_ms"]) - 60.0) < 0.001
    assert set(features) == set(FEATURE_COLUMNS)

    with tempfile.TemporaryDirectory(prefix="autocar-stealth-features-test.") as directory:
        root = Path(directory)
        first = root / "first.pcap"
        duplicate = root / "duplicate.pcap"
        first.write_bytes(b"pcap-one")
        duplicate.write_bytes(b"pcap-one")
        paths: dict[Path, str] = {}
        hashes: dict[str, str] = {}
        _, digest, size = register_capture_identity(first, "sample-one", paths, hashes)
        assert digest == hashlib.sha256(b"pcap-one").hexdigest()
        assert size == len(b"pcap-one")
        try:
            register_capture_identity(first, "sample-path-duplicate", paths, hashes)
        except InsufficientEvidence as error:
            assert "canonical PCAP path" in str(error)
        else:
            raise AssertionError("duplicate canonical path was accepted")
        try:
            register_capture_identity(duplicate, "sample-hash-duplicate", paths, hashes)
        except InsufficientEvidence as error:
            assert "reuses PCAP bytes" in str(error)
        else:
            raise AssertionError("duplicate PCAP digest was accepted")


if __name__ == "__main__":
    raise SystemExit(main())
