#!/usr/bin/env python3
"""Generate and verify inputs for the isolated small-scale stealth pilot.

The generated campaign is always calibration-only. Secret values are never
written to the campaign configuration or the retained effective descriptors;
only SHA-256 commitments are retained by the campaign driver.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, Iterable


PRODUCTS = ("cover", "autocar", "hysteria2")
WORKLOADS = ("idle", "download_1k", "parallel_20")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
USER_RE = re.compile(r"[1-9][0-9]*(?::[1-9][0-9]*)?")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="prepare an internal Docker pilot campaign")
    commands = root.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    for name in (
        "output", "autocar-effective-output", "hysteria-effective-output",
        "campaign-id", "network", "capture-image", "runner-image", "capture-host",
        "inputs-root", "user", "control-container", "control-ip",
        "autocar-container", "autocar-ip", "hysteria-container", "hysteria-ip",
        "origin-ip", "cert", "key", "token", "autocar-binary", "hysteria-binary",
        "hysteria-client-config", "hysteria-server-config", "autocar-version",
        "hysteria-version", "hysteria-expected-sha256",
    ):
        prepare.add_argument("--" + name, required=True)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--campaign-dir", required=True)
    finalize.add_argument("--output", required=True)
    finalize.add_argument("--samples-per-cell", required=True, type=int)
    finalize.add_argument("--workloads", required=True)
    finalize.add_argument("--autocar-version", required=True)
    finalize.add_argument("--hysteria-version", required=True)
    finalize.add_argument("--extraction-status")
    finalize.add_argument("--classification-status")

    select_subnet = commands.add_parser("select-subnet")
    select_subnet.add_argument("--networks-json", required=True)

    commands.add_parser("self-test")
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "finalize":
        finalize(args)
    elif args.command == "select-subnet":
        print(select_subnet(args.networks_json))
    else:
        self_test()
    return 0


def prepare(args: argparse.Namespace) -> None:
    for field in ("campaign_id", "network", "control_container", "autocar_container", "hysteria_container"):
        require_name(getattr(args, field), field)
    if not USER_RE.fullmatch(args.user):
        fail("user must be a non-root numeric UID or UID:GID")
    root = Path(args.inputs_root).resolve(strict=True)
    if not root.is_dir() or root == Path("/"):
        fail("inputs-root must be an existing non-root directory")
    files = {
        name: under(root, Path(getattr(args, name)).resolve(strict=True), name)
        for name in (
            "cert", "key", "token", "autocar_binary", "hysteria_binary",
            "hysteria_client_config", "hysteria_server_config",
        )
    }
    for path in files.values():
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"input is not a non-empty file: {path.name}")
    endpoints = {
        "control": private_ip(args.control_ip),
        "autocar": private_ip(args.autocar_ip),
        "hysteria2": private_ip(args.hysteria_ip),
        "origin": private_ip(args.origin_ip),
    }
    if len(set(endpoints.values())) != len(endpoints):
        fail("pilot endpoint IPs must be distinct")
    hysteria_hash = sha256(files["hysteria_binary"])
    if hysteria_hash != args.hysteria_expected_sha256:
        fail("Hysteria binary does not match the pinned official checksum")

    auth_hash = sha256(files["token"])
    autocar_effective = {
        "schema_version": 1,
        "evidence_class": "calibration_only",
        "product": "autocar",
        "implementation_version": args.autocar_version,
        "binary_sha256": sha256(files["autocar_binary"]),
        "transport": "h3",
        "h3_fingerprint": "chrome-2026-08",
        "relay": f"{endpoints['autocar']}:8443",
        "origin": f"http://{endpoints['origin']}:8080",
        "server_name": "cover.test",
        "certificate_sha256": sha256(files["cert"]),
        "private_key_sha256": sha256(files["key"]),
        "token_sha256": auth_hash,
    }
    hysteria_effective = {
        "schema_version": 1,
        "evidence_class": "calibration_only",
        "product": "hysteria2",
        "implementation_version": args.hysteria_version,
        "binary_sha256": hysteria_hash,
        "profile": "standard",
        "chrome_quic_parrot": True,
        "gecko": False,
        "relay": f"{endpoints['hysteria2']}:8443",
        "origin": f"http://{endpoints['origin']}:8080",
        "server_name": "cover.test",
        "certificate_sha256": sha256(files["cert"]),
        "private_key_sha256": sha256(files["key"]),
        "auth_sha256": auth_hash,
        "client_config_sha256": sha256(files["hysteria_client_config"]),
        "server_config_sha256": sha256(files["hysteria_server_config"]),
    }
    autocar_effective_path = under(
        root, Path(args.autocar_effective_output).resolve(strict=False), "autocar effective output"
    )
    hysteria_effective_path = under(
        root, Path(args.hysteria_effective_output).resolve(strict=False), "hysteria effective output"
    )
    write_json(autocar_effective_path, autocar_effective)
    write_json(hysteria_effective_path, hysteria_effective)

    common_mounts = [{
        "source": str(files["cert"]), "target": "/pilot/server.crt", "read_only": True,
    }]
    config: Dict[str, Any] = {
        "schema_version": 1,
        "campaign_id": args.campaign_id,
        "lab": {
            "docker_network": args.network,
            "ownership_label": f"com.cppla.autocar.stealth-campaign={args.campaign_id}",
            "capture_image": args.capture_image,
            "capture_host": args.capture_host,
            "interface": "eth0",
            "allowed_mount_roots": [str(root)],
            "minimum_packets": 5,
            "workload_timeout_seconds": 45,
            "runner_memory_mb": 512,
            "runner_pids_limit": 128,
        },
        "provenance": {
            "preregistration_recorded_at": "2026-09-01T00:00:00Z",
            "autocar_binary": str(files["autocar_binary"]),
            "autocar_config": str(autocar_effective_path),
            "hysteria2_binary": str(files["hysteria_binary"]),
            "hysteria2_config": str(hysteria_effective_path),
        },
        "products": {
            "cover": {"variants": [{
                "name": "quic-go-standard-h3-control",
                "client_implementation": "quic-go v0.61.0 standard H3 control (not a browser)",
                "server_implementation": "quic-go v0.61.0 HTTP/3 fixture",
                "implementation_version": "v0.61.0-calibration-control",
                "real_browser": False,
                "runner_image": args.runner_image,
                "server_container": args.control_container,
                "server_ip": str(endpoints["control"]),
                "server_port": 8443,
                "transport": "udp",
                "command": [
                    "/stealth-pilot", "h3-workload", "--server", "{server_ip}:{server_port}",
                    "--server-name", "cover.test", "--ca", "/pilot/server.crt",
                    "--workload", "{workload}", "--seed", "{sample_seed}",
                ],
                "environment": {}, "mounts": common_mounts, "user": args.user,
            }]},
            "autocar": {"variants": [{
                "name": "autocar-v101-worktree-h3",
                "client_implementation": "AutoCAR v1.0.1 worktree WebH3Client",
                "server_implementation": "AutoCAR v1.0.1 worktree web H3 server",
                "implementation_version": args.autocar_version,
                "real_browser": False,
                "runner_image": args.runner_image,
                "server_container": args.autocar_container,
                "server_ip": str(endpoints["autocar"]),
                "server_port": 8443,
                "transport": "udp",
                "command": [
                    "/stealth-pilot", "proxy-workload", "--client", "autocar",
                    "--client-bin", "/autocar", "--server", "{server_ip}:{server_port}",
                    "--server-name", "cover.test", "--ca", "/pilot/server.crt",
                    "--token-file", "/pilot/token", "--proxy-listen", "127.0.0.1:18080",
                    "--origin", f"http://{endpoints['origin']}:8080",
                    "--workload", "{workload}", "--seed", "{sample_seed}",
                ],
                "environment": {},
                "mounts": common_mounts + [{
                    "source": str(files["token"]), "target": "/pilot/token", "read_only": True,
                }],
                "user": args.user,
            }]},
            "hysteria2": {"variants": [{
                "name": "hysteria2-v2122-standard",
                "client_implementation": "official Hysteria 2 v2.12.2 client",
                "server_implementation": "official Hysteria 2 v2.12.2 reverse-proxy masquerade",
                "implementation_version": args.hysteria_version,
                "real_browser": False,
                "runner_image": args.runner_image,
                "server_container": args.hysteria_container,
                "server_ip": str(endpoints["hysteria2"]),
                "server_port": 8443,
                "transport": "udp",
                "command": [
                    "/stealth-pilot", "proxy-workload", "--client", "hysteria2",
                    "--client-bin", "/hysteria", "--client-config", "/pilot/hysteria-client.yaml",
                    "--server", "{server_ip}:{server_port}", "--proxy-listen", "127.0.0.1:18080",
                    "--origin", f"http://{endpoints['origin']}:8080",
                    "--workload", "{workload}", "--seed", "{sample_seed}",
                ],
                "environment": {},
                "mounts": common_mounts + [
                    {"source": str(files["hysteria_binary"]), "target": "/hysteria", "read_only": True},
                    {"source": str(files["hysteria_client_config"]), "target": "/pilot/hysteria-client.yaml", "read_only": True},
                ],
                "user": args.user,
            }]},
        },
    }
    output = Path(args.output).resolve(strict=False)
    write_json(output, config)


def finalize(args: argparse.Namespace) -> None:
    if not 1 <= args.samples_per_cell <= 5:
        fail("samples-per-cell must be in 1..5 for a calibration pilot")
    workloads = tuple(item.strip() for item in args.workloads.split(",") if item.strip())
    if not workloads or len(set(workloads)) != len(workloads) or any(item not in WORKLOADS for item in workloads):
        fail("workloads must be a unique comma-separated subset of idle,download_1k,parallel_20")
    root = Path(args.campaign_dir).resolve(strict=True)
    campaign = read_json(root / "campaign.json")
    state = read_json(root / "state.json")
    plan = read_json(root / "plan.json")
    if campaign.get("status") != "insufficient_evidence":
        fail("pilot campaign must remain insufficient_evidence")
    if state.get("status") != "complete":
        fail("pilot campaign did not complete")
    if plan.get("identity", {}).get("mode") != "calibration":
        fail("pilot plan is not calibration mode")
    safety = plan.get("safety", {})
    required_safety = {
        "local_docker_context": True,
        "internal_bridge_only": True,
        "host_interface_capture": False,
        "host_qdisc_modified": False,
        "fresh_network_namespace_per_sample": True,
        "exact_endpoint_bpf": True,
    }
    if any(safety.get(key) != value for key, value in required_safety.items()):
        fail("pilot plan lacks required isolation assertions")
    manifest_path = root / "capture-manifest.csv"
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    expected = len(PRODUCTS) * len(workloads) * args.samples_per_cell
    if len(rows) != expected:
        fail(f"pilot manifest has {len(rows)} rows, want {expected}")
    counts: Dict[tuple[str, str], int] = {}
    for row in rows:
        if row.get("scenario") != "healthy_h3" or row.get("wire_profile") != "h3":
            fail("pilot manifest contains a non-healthy-H3 sample")
        product, workload = row.get("product"), row.get("workload")
        if product not in PRODUCTS or workload not in workloads:
            fail("pilot manifest contains an unexpected product or workload")
        counts[(str(product), str(workload))] = counts.get((str(product), str(workload)), 0) + 1
    if any(counts.get((product, workload)) != args.samples_per_cell for product in PRODUCTS for workload in workloads):
        fail("pilot manifest is unbalanced")
    document = {
        "schema_version": 1,
        "status": "insufficient_evidence",
        "harness_status": "pass",
        "purpose": "small_scale_interoperability_and_capture_calibration",
        "claim_eligible": False,
        "comparison_claim": "forbidden",
        "reason": f"{args.samples_per_cell} samples per product/cell are far below the preregistered release corpus.",
        "campaign_id": campaign.get("campaign_id"),
        "campaign_status": campaign.get("status"),
        "autocar_version": args.autocar_version,
        "hysteria2_version": args.hysteria_version,
        "control": {
            "kind": "standard_quic_go_h3",
            "real_browser": False,
            "label": "standards-library control; not browser evidence",
        },
        "scope": {
            "scenario": "healthy_h3",
            "workloads": list(workloads),
            "samples_per_product_cell": args.samples_per_cell,
            "completed_pcaps": len(rows),
        },
        "isolation": {
            "local_docker_context": True,
            "internal_bridge_only": True,
            "rfc1918_endpoints_only": True,
            "public_campaign_traffic": False,
            "ssh_used": False,
            "host_interface_capture": False,
            "host_firewall_modified": False,
            "host_qdisc_modified": False,
        },
        "capture_manifest_sha256": sha256(manifest_path),
    }
    if args.extraction_status:
        extraction = read_json(Path(args.extraction_status).resolve(strict=True))
        extraction_status = extraction.get("status")
        if extraction_status == "pass":
            document["offline_extraction"] = {
                "status": "pass",
                "samples": extraction.get("samples"),
                "decryption_used": extraction.get("decryption_used"),
            }
        elif extraction_status == "insufficient_evidence":
            document["offline_extraction"] = {
                "status": "unavailable",
                "extractor_status": "insufficient_evidence",
                "reason": extraction.get("reason", "feature extraction unavailable"),
                "classification_run": False,
            }
        else:
            fail("offline extraction reported an operational failure")
    if args.classification_status:
        scores = read_json(Path(args.classification_status).resolve(strict=True))
        document["offline_classification"] = {
            "status": scores.get("status"),
            "claim_eligible": False,
        }
    write_json(Path(args.output).resolve(strict=False), document)


def select_subnet(path: str) -> str:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, list):
        fail("Docker network inventory must be a JSON array")
    occupied = []
    for network in value:
        if not isinstance(network, dict):
            continue
        configs = ((network.get("IPAM") or {}).get("Config") or [])
        for config in configs:
            try:
                occupied.append(ipaddress.ip_network(config.get("Subnet"), strict=False))
            except (AttributeError, TypeError, ValueError):
                continue
    for third in range(64, 240):
        candidate = ipaddress.ip_network(f"10.242.{third}.0/24")
        if not any(candidate.overlaps(existing) for existing in occupied):
            return str(candidate)
    fail("no unused pilot subnet is available in 10.242.64.0/18")
    raise AssertionError("unreachable")


def private_ip(value: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise SystemExit(f"invalid private IP {value!r}") from error
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private or address.is_loopback or address.is_link_local:
        fail(f"IP must be non-loopback RFC1918 IPv4: {value}")
    # is_private is broader than RFC1918 in Python, so make the boundary exact.
    networks = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not any(address in network for network in networks):
        fail(f"IP must be RFC1918 IPv4: {value}")
    return address


def require_name(value: str, label: str) -> None:
    if not NAME_RE.fullmatch(value):
        fail(f"{label} contains unsupported characters")


def under(root: Path, path: Path, label: str) -> Path:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise SystemExit(f"{label} is outside inputs-root") from error
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        fail(f"{path.name} is not a JSON object")
    return value


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="stealth-pilot-config-test.") as directory:
        root = Path(directory)
        secret = "this-value-must-not-appear"
        for name, content in {
            "cert.pem": "certificate", "key.pem": "private-key", "token": secret,
            "autocar": "autocar-binary", "hysteria": "hysteria-binary",
            "hysteria-client.yaml": f"auth: {secret}",
            "hysteria-server.yaml": f"password: {secret}",
        }.items():
            (root / name).write_text(content, encoding="utf-8")
        args = argparse.Namespace(
            output=str(root / "campaign.json"),
            autocar_effective_output=str(root / "autocar-effective.json"),
            hysteria_effective_output=str(root / "hysteria-effective.json"),
            campaign_id="pilot-self-test", network="pilot-self-test", capture_image="capture:test",
            runner_image="runner:test", capture_host="local-docker-pilot", inputs_root=str(root),
            user="65532:65532", control_container="control", control_ip="10.242.1.10",
            autocar_container="autocar", autocar_ip="10.242.1.20",
            hysteria_container="hysteria", hysteria_ip="10.242.1.30", origin_ip="10.242.1.40",
            cert=str(root / "cert.pem"), key=str(root / "key.pem"), token=str(root / "token"),
            autocar_binary=str(root / "autocar"), hysteria_binary=str(root / "hysteria"),
            hysteria_client_config=str(root / "hysteria-client.yaml"),
            hysteria_server_config=str(root / "hysteria-server.yaml"),
            autocar_version="v1.0.1-self-test", hysteria_version="v2.12.2-619a6f8",
            hysteria_expected_sha256=sha256(root / "hysteria"),
        )
        prepare(args)
        retained = "".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("campaign.json", "autocar-effective.json", "hysteria-effective.json")
        )
        if secret in retained:
            fail("self-test found a secret in generated retained inputs")
        generated = read_json(root / "campaign.json")
        cover = generated["products"]["cover"]["variants"][0]
        if cover["real_browser"] is not False or "not a browser" not in cover["client_implementation"]:
            fail("self-test found a misleading cover-control label")
        if generated["lab"]["ownership_label"] != "com.cppla.autocar.stealth-campaign=pilot-self-test":
            fail("self-test found an incorrect ownership label")
        networks = root / "networks.json"
        networks.write_text(json.dumps([{"IPAM": {"Config": [{"Subnet": "10.242.64.0/24"}]}}]), encoding="utf-8")
        if select_subnet(str(networks)) != "10.242.65.0/24":
            fail("self-test subnet selection was not deterministic")
    print(json.dumps({"schema_version": 1, "status": "pass", "self_test": True}))


def fail(message: str) -> None:
    raise SystemExit(message)


if __name__ == "__main__":
    raise SystemExit(main())
