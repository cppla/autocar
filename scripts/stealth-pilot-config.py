#!/usr/bin/env python3
"""Generate and verify inputs for the isolated small-scale stealth pilot.

The generated campaign is always calibration-only. Secret values are never
written to the campaign configuration or the retained effective descriptors;
only SHA-256 commitments are retained by the campaign driver.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
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
BUILD_INFO_LIMIT = 32 << 10
BUILD_INFO_KIND = "autocar-pilot-build-provenance"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GO_VERSION_RE = re.compile(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:(?:rc|beta)[0-9]+)?")
MODULE_VERSION_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
NATIVE_QUIC = "github.com/quic-go/quic-go"
WEB_QUIC = "github.com/apernet/quic-go"
UTLS = "github.com/refraction-networking/utls"
MODULE_SOURCES = {
    NATIVE_QUIC: (NATIVE_QUIC,),
    WEB_QUIC: (WEB_QUIC, "github.com/cppla/quic-go"),
    UTLS: (UTLS, "github.com/cppla/utls"),
}
BUILD_MODULES = {"autocar": (NATIVE_QUIC, WEB_QUIC, UTLS), "control": (NATIVE_QUIC,)}
BUILD_PACKAGES = {
    "autocar": "github.com/cppla/autocar/cmd/autocar",
    "control": "github.com/cppla/autocar/scripts/stealth-pilot",
}


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
        "hysteria-version", "hysteria-expected-sha256", "build-info", "control-binary",
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
            "hysteria_client_config", "hysteria_server_config", "build_info", "control_binary",
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

    build_provenance = read_build_provenance(
        files["build_info"], files["autocar_binary"], files["control_binary"]
    )
    control_version = build_provenance["control"]["modules"][0]["source_version"]
    auth_hash = sha256(files["token"])
    autocar_effective = {
        "schema_version": 1,
        "evidence_class": "calibration_only",
        "product": "autocar",
        "implementation_version": args.autocar_version,
        "binary_sha256": sha256(files["autocar_binary"]),
        "build_provenance": build_provenance,
        "transport": "h3",
        "h3_fingerprint": "chrome-2026-10",
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
                "client_implementation": f"quic-go {control_version} standard H3 control (not a browser)",
                "server_implementation": f"quic-go {control_version} HTTP/3 fixture",
                "implementation_version": f"{control_version}-calibration-control",
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
                "name": "autocar-chrome-2026-10-h3",
                "client_implementation": "AutoCAR worktree WebH3Client (chrome-2026-10)",
                "server_implementation": "AutoCAR worktree web H3 server",
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


def exact_build_keys(value: Any, keys: Iterable[str]) -> None:
    # Never echo unrecognized keys or values: this report is retained publicly.
    if not isinstance(value, dict) or set(value) != set(keys):
        fail("build provenance contains an invalid object or unexpected fields")


def unique_build_object(pairs: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("build provenance contains duplicate JSON fields")
        value[key] = item
    return value


def require_build_string(value: Any, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or len(value) > 256 or not pattern.fullmatch(value):
        fail("build provenance contains an invalid version or digest")


def require_module_sum(value: Any) -> None:
    if not isinstance(value, str) or not value.startswith("h1:") or len(value) != 47:
        fail("build provenance contains an invalid module checksum")
    try:
        digest = base64.b64decode(value[3:], validate=True)
    except (binascii.Error, ValueError):
        fail("build provenance contains an invalid module checksum")
    if len(digest) != 32 or base64.b64encode(digest).decode("ascii") != value[3:]:
        fail("build provenance contains a non-canonical module checksum")


def read_build_provenance(path: Path, autocar_binary: Path, control_binary: Path) -> Dict[str, Any]:
    with path.open("rb") as handle:
        encoded = handle.read(BUILD_INFO_LIMIT + 1)
    if len(encoded) > BUILD_INFO_LIMIT:
        fail("build provenance exceeds the 32 KiB input limit")
    try:
        report = json.loads(encoded.decode("utf-8"), object_pairs_hook=unique_build_object)
    except (UnicodeDecodeError, ValueError, RecursionError):
        fail("build provenance is not valid bounded JSON")
    exact_build_keys(report, ("schema_version", "kind", "autocar", "control"))
    if type(report["schema_version"]) is not int or report["schema_version"] != 1 or report["kind"] != BUILD_INFO_KIND:
        fail("build provenance schema or kind is unsupported")
    sanitized: Dict[str, Any] = {"schema_version": 1, "kind": BUILD_INFO_KIND}
    for role, binary in (("autocar", autocar_binary), ("control", control_binary)):
        record = report[role]
        exact_build_keys(record, (
            "binary_sha256", "go_version", "goos", "goarch", "package", "modules",
        ))
        require_build_string(record["binary_sha256"], SHA256_RE)
        require_build_string(record["go_version"], GO_VERSION_RE)
        if record["binary_sha256"] != sha256(binary):
            fail("build provenance binary checksum does not match the supplied binary")
        if record["goos"] != "linux" or record["goarch"] not in ("amd64", "arm64"):
            fail("build provenance must describe a supported Linux pilot binary")
        if record["package"] != BUILD_PACKAGES[role]:
            fail("build provenance describes an unexpected command package")
        modules = record["modules"]
        if not isinstance(modules, list) or len(modules) != len(BUILD_MODULES[role]):
            fail("build provenance has an incomplete module set")
        validated = {}
        for module in modules:
            exact_build_keys(module, (
                "module_path", "requested_version", "source_path", "source_version", "source_sum", "replaced",
            ))
            identity = module["module_path"]
            if not isinstance(identity, str) or identity not in BUILD_MODULES[role] or identity in validated:
                fail("build provenance has duplicate or unexpected module identities")
            if module["source_path"] not in MODULE_SOURCES[identity]:
                fail("build provenance module source is not an approved remote path")
            require_build_string(module["requested_version"], MODULE_VERSION_RE)
            require_build_string(module["source_version"], MODULE_VERSION_RE)
            require_module_sum(module["source_sum"])
            if type(module["replaced"]) is not bool:
                fail("build provenance replacement flag must be a boolean")
            if identity == NATIVE_QUIC and module["replaced"]:
                fail("build provenance may not replace native official QUIC")
            if not module["replaced"] and (
                module["source_path"] != identity or module["source_version"] != module["requested_version"]
            ):
                fail("build provenance has inconsistent non-replaced module metadata")
            validated[identity] = dict(module)
        if set(validated) != set(BUILD_MODULES[role]):
            fail("build provenance has an incomplete module set")
        sanitized[role] = {
            "binary_sha256": record["binary_sha256"], "go_version": record["go_version"],
            "goos": record["goos"], "goarch": record["goarch"], "package": record["package"],
            "modules": [validated[identity] for identity in BUILD_MODULES[role]],
        }
    if any(sanitized["autocar"][key] != sanitized["control"][key] for key in ("go_version", "goos", "goarch")):
        fail("build provenance binaries must use the same Go version and target")
    if sanitized["autocar"]["modules"][0] != sanitized["control"]["modules"][0]:
        fail("build provenance binaries must use the same official QUIC dependency")
    return sanitized


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="stealth-pilot-config-test.") as directory:
        root = Path(directory)
        secret = "this-value-must-not-appear"
        for name, content in {
            "cert.pem": "certificate", "key.pem": "private-key", "token": secret,
            "autocar": "autocar-binary", "hysteria": "hysteria-binary", "stealth-pilot": "control-binary",
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
            control_binary=str(root / "stealth-pilot"), build_info=str(root / "build-info.json"),
            hysteria_client_config=str(root / "hysteria-client.yaml"),
            hysteria_server_config=str(root / "hysteria-server.yaml"),
            autocar_version="v1.0.1-self-test", hysteria_version="v2.12.2-619a6f8",
            hysteria_expected_sha256=sha256(root / "hysteria"),
        )
        provenance = self_test_build_provenance(root)
        write_json(Path(args.build_info), provenance)
        prepare(args)
        retained = "".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("campaign.json", "autocar-effective.json", "hysteria-effective.json")
        )
        if secret in retained:
            fail("self-test found a secret in generated retained inputs")
        generated = read_json(root / "campaign.json")
        effective = read_json(root / "autocar-effective.json")
        if effective["h3_fingerprint"] != "chrome-2026-10":
            fail("self-test found an incorrect AutoCAR H3 profile")
        if effective["build_provenance"] != provenance:
            fail("self-test did not retain validated replacement-aware provenance")
        autocar = generated["products"]["autocar"]["variants"][0]
        if (
            autocar["name"] != "autocar-chrome-2026-10-h3"
            or autocar["client_implementation"] != "AutoCAR worktree WebH3Client (chrome-2026-10)"
            or autocar["implementation_version"] != args.autocar_version
        ):
            fail("self-test found stale AutoCAR capture labels")
        cover = generated["products"]["cover"]["variants"][0]
        if cover["real_browser"] is not False or "not a browser" not in cover["client_implementation"]:
            fail("self-test found a misleading cover-control label")
        if generated["lab"]["ownership_label"] != "com.cppla.autocar.stealth-campaign=pilot-self-test":
            fail("self-test found an incorrect ownership label")
        networks = root / "networks.json"
        networks.write_text(json.dumps([{"IPAM": {"Config": [{"Subnet": "10.242.64.0/24"}]}}]), encoding="utf-8")
        if select_subnet(str(networks)) != "10.242.65.0/24":
            fail("self-test subnet selection was not deterministic")
        self_test_build_rejections(root, args, provenance)
    print(json.dumps({"schema_version": 1, "status": "pass", "self_test": True}))


def self_test_build_provenance(root: Path) -> Dict[str, Any]:
    report: Dict[str, Any] = {"schema_version": 1, "kind": BUILD_INFO_KIND}
    for role, filename in (("autocar", "autocar"), ("control", "stealth-pilot")):
        report[role] = {
            "binary_sha256": sha256(root / filename), "go_version": "go1.27.2",
            "goos": "linux", "goarch": "arm64", "package": BUILD_PACKAGES[role],
            "modules": [{
                "module_path": identity, "requested_version": "v0.63.0" if identity == NATIVE_QUIC else "v1.2.3",
                "source_path": MODULE_SOURCES[identity][-1],
                "source_version": "v0.63.0" if identity == NATIVE_QUIC else "v0.0.0-20261009040133-c1cae948af15",
                "source_sum": "h1:" + base64.b64encode(hashlib.sha256(identity.encode()).digest()).decode("ascii"),
                "replaced": identity != NATIVE_QUIC,
            } for identity in BUILD_MODULES[role]],
        }
    return report


def self_test_build_rejections(root: Path, args: argparse.Namespace, valid: Dict[str, Any]) -> None:
    report_path = Path(args.build_info)

    def reject(report: Any) -> None:
        write_json(report_path, report)
        outputs = [Path(args.output), Path(args.autocar_effective_output), Path(args.hysteria_effective_output)]
        before = [path.read_bytes() for path in outputs]
        try:
            prepare(args)
        except SystemExit:
            if before != [path.read_bytes() for path in outputs]:
                raise AssertionError("invalid build provenance changed retained outputs")
            return
        raise AssertionError("invalid build provenance was accepted")

    def changed(path: tuple[Any, ...], value: Any) -> Dict[str, Any]:
        report = copy.deepcopy(valid)
        target = report
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return report

    for path, value in (
        (("schema_version",), True), (("schema_version",), 1.0), (("schema_version",), 2), (("kind",), "other"),
        (("secret",), "PRIVATE_SECRET"), (("autocar", "secret"), "PRIVATE_SECRET"),
        (("autocar", "modules", 1, "secret"), "PRIVATE_SECRET"),
        (("autocar", "binary_sha256"), "0" * 64), (("control", "binary_sha256"), "0" * 64),
        (("autocar", "binary_sha256"), "A" * 64), (("autocar", "binary_sha256"), 12),
        (("autocar", "go_version"), "devel"), (("control", "go_version"), "go1.26.1"),
        (("autocar", "goos"), "darwin"), (("autocar", "goarch"), "386"),
        (("control", "goarch"), "amd64"), (("autocar", "package"), BUILD_PACKAGES["control"]),
        (("autocar", "modules"), {}), (("autocar", "modules"), valid["autocar"]["modules"][:-1]),
        (("autocar", "modules", 1), valid["autocar"]["modules"][0]),
        (("autocar", "modules", 1, "module_path"), "github.com/cppla/quic-go"),
        (("autocar", "modules", 1, "module_path"), []),
        (("autocar", "modules", 1, "source_path"), "/tmp/local-quic"),
        (("autocar", "modules", 1, "source_path"), "github.com/unapproved/quic-go"),
        (("autocar", "modules", 1, "source_path"), "github.com/cppla/utls"),
        (("autocar", "modules", 1, "source_version"), ""),
        (("autocar", "modules", 1, "source_version"), "main"),
        (("autocar", "modules", 1, "requested_version"), "(devel)"),
        (("autocar", "modules", 1, "replaced"), 1),
        (("autocar", "modules", 1, "replaced"), False),
        (("autocar", "modules", 0, "replaced"), True),
        (("autocar", "modules", 0, "source_version"), "v0.62.0"),
        (("autocar", "modules", 1, "source_sum"), "h1:" + "A" * 43 + "!"),
        (("autocar", "modules", 1, "source_sum"), "h1:" + "A" * 42 + "B="),
        (("autocar", "modules", 1, "source_sum"), "PRIVATE_SECRET"),
        (("control", "modules", 0, "source_sum"), "h1:" + "A" * 43 + "="),
    ):
        reject(changed(path, value))
    missing = copy.deepcopy(valid)
    del missing["autocar"]["go_version"]
    reject(missing)
    missing = copy.deepcopy(valid)
    del missing["control"]
    reject(missing)
    different_native = copy.deepcopy(valid)
    different_native["control"]["modules"][0].update(requested_version="v0.64.0", source_version="v0.64.0")
    reject(different_native)
    encoded = json.dumps(valid).encode("utf-8")
    for malformed in (
        b" " * (BUILD_INFO_LIMIT + 1), b"\xff", b"{", b"[]",
        b'{"schema_version":1,"schema_version":1}',
        encoded.replace(b'"modules":', b'"modules":[],"modules":', 1),
    ):
        report_path.write_bytes(malformed)
        try:
            read_build_provenance(report_path, root / "autocar", root / "stealth-pilot")
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed or oversized build provenance was accepted")
    # A valid report is bound to both supplied files, not merely well-formed hashes.
    write_json(report_path, valid)
    for filename in ("autocar", "stealth-pilot"):
        binary = root / filename
        original = binary.read_bytes()
        binary.write_bytes(original + b" changed")
        try:
            prepare(args)
        except SystemExit:
            pass
        else:
            raise AssertionError("changed pilot binary was accepted")
        finally:
            binary.write_bytes(original)
    # Original upstream sources and same-path versioned replacements are valid,
    # whereas native official QUIC can never be replaced.
    for replaced in (False, True):
        upstream = copy.deepcopy(valid)
        for module in upstream["autocar"]["modules"][1:]:
            module.update(source_path=module["module_path"], source_version=module["requested_version"], replaced=replaced)
        write_json(report_path, upstream)
        read_build_provenance(report_path, root / "autocar", root / "stealth-pilot")
    # The limit is inclusive, and module order is normalized rather than trusted.
    report_path.write_bytes(encoded + b" " * (BUILD_INFO_LIMIT - len(encoded)))
    if read_build_provenance(report_path, root / "autocar", root / "stealth-pilot") != valid:
        raise AssertionError("valid report at the input-size limit was rejected")
    reordered = copy.deepcopy(valid)
    reordered["autocar"]["modules"].reverse()
    write_json(report_path, reordered)
    if read_build_provenance(report_path, root / "autocar", root / "stealth-pilot") != valid:
        raise AssertionError("valid module order was not normalized")
    for field in ("build_info", "control_binary"):
        original = getattr(args, field)
        setattr(args, field, str(Path(__file__).resolve()))
        try:
            prepare(args)
        except SystemExit:
            pass
        else:
            raise AssertionError("provenance input outside inputs-root was accepted")
        finally:
            setattr(args, field, original)
    future_native = copy.deepcopy(valid)
    for role in ("autocar", "control"):
        future_native[role]["modules"][0].update(requested_version="v0.64.0", source_version="v0.64.0")
    write_json(report_path, future_native)
    prepare(args)
    cover = read_json(Path(args.output))["products"]["cover"]["variants"][0]
    if (
        cover["name"] != "quic-go-standard-h3-control"
        or cover["client_implementation"] != "quic-go v0.64.0 standard H3 control (not a browser)"
        or cover["server_implementation"] != "quic-go v0.64.0 HTTP/3 fixture"
        or cover["implementation_version"] != "v0.64.0-calibration-control"
    ):
        raise AssertionError("control labels did not follow the validated effective version")
    write_json(report_path, valid)


def fail(message: str) -> None:
    raise SystemExit(message)


if __name__ == "__main__":
    raise SystemExit(main())
