#!/usr/bin/env python3
"""Fail-closed, offline release evidence aggregator for the stealth gate.

The checker performs no capture and opens no network connection. It binds two
independent active manifests and one passive campaign to the exact clean Git
commit being packaged, then re-hashes every referenced local evidence file.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any


SCHEMA_VERSION = 1
STATUS_VALUES = {"pass", "tie", "fail", "insufficient_evidence"}
MODEL_NAMES = {"single_feature_rule", "logistic_l2", "tree_depth_3"}
PINNED_HYSTERIA_HASHES = {
    "6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94",
    "ebfacc1ec3a0edfd742cd68ce17f292a6092e606b9d11f99b035c1d888f3d709",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")


class InsufficientEvidence(RuntimeError):
    pass


class GateFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidenceSnapshot:
    """One stable in-memory read of a small evidence input."""

    path: Path
    data: bytes
    sha256: str
    stat_signature: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class CaptureSnapshot:
    """Streaming identity of a PCAP without retaining its payload bytes."""

    declared_path: Path
    path: Path
    sha256: str
    size: int
    stat_signature: tuple[int, int, int, int, int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-active", help="local-docker active manifest JSON")
    parser.add_argument("--remote-active", help="remote-linux active manifest JSON")
    parser.add_argument(
        "--expected-remote-host",
        help="exact operator-declared host:port required in remote active evidence",
    )
    parser.add_argument("--extraction", help="passive extraction status JSON")
    parser.add_argument("--scores", help="passive classifier score JSON")
    parser.add_argument("--campaign", help="passive campaign provenance JSON")
    parser.add_argument("--capture-manifest", help="passive capture manifest CSV")
    parser.add_argument("--features", help="extracted passive feature CSV")
    parser.add_argument("--autocar-binary", help="AutoCAR binary used by the passive campaign")
    parser.add_argument("--autocar-config", help="effective AutoCAR passive-campaign configuration")
    parser.add_argument("--hysteria-binary", help="pinned Hysteria binary used by the passive campaign")
    parser.add_argument("--hysteria-config", help="effective Hysteria passive-campaign configuration")
    parser.add_argument(
        "--preregistration",
        default="testdata/stealth/preregistration.json",
        help="frozen checked-in preregistration JSON",
    )
    parser.add_argument("--expected-commit", help="exact Git commit being released")
    parser.add_argument("--repo-root", default=".", help="clean Git repository being released")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print(json.dumps({"status": "pass", "self_test": True}, sort_keys=True))
        return 0
    required = (
        "local_active",
        "remote_active",
        "expected_remote_host",
        "extraction",
        "scores",
        "campaign",
        "capture_manifest",
        "features",
        "autocar_binary",
        "autocar_config",
        "hysteria_binary",
        "hysteria_config",
        "preregistration",
        "expected_commit",
    )
    missing = ["--" + name.replace("_", "-") for name in required if not getattr(args, name, None)]
    if missing:
        print("required arguments missing: " + ", ".join(missing), file=sys.stderr)
        return 2
    try:
        report = validate_release(args, verify_repo=True)
    except InsufficientEvidence as error:
        report = {"schema_version": SCHEMA_VERSION, "status": "insufficient_evidence", "reason": str(error)}
        print(json.dumps(report, sort_keys=True))
        return 2
    except Exception as error:
        report = {"schema_version": SCHEMA_VERSION, "status": "fail", "reason": str(error)}
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


def validate_release(args: argparse.Namespace | SimpleNamespace, verify_repo: bool) -> dict[str, Any]:
    expected_commit = str(args.expected_commit).strip().lower()
    if not COMMIT_RE.fullmatch(expected_commit):
        raise GateFailure("--expected-commit must be a full hexadecimal Git object ID")

    paths = {
        "local_active": evidence_file(args.local_active),
        "remote_active": evidence_file(args.remote_active),
        "extraction": evidence_file(args.extraction),
        "scores": evidence_file(args.scores),
        "campaign": evidence_file(args.campaign),
        "capture_manifest": evidence_file(args.capture_manifest),
        "features": evidence_file(args.features),
        "autocar_binary": evidence_file(args.autocar_binary),
        "autocar_config": evidence_file(args.autocar_config),
        "hysteria_binary": evidence_file(args.hysteria_binary),
        "hysteria_config": evidence_file(args.hysteria_config),
        "preregistration": evidence_file(args.preregistration),
    }
    reject_duplicate_evidence_files(paths)

    repo_root = Path(args.repo_root).resolve()
    if verify_repo:
        validate_repository(repo_root, expected_commit, paths["preregistration"])

    snapshots = snapshot_evidence_files(paths)
    documents = {
        name: load_json_unique(snapshots[name].data, name)
        for name in ("local_active", "remote_active", "extraction", "scores", "campaign")
    }
    preregistration_document = load_json_unique(
        snapshots["preregistration"].data, "preregistration"
    )
    expected_remote_host = validate_execution_host(
        args.expected_remote_host, "--expected-remote-host"
    )
    active_policy = preregistration_document.get("active_evidence")
    if not isinstance(active_policy, dict):
        raise GateFailure("preregistration omitted active_evidence policy")
    registered_remote_host = validate_execution_host(
        active_policy.get("remote_execution_host"),
        "preregistration remote_execution_host",
    )
    registered_remote_ssh_key = validate_ssh_host_key_fingerprint(
        active_policy.get("remote_ssh_host_key_ed25519_sha256"),
        "preregistration remote ED25519 SSH host key",
    )
    if expected_remote_host != registered_remote_host:
        raise GateFailure(
            "--expected-remote-host does not match the checked-in preregistration"
        )
    validate_active(
        documents["local_active"],
        "local-docker",
        expected_commit,
        "local-docker",
        "not-applicable",
    )
    validate_active(
        documents["remote_active"],
        "remote-linux",
        expected_commit,
        expected_remote_host,
        registered_remote_ssh_key,
    )
    if snapshots["local_active"].data == snapshots["remote_active"].data:
        raise GateFailure("local and remote active evidence are byte-identical")
    if documents["local_active"]["docker_engine_fingerprint"] == documents["remote_active"]["docker_engine_fingerprint"]:
        raise GateFailure("local and remote active evidence came from the same Docker engine")

    preregistration_sha256 = snapshots["preregistration"].sha256
    capture_manifest_sha256 = snapshots["capture_manifest"].sha256
    feature_sha256 = snapshots["features"].sha256
    validate_extraction(
        documents["extraction"], paths["capture_manifest"], capture_manifest_sha256, feature_sha256
    )
    validate_scores(documents["scores"], documents["extraction"], preregistration_sha256, feature_sha256)
    validate_campaign(
        documents["campaign"],
        expected_commit,
        preregistration_sha256,
        capture_manifest_sha256,
        snapshots,
    )
    capture_snapshots = validate_capture_files(
        snapshots["capture_manifest"], documents["extraction"]
    )

    # Every validation and reported digest above is derived from the immutable
    # first-read snapshots. Refuse success if a pathname changed meanwhile.
    assert_snapshots_unchanged(snapshots)
    assert_capture_snapshots_unchanged(capture_snapshots)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "decision": "release_evidence_complete",
        "autocar_commit": expected_commit,
        "active_roles": ["local-docker", "remote-linux"],
        "remote_execution_host": expected_remote_host,
        "remote_ssh_host_key_ed25519_sha256": registered_remote_ssh_key,
        "passive_decision": documents["scores"]["decision"],
        "sample_count": documents["scores"]["sample_count"],
        "input_sha256": {
            name: snapshot.sha256 for name, snapshot in sorted(snapshots.items())
        },
    }


def evidence_file(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_file():
        raise InsufficientEvidence(f"evidence file not found: {path}")
    if path.stat().st_size == 0:
        raise InsufficientEvidence(f"evidence file is empty: {path}")
    return path


def reject_duplicate_evidence_files(paths: dict[str, Path]) -> None:
    canonical: dict[Path, str] = {}
    for name, path in paths.items():
        prior = canonical.get(path)
        if prior is not None:
            raise GateFailure(f"{name} reuses the same evidence path as {prior}")
        canonical[path] = name


def stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def snapshot_file(path: Path, label: str) -> EvidenceSnapshot:
    """Read a file once, rejecting mutation or replacement during that read."""

    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            data = handle.read()
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise InsufficientEvidence(f"cannot read {label} evidence file: {path}") from error
    if stat_signature(before) != stat_signature(after) or len(data) != after.st_size:
        raise GateFailure(f"{label} changed while its evidence snapshot was read")
    if not data:
        raise InsufficientEvidence(f"evidence file is empty: {path}")
    return EvidenceSnapshot(
        path=path,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        stat_signature=stat_signature(after),
    )


def snapshot_evidence_files(paths: dict[str, Path]) -> dict[str, EvidenceSnapshot]:
    snapshots = {name: snapshot_file(path, name) for name, path in paths.items()}
    identities: dict[tuple[int, int], str] = {}
    for name, snapshot in snapshots.items():
        identity = snapshot.stat_signature[:2]
        prior = identities.get(identity)
        if prior is not None:
            raise GateFailure(f"{name} reuses the same evidence inode as {prior}")
        identities[identity] = name
    return snapshots


def assert_snapshots_unchanged(snapshots: dict[str, EvidenceSnapshot]) -> None:
    for name, original in snapshots.items():
        try:
            current = snapshot_file(original.path, name)
        except (InsufficientEvidence, GateFailure) as error:
            raise GateFailure(f"{name} changed while release evidence was checked") from error
        if (
            current.stat_signature != original.stat_signature
            or current.sha256 != original.sha256
            or current.data != original.data
        ):
            raise GateFailure(f"{name} changed while release evidence was checked")


def snapshot_capture_file(path: Path, label: str) -> CaptureSnapshot:
    """Hash one PCAP incrementally and reject mutation during the read."""

    # Keep the lexical manifest pathname, rather than resolving it once and
    # forgetting how the manifest reached the file.  This makes the final
    # recheck detect a pathname that was replaced with a symlink or whose
    # resolved target changed after the first hash.  A platform-level parent
    # alias such as macOS /var -> /private/var is allowed, but its resolved
    # target is bound into the snapshot.
    declared = Path(os.path.abspath(path))
    try:
        declared_before = declared.lstat()
        canonical_before = declared.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise InsufficientEvidence(f"cannot read {label} evidence file: {declared}") from error
    if not stat.S_ISREG(declared_before.st_mode):
        raise GateFailure(f"{label} must be a regular file, not a symbolic link")

    digest = hashlib.sha256()
    bytes_read = 0
    try:
        with declared.open("rb") as handle:
            before = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
                bytes_read += len(chunk)
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise InsufficientEvidence(f"cannot read {label} evidence file: {path}") from error
    try:
        declared_after = declared.lstat()
        canonical_after = declared.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise GateFailure(f"{label} changed while its evidence snapshot was read") from error
    if (
        stat_signature(declared_before) != stat_signature(before)
        or stat_signature(before) != stat_signature(after)
        or stat_signature(after) != stat_signature(declared_after)
        or canonical_after != canonical_before
        or bytes_read != after.st_size
    ):
        raise GateFailure(f"{label} changed while its evidence snapshot was read")
    if bytes_read == 0:
        raise InsufficientEvidence(f"evidence file is empty: {declared}")
    return CaptureSnapshot(
        declared_path=declared,
        path=canonical_before,
        sha256=digest.hexdigest(),
        size=bytes_read,
        stat_signature=stat_signature(after),
    )


def assert_capture_snapshots_unchanged(snapshots: dict[str, CaptureSnapshot]) -> None:
    """Re-hash every PCAP without ever retaining the corpus in memory."""

    for name, original in snapshots.items():
        try:
            current = snapshot_capture_file(original.declared_path, name)
        except (InsufficientEvidence, GateFailure) as error:
            raise GateFailure(f"{name} changed while release evidence was checked") from error
        if (
            current.path != original.path
            or current.declared_path != original.declared_path
            or current.stat_signature != original.stat_signature
            or current.sha256 != original.sha256
            or current.size != original.size
        ):
            raise GateFailure(f"{name} changed while release evidence was checked")


def load_json_unique(data: bytes, label: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GateFailure(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure(f"cannot parse {label} JSON: {error}") from error
    if not isinstance(value, dict):
        raise GateFailure(f"{label} must contain one JSON object")
    return value


def validate_repository(repo_root: Path, expected_commit: str, preregistration: Path) -> None:
    head = git_output(repo_root, "rev-parse", "--verify", "HEAD").lower()
    if head != expected_commit:
        raise GateFailure(f"current HEAD {head} does not match evidence commit {expected_commit}")
    if git_output(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise GateFailure("release checkout is not clean")
    try:
        relative = preregistration.relative_to(repo_root)
    except ValueError as error:
        raise GateFailure("preregistration must be inside the release repository") from error
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "--error-unmatch", "--", str(relative)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise GateFailure("preregistration is not tracked by the release commit")


def git_output(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise GateFailure("Git command failed: " + " ".join(args))
    return completed.stdout.strip()


def validate_execution_host(value: Any, label: str) -> str:
    if not isinstance(value, str) or value != value.strip() or len(value) > 300:
        raise GateFailure(f"{label} must be an exact host or host:port label")
    match = re.fullmatch(
        r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?)"
        r"(?::(?P<port>[0-9]{1,5}))?",
        value,
    )
    if match is None or ".." in value:
        raise GateFailure(f"{label} must be an exact host or host:port label")
    hostname = match.group("host").lower()
    port = match.group("port")
    if port is not None and not 1 <= int(port) <= 65535:
        raise GateFailure(f"{label} contains an invalid port")
    if hostname in {"localhost", "unspecified"} or hostname.endswith(".localhost"):
        raise GateFailure(f"{label} cannot name a loopback or unspecified host")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_unspecified or address.is_multicast):
        raise GateFailure(f"{label} cannot name a loopback, unspecified, or multicast address")
    return hostname + ((":" + port) if port is not None else "")


def validate_ssh_host_key_fingerprint(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value) is None:
        raise GateFailure(f"{label} is not a SHA-256 SSH host-key fingerprint")
    return value


def validate_active(
    document: dict[str, Any],
    role: str,
    expected_commit: str,
    expected_execution_host: str,
    expected_ssh_host_key: str,
) -> None:
    require_status(document, f"{role} active", {"pass"})
    allowed_fields = {
        "schema_version", "status", "harness_status", "scope", "run_role",
        "execution_host", "execution_host_ssh_key_ed25519_sha256", "host_os",
        "host_architecture", "autocar_commit", "autocar_commit_start",
        "autocar_commit_end", "autocar_tree_start", "autocar_tree_end",
        "build_context_source", "autocar_image", "lab_image",
        "docker_network_internal", "docker_network_allow_cidr",
        "docker_engine_fingerprint", "hysteria2_version",
        "hysteria2_active_probe_exit", "hysteria2_active_probe_status",
        "hysteria2_active_probe_observed_status", "hysteria2_healthy_path",
        "hysteria2_udp_blackhole_new_flow", "hysteria2_tcp_cover",
        "hysteria2_gecko", "autocar_active", "autocar_transition", "iterations",
        "release_gate", "release_evidence_complete", "worktree_clean",
        "worktree_clean_start", "worktree_clean_end", "source_state_unchanged",
        "host_firewall_or_qdisc_modified", "secrets_in_artifacts",
    }
    unknown_fields = set(document) - allowed_fields
    if unknown_fields:
        raise GateFailure(f"{role} active contains unknown fields: {sorted(unknown_fields)}")
    missing_fields = allowed_fields - set(document)
    if missing_fields:
        raise InsufficientEvidence(f"{role} active omitted fields: {sorted(missing_fields)}")
    actual_execution_host = validate_execution_host(
        document.get("execution_host"), f"{role} active execution_host"
    )
    if actual_execution_host != expected_execution_host:
        raise GateFailure(
            f"{role} active execution_host {actual_execution_host!r} does not match "
            f"expected host {expected_execution_host!r}"
        )
    actual_ssh_host_key = document.get("execution_host_ssh_key_ed25519_sha256")
    if actual_ssh_host_key != expected_ssh_host_key or not isinstance(actual_ssh_host_key, str):
        raise GateFailure(f"{role} active SSH host-key fingerprint does not match expected identity")
    expected_values: dict[str, Any] = {
        "status": "pass",
        "schema_version": 3,
        "harness_status": "pass",
        "scope": "active_probe_and_userspace_udp_blackhole",
        "run_role": role,
        "host_os": "Linux" if role == "remote-linux" else "Darwin",
        "autocar_commit": expected_commit,
        "autocar_commit_start": expected_commit,
        "autocar_commit_end": expected_commit,
        "build_context_source": "git_archive",
        "release_gate": 1,
        "release_evidence_complete": True,
        "worktree_clean": True,
        "worktree_clean_start": True,
        "worktree_clean_end": True,
        "source_state_unchanged": True,
        "docker_network_internal": True,
        "hysteria2_version": "v2.12.2",
        "hysteria2_active_probe_exit": 0,
        "hysteria2_active_probe_status": "pass",
        "hysteria2_active_probe_observed_status": "pass",
        "hysteria2_healthy_path": "pass",
        "hysteria2_udp_blackhole_new_flow": "pass",
        "hysteria2_tcp_cover": "pass",
        "hysteria2_gecko": "pass",
        "autocar_active": "pass",
        "autocar_transition": "pass",
        "host_firewall_or_qdisc_modified": False,
        "secrets_in_artifacts": False,
    }
    for key, expected in expected_values.items():
        actual = document.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise InsufficientEvidence(f"{role} active field {key!r} is not {expected!r}")
    if type(document.get("iterations")) is not int or document["iterations"] < 100:
        raise InsufficientEvidence(f"{role} active evidence has fewer than 100 iterations")
    for key in ("autocar_image", "lab_image"):
        value = document.get(key)
        if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise GateFailure(f"{role} active field {key!r} is not an image ID")
    if type(document.get("host_architecture")) is not str or not document["host_architecture"]:
        raise GateFailure(f"{role} active host architecture is missing")
    for key in ("autocar_tree_start", "autocar_tree_end"):
        value = document.get(key)
        if type(value) is not str or not COMMIT_RE.fullmatch(value):
            raise GateFailure(f"{role} active field {key!r} is not a full Git tree ID")
    if document["autocar_tree_start"] != document["autocar_tree_end"]:
        raise GateFailure(f"{role} active Git tree changed during the run")
    engine_fingerprint = document.get("docker_engine_fingerprint")
    if type(engine_fingerprint) is not str or not COMMIT_RE.fullmatch(engine_fingerprint):
        raise GateFailure(f"{role} active Docker engine fingerprint is missing or malformed")
    allow_cidr = document.get("docker_network_allow_cidr")
    if type(allow_cidr) is not str or not allow_cidr:
        raise GateFailure(f"{role} active evidence omitted its exact Docker allowlist CIDR")
    try:
        network = ipaddress.ip_network(allow_cidr, strict=True)
    except ValueError as error:
        raise GateFailure(f"{role} active Docker allowlist CIDR is malformed") from error
    if not (network.is_private or network.is_loopback) or network.is_link_local:
        raise GateFailure(f"{role} active Docker allowlist CIDR is outside isolated space")
    if role == "remote-linux" and document.get("host_os") != "Linux":
        raise GateFailure("remote-linux active evidence was not produced on a Linux host")


def validate_extraction(
    document: dict[str, Any], capture_manifest: Path, manifest_sha256: str, feature_sha256: str
) -> None:
    require_status(document, "passive extraction", {"pass"})
    if document.get("manifest_sha256") != manifest_sha256:
        raise GateFailure("extraction manifest digest does not match the supplied capture manifest")
    if document.get("feature_sha256") != feature_sha256:
        raise GateFailure("extraction feature digest does not match the supplied feature table")
    if document.get("address_fields_emitted") is not False or document.get("decryption_used") is not False:
        raise GateFailure("passive extraction privacy controls are not asserted")
    samples = document.get("samples")
    digests = document.get("capture_digests")
    if not isinstance(samples, int) or samples <= 0 or not isinstance(digests, list) or len(digests) != samples:
        raise InsufficientEvidence("extraction does not contain one capture digest per sample")
    _ = capture_manifest


def validate_scores(
    document: dict[str, Any], extraction: dict[str, Any], preregistration_sha256: str, feature_sha256: str
) -> None:
    require_status(document, "passive score", {"pass"})
    if document.get("decision") != "superior_in_preregistered_scope":
        raise InsufficientEvidence("passive score did not prove superiority in the preregistered scope")
    if document.get("feature_table_sha256") != feature_sha256:
        raise GateFailure("score feature digest does not match the supplied feature table")
    if document.get("preregistration_sha256") != preregistration_sha256:
        raise GateFailure("score preregistration digest does not match the checked-in contract")
    if document.get("sample_count") != extraction.get("samples"):
        raise GateFailure("score and extraction sample counts differ")
    models = document.get("models")
    if not isinstance(models, dict) or set(models) != MODEL_NAMES:
        raise InsufficientEvidence("passive score does not contain exactly the three preregistered models")
    if any(not isinstance(value, dict) or value.get("passed") is not True for value in models.values()):
        raise InsufficientEvidence("at least one preregistered passive model gate did not pass")


def validate_campaign(
    document: dict[str, Any],
    expected_commit: str,
    preregistration_sha256: str,
    manifest_sha256: str,
    snapshots: dict[str, EvidenceSnapshot],
) -> None:
    require_status(document, "passive campaign", {"pass"})
    expected = {
        "schema_version": SCHEMA_VERSION,
        "autocar_commit": expected_commit,
        "preregistration_git_commit": expected_commit,
        "preregistration_sha256": preregistration_sha256,
        "capture_manifest_sha256": manifest_sha256,
        "claim_scope": "hysteria2-v2.12.2-standard",
        "preregistration_recorded_before_capture": True,
    }
    for key, value in expected.items():
        if document.get(key) != value:
            raise InsufficientEvidence(f"passive campaign field {key!r} is not {value!r}")
    started = parse_timestamp(document.get("capture_started_at"), "capture_started_at")
    completed = parse_timestamp(document.get("capture_completed_at"), "capture_completed_at")
    registered = parse_timestamp(document.get("preregistration_recorded_at"), "preregistration_recorded_at")
    if not registered < started < completed:
        raise GateFailure("campaign timestamps do not prove preregistration before a non-empty capture interval")

    products = document.get("products")
    if not isinstance(products, dict) or set(products) != {"autocar", "hysteria2", "cover"}:
        raise InsufficientEvidence("campaign products must be exactly autocar, hysteria2, and cover")
    autocar = require_object(products.get("autocar"), "campaign autocar provenance")
    if autocar.get("commit") != expected_commit:
        raise GateFailure("campaign AutoCAR commit differs from the release commit")
    if (
        require_sha256(autocar.get("binary_sha256"), "campaign AutoCAR binary")
        != snapshots["autocar_binary"].sha256
    ):
        raise GateFailure("campaign AutoCAR binary digest does not match the supplied binary")
    if (
        require_sha256(autocar.get("config_sha256"), "campaign AutoCAR config")
        != snapshots["autocar_config"].sha256
    ):
        raise GateFailure("campaign AutoCAR config digest does not match the supplied effective configuration")
    hysteria = require_object(products.get("hysteria2"), "campaign Hysteria provenance")
    if hysteria.get("version") != "v2.12.2" or hysteria.get("commit") != "619a6f8":
        raise GateFailure("campaign Hysteria provenance is not the pinned v2.12.2 build")
    if hysteria.get("binary_sha256") not in PINNED_HYSTERIA_HASHES:
        raise GateFailure("campaign Hysteria binary digest is not a pinned official build")
    if hysteria.get("binary_sha256") != snapshots["hysteria_binary"].sha256:
        raise GateFailure("campaign Hysteria digest does not match the supplied binary")
    if (
        require_sha256(hysteria.get("config_sha256"), "campaign Hysteria config")
        != snapshots["hysteria_config"].sha256
    ):
        raise GateFailure("campaign Hysteria config digest does not match the supplied effective configuration")
    cover = require_object(products.get("cover"), "campaign cover provenance")
    require_diverse_implementations(cover.get("client_implementations"), "cover client")
    require_diverse_implementations(cover.get("server_implementations"), "cover server")
    if cover.get("real_browser_h2_h3_present") is not True:
        raise InsufficientEvidence("campaign lacks asserted real-browser H2/H3 cover samples")


def validate_capture_files(
    manifest_snapshot: EvidenceSnapshot, extraction: dict[str, Any]
) -> dict[str, CaptureSnapshot]:
    entries = extraction.get("capture_digests")
    expected: dict[str, tuple[str, int]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise GateFailure("extraction capture digest entry is not an object")
        sample_id = str(entry.get("sample_id", ""))
        digest = str(entry.get("sha256", ""))
        size = entry.get("bytes")
        if (
            not sample_id
            or sample_id in expected
            or not SHA256_RE.fullmatch(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise GateFailure("extraction capture digest entries are empty, duplicate, or malformed")
        expected[sample_id] = (digest, size)

    try:
        manifest_text = manifest_snapshot.data.decode("utf-8")
        reader = csv.DictReader(io.StringIO(manifest_text, newline=""))
        if not reader.fieldnames or not {"sample_id", "pcap"}.issubset(reader.fieldnames):
            raise GateFailure("capture manifest lacks sample_id or pcap")
        rows = list(reader)
    except (UnicodeError, csv.Error) as error:
        raise GateFailure(f"cannot parse capture manifest CSV: {error}") from error
    if len(rows) != len(expected):
        raise GateFailure("capture manifest and extraction digest counts differ")
    root = manifest_snapshot.path.parent
    seen_paths: dict[Path, str] = {}
    seen_hashes: dict[str, str] = {}
    seen_samples: set[str] = set()
    capture_snapshots: dict[str, CaptureSnapshot] = {}
    for row_number, row in enumerate(rows, start=2):
        sample_id = row["sample_id"].strip()
        if not sample_id or sample_id in seen_samples or sample_id not in expected:
            raise GateFailure(f"capture manifest row {row_number} has an unknown or duplicate sample_id")
        seen_samples.add(sample_id)
        path = Path(row["pcap"])
        if not path.is_absolute():
            path = root / path
        try:
            canonical = path.resolve(strict=True)
        except (FileNotFoundError, OSError) as error:
            raise InsufficientEvidence(f"capture for sample {sample_id} is missing") from error
        prior_path = seen_paths.get(canonical)
        if prior_path is not None:
            raise GateFailure(f"samples {prior_path} and {sample_id} reuse one canonical PCAP path")
        capture_snapshot = snapshot_capture_file(path, f"capture for sample {sample_id}")
        digest = capture_snapshot.sha256
        prior_hash = seen_hashes.get(digest)
        if prior_hash is not None:
            raise GateFailure(f"samples {prior_hash} and {sample_id} reuse identical PCAP bytes")
        expected_digest, expected_size = expected[sample_id]
        if digest != expected_digest or capture_snapshot.size != expected_size:
            raise GateFailure(f"capture digest changed after extraction for sample {sample_id}")
        seen_paths[canonical] = sample_id
        seen_hashes[digest] = sample_id
        capture_snapshots[f"capture for sample {sample_id}"] = capture_snapshot
    return capture_snapshots


def require_status(document: dict[str, Any], label: str, allowed: set[str]) -> None:
    status = document.get("status")
    if status not in STATUS_VALUES:
        raise GateFailure(f"{label} has invalid status vocabulary {status!r}")
    if status not in allowed:
        raise InsufficientEvidence(f"{label} status is {status!r}, not pass")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InsufficientEvidence(f"{label} is missing")
    return value


def require_sha256(value: Any, label: str) -> str:
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise GateFailure(f"{label} SHA-256 is missing or malformed")
    return text


def require_diverse_implementations(value: Any, label: str) -> None:
    if not isinstance(value, list) or len(value) < 2:
        raise InsufficientEvidence(f"campaign needs at least two {label} implementations")
    normalized = {str(item).strip().lower() for item in value if str(item).strip()}
    if len(normalized) < 2:
        raise InsufficientEvidence(f"campaign {label} implementations are not distinct")


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise InsufficientEvidence(f"campaign {label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateFailure(f"campaign {label} is not ISO-8601") from error
    if parsed.tzinfo is None:
        raise GateFailure(f"campaign {label} must include a timezone")
    return parsed


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def self_test() -> None:
    from unittest.mock import patch

    commit = "a" * 40
    ssh_fingerprint = "SHA256:" + "A" * 43
    with tempfile.TemporaryDirectory(prefix="autocar-stealth-release-check.") as directory:
        root = Path(directory)
        missing = root / "missing-evidence.json"
        try:
            snapshot_file(missing, "missing fixture")
        except InsufficientEvidence as error:
            assert str(error) == f"cannot read missing fixture evidence file: {missing}"
            assert isinstance(error.__cause__, FileNotFoundError)
        else:
            raise AssertionError("missing evidence did not report insufficient evidence")

        # Mock the read error so this remains deterministic when tests run as
        # root, which can read a chmod(000) fixture on many filesystems.
        permission_error = PermissionError("self-test denied evidence read")
        with patch.object(Path, "open", side_effect=permission_error):
            try:
                snapshot_file(root / "unreadable-evidence.json", "unreadable fixture")
            except InsufficientEvidence as error:
                assert "cannot read unreadable fixture evidence file:" in str(error)
                assert error.__cause__ is permission_error
            else:
                raise AssertionError("unreadable evidence did not report insufficient evidence")

        capture = root / "capture.pcap"
        # Cross at least two 1 MiB streaming boundaries so the self-test would
        # catch a regression back to a single short read.
        capture.write_bytes((b"one independent capture\n" * 100000) + b"tail")
        capture_hash = file_sha256(capture)
        manifest = root / "manifest.csv"
        manifest.write_text("sample_id,pcap\nsample-one,capture.pcap\n", encoding="utf-8")
        features = root / "features.csv"
        features.write_text("schema_version,sample_id\n1,sample-one\n", encoding="utf-8")
        preregistration = root / "preregistration.json"
        write_json(
            preregistration,
            {
                "schema_version": 1,
                "active_evidence": {
                    "remote_execution_host": "198.51.100.10:22",
                    "remote_ssh_host_key_ed25519_sha256": ssh_fingerprint,
                },
            },
        )
        autocar_binary = root / "autocar"
        autocar_binary.write_bytes(b"autocar passive binary")
        autocar_config = root / "autocar.json"
        autocar_config.write_bytes(b"autocar effective config")
        hysteria_binary = root / "hysteria"
        hysteria_binary.write_bytes(b"pinned hysteria binary fixture")
        hysteria_config = root / "hysteria.yaml"
        hysteria_config.write_bytes(b"hysteria effective config")
        pinned_fixture_hash = file_sha256(hysteria_binary)
        PINNED_HYSTERIA_HASHES.add(pinned_fixture_hash)

        def active(role: str) -> dict[str, Any]:
            return {
                "status": "pass",
                "schema_version": 3,
                "harness_status": "pass",
                "scope": "active_probe_and_userspace_udp_blackhole",
                "run_role": role,
                "execution_host": "198.51.100.10:22" if role == "remote-linux" else "local-docker",
                "execution_host_ssh_key_ed25519_sha256": (
                    ssh_fingerprint if role == "remote-linux" else "not-applicable"
                ),
                "host_os": "Linux" if role == "remote-linux" else "Darwin",
                "host_architecture": "x86_64" if role == "remote-linux" else "arm64",
                "autocar_commit": commit,
                "autocar_commit_start": commit,
                "autocar_commit_end": commit,
                "autocar_tree_start": "b" * 40,
                "autocar_tree_end": "b" * 40,
                "build_context_source": "git_archive",
                "autocar_image": "sha256:" + "e" * 64,
                "lab_image": "sha256:" + "f" * 64,
                "release_gate": 1,
                "release_evidence_complete": True,
                "worktree_clean": True,
                "worktree_clean_start": True,
                "worktree_clean_end": True,
                "source_state_unchanged": True,
                "docker_network_internal": True,
                "docker_network_allow_cidr": "172.20.0.0/16",
                "docker_engine_fingerprint": ("c" if role == "local-docker" else "d") * 40,
                "hysteria2_version": "v2.12.2",
                "hysteria2_active_probe_exit": 0,
                "hysteria2_active_probe_status": "pass",
                "hysteria2_active_probe_observed_status": "pass",
                "hysteria2_healthy_path": "pass",
                "hysteria2_udp_blackhole_new_flow": "pass",
                "hysteria2_tcp_cover": "pass",
                "hysteria2_gecko": "pass",
                "autocar_active": "pass",
                "autocar_transition": "pass",
                "iterations": 100,
                "host_firewall_or_qdisc_modified": False,
                "secrets_in_artifacts": False,
            }

        local = root / "local.json"
        remote = root / "remote.json"
        write_json(local, active("local-docker"))
        write_json(remote, active("remote-linux"))
        extraction = root / "extraction.json"
        write_json(
            extraction,
            {
                "status": "pass",
                "manifest_sha256": file_sha256(manifest),
                "feature_sha256": file_sha256(features),
                "address_fields_emitted": False,
                "decryption_used": False,
                "samples": 1,
                "capture_digests": [{"sample_id": "sample-one", "sha256": capture_hash, "bytes": capture.stat().st_size}],
            },
        )
        scores = root / "scores.json"
        write_json(
            scores,
            {
                "status": "pass",
                "decision": "superior_in_preregistered_scope",
                "feature_table_sha256": file_sha256(features),
                "preregistration_sha256": file_sha256(preregistration),
                "sample_count": 1,
                "models": {name: {"passed": True} for name in MODEL_NAMES},
            },
        )
        campaign = root / "campaign.json"
        write_json(
            campaign,
            {
                "schema_version": 1,
                "status": "pass",
                "autocar_commit": commit,
                "preregistration_git_commit": commit,
                "preregistration_sha256": file_sha256(preregistration),
                "capture_manifest_sha256": file_sha256(manifest),
                "claim_scope": "hysteria2-v2.12.2-standard",
                "preregistration_recorded_before_capture": True,
                "preregistration_recorded_at": "2026-01-01T00:00:00Z",
                "capture_started_at": "2026-01-02T00:00:00Z",
                "capture_completed_at": "2026-01-03T00:00:00Z",
                "products": {
                    "autocar": {
                        "commit": commit,
                        "binary_sha256": file_sha256(autocar_binary),
                        "config_sha256": file_sha256(autocar_config),
                    },
                    "hysteria2": {
                        "version": "v2.12.2",
                        "commit": "619a6f8",
                        "binary_sha256": pinned_fixture_hash,
                        "config_sha256": file_sha256(hysteria_config),
                    },
                    "cover": {
                        "client_implementations": ["chromium", "firefox"],
                        "server_implementations": ["nginx", "caddy"],
                        "real_browser_h2_h3_present": True,
                    },
                },
            },
        )
        args = SimpleNamespace(
            local_active=str(local),
            remote_active=str(remote),
            expected_remote_host="198.51.100.10:22",
            extraction=str(extraction),
            scores=str(scores),
            campaign=str(campaign),
            capture_manifest=str(manifest),
            features=str(features),
            autocar_binary=str(autocar_binary),
            autocar_config=str(autocar_config),
            hysteria_binary=str(hysteria_binary),
            hysteria_config=str(hysteria_config),
            preregistration=str(preregistration),
            expected_commit=commit,
            repo_root=str(root),
        )
        report = validate_release(args, verify_repo=False)
        assert report["status"] == "pass"
        assert report["input_sha256"]["remote_active"] == file_sha256(remote)

        capture_snapshots = validate_capture_files(
            snapshot_file(manifest, "capture_manifest"),
            load_json_unique(snapshot_file(extraction, "extraction").data, "extraction"),
        )
        capture_snapshot = capture_snapshots["capture for sample sample-one"]
        assert isinstance(capture_snapshot, CaptureSnapshot)
        assert capture_snapshot.size == capture.stat().st_size
        assert capture_snapshot.sha256 == capture_hash
        assert not hasattr(capture_snapshot, "data")
        assert_capture_snapshots_unchanged(capture_snapshots)

        original_capture = capture.read_bytes()
        capture.write_bytes(original_capture + b" changed")
        try:
            assert_capture_snapshots_unchanged(capture_snapshots)
        except GateFailure as error:
            assert "changed while release evidence was checked" in str(error)
        else:
            raise AssertionError("a PCAP mutation after streaming snapshotting was accepted")
        finally:
            capture.write_bytes(original_capture)

        alternate_capture = root / "alternate.pcap"
        alternate_capture.write_bytes(original_capture)
        capture.unlink()
        capture.symlink_to(alternate_capture.name)
        try:
            assert_capture_snapshots_unchanged(capture_snapshots)
        except GateFailure as error:
            assert "changed while release evidence was checked" in str(error)
            assert isinstance(error.__cause__, GateFailure)
            assert "not a symbolic link" in str(error.__cause__)
        else:
            raise AssertionError("a PCAP pathname changed to a symlink was accepted")
        finally:
            capture.unlink()
            capture.write_bytes(original_capture)

        duplicate_args = SimpleNamespace(**vars(args))
        duplicate_args.remote_active = str(local)
        try:
            validate_release(duplicate_args, verify_repo=False)
        except GateFailure as error:
            assert "same evidence path" in str(error)
        else:
            raise AssertionError("duplicate local/remote active evidence was accepted")

        mismatched_host_args = SimpleNamespace(**vars(args))
        mismatched_host_args.expected_remote_host = "203.0.113.10:22"
        try:
            validate_release(mismatched_host_args, verify_repo=False)
        except GateFailure as error:
            assert "checked-in preregistration" in str(error)
        else:
            raise AssertionError("remote host outside the preregistration was accepted")

        def assert_remote_rejected(
            candidate: dict[str, Any],
            error_type: type[Exception],
            error_fragment: str,
            assertion_message: str,
        ) -> None:
            write_json(remote, candidate)
            try:
                validate_release(args, verify_repo=False)
            except error_type as error:
                assert error_fragment in str(error), str(error)
            else:
                raise AssertionError(assertion_message)
            finally:
                write_json(remote, active("remote-linux"))

        wrong_remote = active("remote-linux")
        wrong_remote["execution_host"] = "jump.example.invalid:24"
        assert_remote_rejected(
            wrong_remote,
            GateFailure,
            "execution_host",
            "remote evidence from a different execution host was accepted",
        )

        missing_field = active("remote-linux")
        del missing_field["scope"]
        assert_remote_rejected(
            missing_field,
            InsufficientEvidence,
            "omitted fields",
            "remote evidence with a missing schema field was accepted",
        )

        unknown_field = active("remote-linux")
        unknown_field["unregistered_attestation"] = True
        assert_remote_rejected(
            unknown_field,
            GateFailure,
            "unknown fields",
            "remote evidence with an unknown schema field was accepted",
        )

        type_spoof = active("remote-linux")
        type_spoof["release_gate"] = True  # bool compares equal to int(1) without exact type checks.
        assert_remote_rejected(
            type_spoof,
            InsufficientEvidence,
            "release_gate",
            "remote evidence with a bool-for-int type spoof was accepted",
        )

        old_schema = active("remote-linux")
        old_schema["schema_version"] = 2
        assert_remote_rejected(
            old_schema,
            InsufficientEvidence,
            "schema_version",
            "remote evidence using an old schema was accepted",
        )

        wrong_ssh_key = active("remote-linux")
        wrong_ssh_key["execution_host_ssh_key_ed25519_sha256"] = "SHA256:" + "B" * 43
        assert_remote_rejected(
            wrong_ssh_key,
            GateFailure,
            "SSH host-key fingerprint",
            "remote evidence with the wrong SSH host key was accepted",
        )

        remote_snapshot = snapshot_file(remote, "remote_active")
        remote.write_bytes(remote_snapshot.data + b"\n")
        try:
            assert_snapshots_unchanged({"remote_active": remote_snapshot})
        except GateFailure as error:
            assert "changed while release evidence was checked" in str(error)
        else:
            raise AssertionError("an evidence input mutation after snapshotting was accepted")
        finally:
            remote.write_bytes(remote_snapshot.data)


if __name__ == "__main__":
    raise SystemExit(main())
