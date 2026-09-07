#!/usr/bin/env python3
"""Validate and audit the formal 31,510-capture offline campaign pipeline.

This helper is intentionally standard-library-only.  The shell wrapper runs it
inside the same pinned, network-disabled image used for feature extraction and
classification.  A compact JSON audit refers to a separately streamed PCAP
inventory instead of embedding tens of thousands of capture records.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
REQUIRED_SAMPLES = 31_500
AUXILIARY_SAMPLES = 10
TOTAL_SAMPLES = REQUIRED_SAMPLES + AUXILIARY_SAMPLES
PRODUCTS = ("cover", "autocar", "hysteria2")
MANIFEST_FIELDS = (
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
    "client_implementation",
    "server_implementation",
    "implementation_version",
    "runner_image_id",
    "server_container_id",
    "capture_host",
    "docker_engine_fingerprint",
)
INVENTORY_FIELDS = ("sample_id", "path", "bytes", "sha256")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
RISKY_NAME_RE = re.compile(
    r"(?:^|[._-])(token|secret|password|private)(?:[._-]|$)|\.(?:key|pem|p12|pfx)$",
    re.IGNORECASE,
)
FORBIDDEN_FEATURE_TOKENS = {
    "addr",
    "address",
    "cert",
    "certificate",
    "filename",
    "host",
    "ip",
    "ipv4",
    "ipv6",
    "path",
    "pcap",
    "port",
    "sni",
}
META_COLUMNS = {
    "schema_version",
    "sample_id",
    "product",
    "scenario",
    "workload",
    "wire_profile",
    "run_id",
    "seed",
}
BASE_IMAGE = (
    "alpine:3.24@sha256:"
    "28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
)
TOOL_PINS = {
    "python_package": "python3=3.14.7-r1",
    "tshark_package": "tshark=4.6.6-r0",
}
TOOL_INPUT_PATHS = (
    "scripts/stealth-offline.Dockerfile",
    "scripts/stealth-full-offline.sh",
    "scripts/stealth-full-offline.py",
    "scripts/stealth-features.py",
    "scripts/stealth-classify.py",
    "testdata/stealth/preregistration.json",
)


class AuditError(RuntimeError):
    """The retained inputs or outputs cannot support a formal audit."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-input")
    validate.add_argument("--campaign-dir", required=True)
    validate.add_argument("--preregistration", required=True)
    validate.add_argument("--output-dir", required=True)

    binding = commands.add_parser("repo-binding")
    binding.add_argument("--repo", required=True)
    binding.add_argument("--plan", required=True)
    binding.add_argument("--output", required=True)
    binding.add_argument("--phase", required=True)
    binding.add_argument("--runtime-repo")

    audit = commands.add_parser("audit")
    audit.add_argument("--campaign-dir", required=True)
    audit.add_argument("--repo", required=True)
    audit.add_argument("--output-dir", required=True)
    audit.add_argument("--image-reference", required=True)
    audit.add_argument("--image-id", required=True)
    audit.add_argument("--docker-endpoint", required=True)
    audit.add_argument("--runtime-user", required=True)
    audit.add_argument("--validation-exit", required=True)
    audit.add_argument("--extraction-exit", required=True)
    audit.add_argument("--classification-exit", required=True)

    commands.add_parser("self-test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "self-test":
        self_test()
        print(compact_json({"schema_version": 1, "status": "pass", "self_test": True}))
        return 0
    if args.command == "validate-input":
        output = Path(args.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        try:
            report = validate_input(
                Path(args.campaign_dir), Path(args.preregistration), output
            )
        except Exception as error:
            report = {
                "schema_version": SCHEMA_VERSION,
                "status": "fail",
                "reason": str(error),
            }
            write_json_atomic(output / "input-validation.json", report)
            print(compact_json(report))
            return 1
        write_json_atomic(output / "input-validation.json", report)
        print(compact_json({"status": "pass", "samples": report["counts"]["total"]}))
        return 0
    if args.command == "repo-binding":
        try:
            report = capture_repo_binding(
                Path(args.repo), Path(args.plan), args.phase,
                Path(args.runtime_repo) if args.runtime_repo else None,
            )
        except Exception as error:
            report = {
                "schema_version": SCHEMA_VERSION,
                "status": "fail",
                "phase": args.phase,
                "reason": str(error),
            }
            write_json_atomic(Path(args.output), report)
            print(compact_json(report))
            return 1
        write_json_atomic(Path(args.output), report)
        print(compact_json({"status": "pass", "phase": args.phase}))
        return 0
    try:
        report, passed = create_audit(
            campaign_dir=Path(args.campaign_dir),
            repo=Path(args.repo),
            output=Path(args.output_dir),
            image_reference=args.image_reference,
            image_id=args.image_id,
            docker_endpoint=args.docker_endpoint,
            runtime_user=args.runtime_user,
            stage_exits={
                "validation": args.validation_exit,
                "extraction": args.extraction_exit,
                "classification": args.classification_exit,
            },
        )
    except Exception as error:
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "fail",
            "evidence_complete": False,
            "reason": f"audit generation failed: {error}",
        }
        passed = False
    write_json_atomic(Path(args.output_dir) / "audit.json", report)
    print(compact_json({"status": report["status"], "evidence_complete": passed}))
    return 0 if passed else 1


def validate_input(campaign_dir: Path, preregistration_path: Path, output: Path) -> dict[str, Any]:
    root = campaign_dir.resolve(strict=True)
    if not root.is_dir():
        raise AuditError("FULL_CAMPAIGN_DIR is not a directory")
    preregistration_path = preregistration_path.resolve(strict=True)
    campaign_path = checked_file(root, "campaign.json")
    manifest_path = checked_file(root, "capture-manifest.csv")
    plan_path = checked_file(root, "plan.json")
    state_path = checked_file(root, "state.json")
    events_path = checked_file(root, "events.jsonl")

    campaign = read_object(campaign_path, "campaign")
    plan = read_object(plan_path, "plan")
    state = read_object(state_path, "state")
    prereg = read_object(preregistration_path, "preregistration")
    campaign_sha256 = sha256(campaign_path)
    manifest_sha256 = sha256(manifest_path)
    preregistration_sha256 = sha256(preregistration_path)

    validate_campaign_documents(
        campaign, plan, state, manifest_sha256, preregistration_sha256
    )
    cells = preregistered_cells(prereg)
    completions = read_completion_ledger(events_path)
    if len(completions) != TOTAL_SAMPLES:
        raise AuditError(
            f"completion ledger has {len(completions)} completed samples; need {TOTAL_SAMPLES}"
        )

    inventory_path = output / "pcap-inventory.csv"
    descriptor, temporary = tempfile.mkstemp(
        prefix=inventory_path.name + ".", dir=output
    )
    sample_ids: set[str] = set()
    manifest_sample_order: list[str] = []
    pcap_paths: set[Path] = set()
    pcap_hashes: set[str] = set()
    required_counts: Counter[tuple[str, str, str, str]] = Counter()
    group_counts: Counter[tuple[str, str, str, str, str]] = Counter()
    auxiliary_rows: list[dict[str, str]] = []
    manifest_rows = 0
    try:
        with manifest_path.open(newline="", encoding="utf-8") as source, os.fdopen(
            descriptor, "w", newline="", encoding="utf-8"
        ) as destination:
            reader = csv.DictReader(source)
            if tuple(reader.fieldnames or ()) != MANIFEST_FIELDS:
                raise AuditError("capture manifest does not have the frozen schema and column order")
            writer = csv.DictWriter(destination, fieldnames=INVENTORY_FIELDS, lineterminator="\n")
            writer.writeheader()
            for row_number, row in enumerate(reader, start=2):
                manifest_rows += 1
                validate_manifest_row_shape(row, row_number)
                sample_id = row["sample_id"]
                if sample_id in sample_ids:
                    raise AuditError(f"manifest row {row_number} duplicates sample_id {sample_id!r}")
                sample_ids.add(sample_id)
                manifest_sample_order.append(sample_id)
                completion = completions.get(sample_id)
                if completion is None:
                    raise AuditError(f"manifest sample {sample_id!r} is absent from completion ledger")
                if completion["manifest_row_sha256"] != object_sha256(row):
                    raise AuditError(f"manifest sample {sample_id!r} differs from completion ledger")

                pcap_relative = Path(row["pcap"])
                if pcap_relative.is_absolute():
                    raise AuditError(f"manifest row {row_number} uses an absolute PCAP path")
                pcap = (root / pcap_relative).resolve(strict=True)
                require_beneath(root, pcap, f"manifest row {row_number} PCAP")
                if not pcap.is_file():
                    raise AuditError(f"manifest row {row_number} PCAP is not a regular file")
                expected_relative = Path("pcaps") / f"{sample_id}.pcap"
                if pcap_relative != expected_relative:
                    raise AuditError(
                        f"manifest row {row_number} PCAP path is not the frozen sample path"
                    )
                if pcap in pcap_paths:
                    raise AuditError(f"manifest row {row_number} reuses a PCAP path")
                pcap_paths.add(pcap)
                pcap_sha256 = sha256(pcap)
                if pcap_sha256 in pcap_hashes:
                    raise AuditError(f"manifest row {row_number} reuses PCAP bytes")
                pcap_hashes.add(pcap_sha256)
                if completion["pcap_sha256"] != pcap_sha256:
                    raise AuditError(f"PCAP hash for {sample_id!r} differs from completion ledger")
                pcap_bytes = pcap.stat().st_size
                if completion["pcap_bytes"] != pcap_bytes:
                    raise AuditError(f"PCAP size for {sample_id!r} differs from completion ledger")
                writer.writerow(
                    {
                        "sample_id": sample_id,
                        "path": pcap_relative.as_posix(),
                        "bytes": pcap_bytes,
                        "sha256": pcap_sha256,
                    }
                )

                if row["wire_profile"] == "h3":
                    key = (row["product"], row["scenario"], row["workload"], "h3")
                    required_counts[key] += 1
                    group_counts[key + (row["run_id"],)] += 1
                    validate_receipt(row, completion.get("workload_receipt"), required=True)
                elif row["wire_profile"] == "h2":
                    auxiliary_rows.append(row)
                    validate_receipt(row, completion.get("workload_receipt"), required=True)
                else:
                    raise AuditError(f"manifest row {row_number} has unsupported wire_profile")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, inventory_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    if set(completions) != sample_ids:
        raise AuditError("completion ledger contains samples absent from the manifest")
    if list(completions) != manifest_sample_order:
        raise AuditError("completion ledger and manifest sample order differ")
    validate_formal_counts(
        manifest_rows, required_counts, group_counts, auxiliary_rows, cells
    )
    if sha256(manifest_path) != manifest_sha256:
        raise AuditError("capture manifest changed while its PCAPs were inventoried")
    if sha256(campaign_path) != campaign_sha256:
        raise AuditError("campaign.json changed while inputs were inventoried")

    privacy = scan_input_privacy(root)
    if not privacy["passed"]:
        raise AuditError("retained campaign metadata failed the plaintext secret check")

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "reason": "formal campaign structure, ledger lineage, and PCAP identity verified",
        "counts": {
            "required_h3": REQUIRED_SAMPLES,
            "auxiliary_cover_browser_h2": AUXILIARY_SAMPLES,
            "total": TOTAL_SAMPLES,
            "unique_sample_ids": len(sample_ids),
            "unique_pcap_paths": len(pcap_paths),
            "unique_pcap_sha256": len(pcap_hashes),
        },
        "input_sha256": {
            "campaign.json": campaign_sha256,
            "capture-manifest.csv": manifest_sha256,
            "plan.json": sha256(plan_path),
            "state.json": sha256(state_path),
            "events.jsonl": sha256(events_path),
            "preregistration.json": preregistration_sha256,
            "pcap-inventory.csv": sha256(inventory_path),
        },
        "pcap_inventory": {
            "file": "pcap-inventory.csv",
            "rows": TOTAL_SAMPLES,
            "embedded_in_audit": False,
        },
        "browser_controls": {
            "campaign_real_browser_h2_h3_present": True,
            "all_cover_receipts_verified": True,
            "h2_client_implementations": sorted(
                {row["client_implementation"] for row in auxiliary_rows}
            ),
        },
        "privacy_check": privacy,
    }


def capture_repo_binding(
    repo: Path,
    plan_path: Path,
    phase: str,
    runtime_repo: Path | None = None,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    plan_path = plan_path.resolve(strict=True)
    if not repo.is_dir():
        raise AuditError("repository root is not a directory")
    top = git(repo, "rev-parse", "--show-toplevel")
    if Path(top).resolve(strict=True) != repo:
        raise AuditError("repository argument is not the exact Git top level")
    dirty = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise AuditError("formal offline processing requires a clean Git worktree")
    head = git(repo, "rev-parse", "--verify", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    plan = read_object(plan_path, "campaign plan")
    source = plan.get("identity", {}).get("source")
    if not isinstance(source, dict):
        raise AuditError("campaign plan identity.source is missing")
    if source.get("git_dirty") is not False:
        raise AuditError("campaign plan did not freeze a clean source tree")
    if source.get("git_head") != head or source.get("git_tree") != tree:
        raise AuditError("current Git HEAD/tree differs from the captured campaign plan")

    tool_sha256: dict[str, str] = {}
    for relative in TOOL_INPUT_PATHS:
        path = checked_file(repo, relative)
        tracked = subprocess.run(
            ["git", "-C", str(repo), "show", f"HEAD:{relative}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if tracked.returncode != 0 or tracked.stdout != path.read_bytes():
            raise AuditError(f"runtime tool is not byte-identical to HEAD: {relative}")
        tool_sha256[relative] = sha256(path)
    runtime_tool_sha256: dict[str, str] | None = None
    if runtime_repo is not None:
        runtime_repo = runtime_repo.resolve(strict=True)
        runtime_tool_sha256 = {
            relative: sha256(checked_file(runtime_repo, relative))
            for relative in TOOL_INPUT_PATHS
        }
        if runtime_tool_sha256 != tool_sha256:
            raise AuditError("immutable runtime snapshot tool hashes differ from Git HEAD")
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "phase": phase,
        "repository_clean": True,
        "git_head": head,
        "git_tree": tree,
        "plan_git_head": source["git_head"],
        "plan_git_tree": source["git_tree"],
        "plan_sha256": sha256(plan_path),
        "tool_sha256": tool_sha256,
    }
    if runtime_tool_sha256 is not None:
        report["runtime_snapshot_tool_sha256"] = runtime_tool_sha256
    return report


def validate_campaign_documents(
    campaign: Mapping[str, Any],
    plan: Mapping[str, Any],
    state: Mapping[str, Any],
    manifest_sha256: str,
    preregistration_sha256: str,
) -> None:
    driver = campaign.get("driver")
    if not isinstance(driver, dict):
        raise AuditError("campaign driver report is missing")
    expected_driver = {
        "mode": "full",
        "required_samples": REQUIRED_SAMPLES,
        "auxiliary_samples": AUXILIARY_SAMPLES,
        "completed_samples": TOTAL_SAMPLES,
    }
    if campaign.get("schema_version") != 1 or campaign.get("status") != "pass":
        raise AuditError("campaign.json status is not a formal pass")
    for key, expected in expected_driver.items():
        if driver.get(key) != expected:
            raise AuditError(f"campaign driver {key} is not {expected!r}")
    if campaign.get("capture_manifest_sha256") != manifest_sha256:
        raise AuditError("campaign manifest digest does not match capture-manifest.csv")
    if campaign.get("preregistration_sha256") != preregistration_sha256:
        raise AuditError("campaign preregistration digest does not match the mounted repository")
    if campaign.get("preregistration_recorded_before_capture") is not True:
        raise AuditError("campaign does not prove preregistration preceded capture")
    cover = campaign.get("products", {}).get("cover", {})
    if cover.get("real_browser_h2_h3_present") is not True:
        raise AuditError("campaign does not attest real-browser H2/H3 controls")

    identity = plan.get("identity")
    if not isinstance(identity, dict):
        raise AuditError("plan identity is missing")
    plan_expected = {
        "mode": "full",
        "required_sample_count": REQUIRED_SAMPLES,
        "auxiliary_sample_count": AUXILIARY_SAMPLES,
        "total_sample_count": TOTAL_SAMPLES,
        "groups": 5,
        "samples_per_product_cell_group": 100,
        "include_cover_h2": True,
    }
    for key, expected in plan_expected.items():
        if identity.get(key) != expected:
            raise AuditError(f"frozen plan {key} is not {expected!r}")
    if identity.get("preregistration_sha256") != preregistration_sha256:
        raise AuditError("plan preregistration digest differs from mounted repository")
    if identity.get("configuration_sha256") != driver.get("configuration_sha256"):
        raise AuditError("campaign and plan configuration digests differ")
    if identity.get("schedule_sha256") != driver.get("schedule_sha256"):
        raise AuditError("campaign and plan schedule digests differ")
    if state.get("schema_version") != 1 or state.get("status") != "complete":
        raise AuditError("campaign state is not complete")
    if state.get("completed_samples") != TOTAL_SAMPLES or state.get("total_samples") != TOTAL_SAMPLES:
        raise AuditError("campaign state sample counts are incomplete")


def preregistered_cells(prereg: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    if prereg.get("schema_version") != 1:
        raise AuditError("unsupported preregistration schema")
    if prereg.get("minimum_groups_per_product_cell") != 5:
        raise AuditError("preregistration does not require exactly five groups")
    if prereg.get("minimum_samples_per_product_cell_group") != 100:
        raise AuditError("preregistration does not require exactly 100 samples per group")
    baseline = prereg.get("baseline")
    if not isinstance(baseline, dict) or (
        baseline.get("hysteria2_version") != "v2.12.2"
        or baseline.get("disable_update_check") is not True
        or baseline.get("local_http_proxy_connection_header")
        != "Proxy-Connection: keep-alive"
    ):
        raise AuditError("preregistration does not freeze the Hysteria workload controls")
    if prereg.get("sample_attempt_policy") != {
        "maximum_attempts_per_sample": 1,
        "retry_failed_or_interrupted_sample": False,
        "checkpoint_boundary": "after_sample_complete",
    }:
        raise AuditError("preregistration does not enforce first-attempt-only evidence")
    raw = prereg.get("required_common_cells")
    if not isinstance(raw, list):
        raise AuditError("preregistration required_common_cells is missing")
    cells: set[tuple[str, str, str]] = set()
    for number, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise AuditError(f"preregistration cell {number} is not an object")
        try:
            cell = (item["scenario"], item["workload"], item["wire_profile"])
        except KeyError as error:
            raise AuditError(f"preregistration cell {number} is incomplete") from error
        if not all(isinstance(value, str) and value for value in cell) or cell[2] != "h3":
            raise AuditError(f"preregistration cell {number} is not a non-empty H3 cell")
        if cell in cells:
            raise AuditError("preregistration contains duplicate common cells")
        cells.add(cell)
    if len(cells) != 21:
        raise AuditError(f"preregistration has {len(cells)} common cells; need 21")
    return cells


def read_completion_ledger(path: Path) -> dict[str, dict[str, Any]]:
    completions: dict[str, dict[str, Any]] = {}
    open_sample: tuple[str, str] | None = None
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if len(line) > (1 << 20):
                raise AuditError(f"events ledger line {line_number} exceeds 1 MiB")
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise AuditError(f"events ledger line {line_number} is invalid JSON") from error
            if not isinstance(event, dict):
                raise AuditError(f"events ledger line {line_number} is not an object")
            event_kind = event.get("event")
            sample_id = event.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise AuditError(f"events ledger line {line_number} has an invalid sample ID")
            parse_ledger_time(event.get("at"), line_number)
            if event_kind == "sample_started":
                if set(event) != {"event", "at", "sample_id", "variant"}:
                    raise AuditError(f"events ledger line {line_number} has an invalid start schema")
                variant = event.get("variant")
                if not isinstance(variant, str) or not variant:
                    raise AuditError(f"events ledger line {line_number} has an invalid variant")
                if open_sample is not None or sample_id in completions:
                    raise AuditError(
                        f"events ledger line {line_number} starts a repeated or interleaved attempt"
                    )
                open_sample = (sample_id, variant)
                continue
            if event_kind == "sample_failed":
                raise AuditError(
                    f"events ledger line {line_number} records a failed attempt; "
                    "retry-selected evidence is not admissible"
                )
            if event_kind != "sample_complete":
                raise AuditError(f"events ledger line {line_number} has an unsupported event")
            complete_fields = {
                "event", "at", "sample_id", "variant", "packets", "pcap_sha256",
                "pcap_bytes", "manifest_row",
            }
            if set(event) not in (complete_fields, complete_fields | {"workload_receipt"}):
                raise AuditError(
                    f"events ledger line {line_number} has an invalid completion schema"
                )
            if open_sample != (sample_id, event.get("variant")):
                raise AuditError(
                    f"events ledger line {line_number} completes without its single adjacent start"
                )
            pcap_sha256 = event.get("pcap_sha256")
            pcap_bytes = event.get("pcap_bytes")
            packets = event.get("packets")
            manifest_row = event.get("manifest_row")
            if sample_id in completions:
                raise AuditError(f"events ledger line {line_number} has a duplicate/invalid completion")
            if not isinstance(pcap_sha256, str) or SHA256_RE.fullmatch(pcap_sha256) is None:
                raise AuditError(f"events ledger line {line_number} has an invalid PCAP digest")
            if not isinstance(pcap_bytes, int) or pcap_bytes <= 24:
                raise AuditError(f"events ledger line {line_number} has an invalid PCAP size")
            if not isinstance(packets, int) or isinstance(packets, bool) or packets <= 0:
                raise AuditError(f"events ledger line {line_number} has an invalid packet count")
            if not isinstance(manifest_row, dict) or set(manifest_row) != set(MANIFEST_FIELDS):
                raise AuditError(f"events ledger line {line_number} has an invalid manifest row")
            if any(not isinstance(manifest_row.get(field), str) for field in MANIFEST_FIELDS):
                raise AuditError(f"events ledger line {line_number} has non-string manifest data")
            completions[sample_id] = {
                "pcap_sha256": pcap_sha256,
                "pcap_bytes": pcap_bytes,
                "manifest_row_sha256": object_sha256(manifest_row),
                "workload_receipt": event.get("workload_receipt"),
            }
            open_sample = None
    if open_sample is not None:
        raise AuditError(f"events ledger ends during the first attempt for {open_sample[0]!r}")
    return completions


def parse_ledger_time(value: Any, line_number: int) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise AuditError(f"events ledger line {line_number} has an invalid timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuditError(f"events ledger line {line_number} has an invalid timestamp") from error
    if parsed.tzinfo is None:
        raise AuditError(f"events ledger line {line_number} timestamp lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_manifest_row_shape(row: Mapping[str, Any], row_number: int) -> None:
    for field in MANIFEST_FIELDS:
        value = row.get(field)
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise AuditError(f"manifest row {row_number} has invalid {field}")
    if row["product"] not in PRODUCTS:
        raise AuditError(f"manifest row {row_number} has an unsupported product")


def validate_receipt(
    row: Mapping[str, str], receipt: Any, *, required: bool
) -> None:
    if row["product"] != "cover":
        if receipt is not None:
            raise AuditError(f"non-cover sample {row['sample_id']!r} has a browser receipt")
        return
    if not required or not isinstance(receipt, dict):
        raise AuditError(f"cover sample {row['sample_id']!r} lacks a browser receipt")
    expected_fields = {
        "schema_version", "status", "kind", "client_implementation",
        "implementation_version", "browser_binary_sha256", "protocol",
        "workload", "sample_seed", "next_hop_protocols", "request_count",
        "response_bytes", "result_sha256",
    }
    if set(receipt) != expected_fields:
        raise AuditError(f"cover sample {row['sample_id']!r} receipt schema is invalid")
    expected = {
        "schema_version": 1,
        "status": "pass",
        "kind": "real-browser-workload",
        "protocol": row["wire_profile"],
        "workload": row["workload"],
        "client_implementation": row["client_implementation"],
        "implementation_version": row["implementation_version"],
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise AuditError(
                f"cover sample {row['sample_id']!r} receipt {key} differs from manifest"
            )
    if (
        not isinstance(receipt.get("sample_seed"), int)
        or isinstance(receipt["sample_seed"], bool)
        or receipt["sample_seed"] < 0
    ):
        raise AuditError(f"cover sample {row['sample_id']!r} has invalid sample seed")
    protocols = receipt.get("next_hop_protocols")
    if not isinstance(protocols, list) or not protocols or set(protocols) != {row["wire_profile"]}:
        raise AuditError(f"cover sample {row['sample_id']!r} has invalid browser protocol evidence")
    digest = receipt.get("browser_binary_sha256")
    result_digest = receipt.get("result_sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise AuditError(f"cover sample {row['sample_id']!r} has invalid browser binary digest")
    if not isinstance(result_digest, str) or SHA256_RE.fullmatch(result_digest) is None:
        raise AuditError(f"cover sample {row['sample_id']!r} has invalid result digest")
    if (
        not isinstance(receipt.get("request_count"), int)
        or isinstance(receipt["request_count"], bool)
        or receipt["request_count"] < 1
    ):
        raise AuditError(f"cover sample {row['sample_id']!r} has invalid request count")
    if (
        not isinstance(receipt.get("response_bytes"), int)
        or isinstance(receipt["response_bytes"], bool)
        or receipt["response_bytes"] < 0
    ):
        raise AuditError(f"cover sample {row['sample_id']!r} has invalid response byte count")


def validate_formal_counts(
    manifest_rows: int,
    required_counts: Mapping[tuple[str, str, str, str], int],
    group_counts: Mapping[tuple[str, str, str, str, str], int],
    auxiliary_rows: Sequence[Mapping[str, str]],
    cells: set[tuple[str, str, str]],
) -> None:
    if manifest_rows != TOTAL_SAMPLES:
        raise AuditError(f"manifest has {manifest_rows} rows; need exactly {TOTAL_SAMPLES}")
    expected = {
        (product, scenario, workload, wire)
        for scenario, workload, wire in cells
        for product in PRODUCTS
    }
    if set(required_counts) != expected:
        raise AuditError("manifest H3 cells/products differ from preregistration")
    if any(required_counts[key] != 500 for key in expected):
        raise AuditError("manifest does not contain exactly 500 samples per product/cell")
    for key in expected:
        grouped = {
            group: count
            for (*prefix, group), count in group_counts.items()
            if tuple(prefix) == key
        }
        if len(grouped) != 5 or set(grouped.values()) != {100}:
            raise AuditError("manifest does not contain five 100-sample groups per product/cell")
    if sum(required_counts.values()) != REQUIRED_SAMPLES:
        raise AuditError(f"manifest does not contain exactly {REQUIRED_SAMPLES} required H3 samples")
    if len(auxiliary_rows) != AUXILIARY_SAMPLES:
        raise AuditError(f"manifest has {len(auxiliary_rows)} H2 controls; need 10")
    for row in auxiliary_rows:
        if (
            row["product"] != "cover"
            or row["scenario"] != "cover_diversity"
            or row["workload"] != "browser_h2"
            or row["wire_profile"] != "h2"
        ):
            raise AuditError("an auxiliary sample is not a cover/browser_h2/H2 control")
    implementations = Counter(row["client_implementation"] for row in auxiliary_rows)
    if len(implementations) != 2 or set(implementations.values()) != {5}:
        raise AuditError("H2 controls do not contain five samples from each of two browsers")
    runs = Counter(row["run_id"] for row in auxiliary_rows)
    if len(runs) != 5 or set(runs.values()) != {2}:
        raise AuditError("H2 controls do not contain both browsers in all five groups")


def scan_input_privacy(root: Path) -> dict[str, Any]:
    risky_names: list[str] = []
    plaintext_markers: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if RISKY_NAME_RE.search(path.name):
            risky_names.append(relative)
        if path.suffix.lower() in {".pcap", ".pcapng"}:
            continue
        if contains_plaintext_secret(path):
            plaintext_markers.append(relative)
    return {
        "scope": "retained non-PCAP campaign metadata; encrypted captures were not decrypted",
        "risky_retained_filenames": risky_names,
        "plaintext_secret_marker_files": plaintext_markers,
        "passed": not risky_names and not plaintext_markers,
    }


def create_audit(
    *,
    campaign_dir: Path,
    repo: Path,
    output: Path,
    image_reference: str,
    image_id: str,
    docker_endpoint: str,
    runtime_user: str,
    stage_exits: Mapping[str, str],
) -> tuple[dict[str, Any], bool]:
    campaign_dir = campaign_dir.resolve(strict=True)
    repo = repo.resolve(strict=True)
    output = output.resolve(strict=True)
    validation = read_optional_object(output / "input-validation.json")
    extraction = read_optional_object(output / "extraction.json")
    scores = read_optional_object(output / "scores.json")

    validation_ok = stage_exits["validation"] == "0" and validation.get("status") == "pass"
    extraction_ok = (
        stage_exits["extraction"] == "0"
        and extraction.get("status") == "pass"
        and extraction.get("samples") == TOTAL_SAMPLES
        and extraction.get("manifest_sha256")
        == validation.get("input_sha256", {}).get("capture-manifest.csv")
        and extraction.get("address_fields_emitted") is False
        and extraction.get("decryption_used") is False
    )
    lineage_ok, lineage_reason = compare_extraction_inventory(
        output / "pcap-inventory.csv", extraction
    )
    classification_ok, classification_reason = formal_classification_result(
        stage_exits["classification"], scores
    )
    if scores.get("sample_count") != TOTAL_SAMPLES:
        classification_ok = False
        classification_reason = "classification did not consume exactly 31,510 samples"
    if scores.get("feature_table_sha256") != extraction.get("feature_sha256"):
        classification_ok = False
        classification_reason = "classification feature digest differs from extraction"
    if scores.get("preregistration_sha256") != validation.get("input_sha256", {}).get(
        "preregistration.json"
    ):
        classification_ok = False
        classification_reason = "classification preregistration digest differs from validation"

    feature_privacy = inspect_feature_privacy(output / "features.csv", extraction, scores)
    output_privacy = scan_output_secrets(output)
    privacy_ok = feature_privacy["passed"] and output_privacy["passed"]
    toolchain = inspect_toolchain(output / "toolchain.txt")
    toolchain_ok = toolchain.pop("passed")

    live_input_hashes: dict[str, str] = {}
    for name in ("campaign.json", "capture-manifest.csv", "plan.json", "state.json", "events.jsonl"):
        path = checked_file(campaign_dir, name)
        live_input_hashes[name] = sha256(path)
    live_input_ok = all(
        live_input_hashes.get(name) == digest
        for name, digest in validation.get("input_sha256", {}).items()
        if name in live_input_hashes
    )

    tool_input_sha256 = {
        name: sha256(checked_file(repo, name)) for name in TOOL_INPUT_PATHS
    }
    binding_names = (
        "repo-binding-before-build.json",
        "repo-binding-before-runtime.json",
        "repo-binding-after-runtime.json",
    )
    bindings = [read_optional_object(output / name) for name in binding_names]
    binding_phases = ["before-build", "before-runtime", "after-runtime"]
    binding_core = (
        "git_head", "git_tree", "plan_git_head", "plan_git_tree",
        "plan_sha256", "tool_sha256",
    )
    repository_binding_ok = all(
        binding.get("status") == "pass"
        and binding.get("repository_clean") is True
        and binding.get("phase") == phase
        for binding, phase in zip(bindings, binding_phases)
    )
    if repository_binding_ok:
        reference = bindings[0]
        repository_binding_ok = all(
            all(binding.get(key) == reference.get(key) for key in binding_core)
            for binding in bindings[1:]
        )
        repository_binding_ok = (
            repository_binding_ok
            and reference.get("git_head") == reference.get("plan_git_head")
            and reference.get("git_tree") == reference.get("plan_git_tree")
            and reference.get("plan_sha256")
            == validation.get("input_sha256", {}).get("plan.json")
            and reference.get("tool_sha256") == tool_input_sha256
            and all(
                binding.get("runtime_snapshot_tool_sha256") == tool_input_sha256
                for binding in bindings[1:]
            )
        )

    outputs: dict[str, dict[str, Any]] = {}
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name not in {
            "audit.json", "audit.stdout.json", "audit.stderr.log"
        }:
            outputs[path.name] = {"bytes": path.stat().st_size, "sha256": sha256(path)}

    passed = all(
        (
            validation_ok,
            extraction_ok,
            lineage_ok,
            classification_ok,
            privacy_ok,
            toolchain_ok,
            live_input_ok,
            repository_binding_ok,
        )
    )
    comparison_status = scores.get("status") if classification_ok else "invalid"
    superiority = (
        classification_ok
        and scores.get("status") == "pass"
        and scores.get("decision") == "superior_in_preregistered_scope"
    )
    reasons = [
        reason
        for condition, reason in (
            (validation_ok, "formal input validation failed"),
            (extraction_ok, "feature extraction did not complete formally"),
            (lineage_ok, lineage_reason),
            (classification_ok, classification_reason),
            (privacy_ok, "privacy-field checks failed"),
            (toolchain_ok, "runtime toolchain does not match pins"),
            (live_input_ok, "campaign inputs changed after validation"),
            (repository_binding_ok, "repository HEAD/tree or runtime tool hashes drifted"),
        )
        if not condition
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if passed else "fail",
        "evidence_complete": passed,
        "reason": (
            "offline extraction and classification evidence is complete"
            if passed
            else "; ".join(reasons)
        ),
        "return_code_semantics": (
            "wrapper exit 0 means the offline evidence pipeline is complete; "
            "it does not by itself mean AutoCAR superiority"
        ),
        "comparison": {
            "status": comparison_status,
            "decision": scores.get("decision"),
            "reason": scores.get("reason"),
            "superiority_proven_in_preregistered_scope": superiority,
        },
        "runtime_isolation": {
            "docker_endpoint": docker_endpoint,
            "network_mode": "none",
            "input_mount_read_only": True,
            "repository_mount_read_only": True,
            "only_persistent_writable_mount": "output",
            "container_root_read_only": True,
            "capabilities_dropped": "ALL",
            "no_new_privileges": True,
            "runtime_user": runtime_user,
            "runtime_repository_is_immutable_head_snapshot": True,
        },
        "toolchain": {
            "image_reference": image_reference,
            "image_id": image_id,
            "base_image": BASE_IMAGE,
            **TOOL_PINS,
            "observed": toolchain,
            "input_sha256": tool_input_sha256,
        },
        "input": {
            "campaign_directory_name": campaign_dir.name,
            "validation": validation,
            "live_control_file_sha256": live_input_hashes,
            "pcap_inventory_file": "pcap-inventory.csv",
            "pcap_inventory_embedded": False,
            "repository_binding": {
                "passed": repository_binding_ok,
                "checked_phases": binding_phases,
                "git_head": bindings[0].get("git_head") if bindings else None,
                "git_tree": bindings[0].get("git_tree") if bindings else None,
                "plan_git_head": bindings[0].get("plan_git_head") if bindings else None,
                "plan_git_tree": bindings[0].get("plan_git_tree") if bindings else None,
                "repository_clean_at_every_check": all(
                    item.get("repository_clean") is True for item in bindings
                ),
                "tool_sha256": tool_input_sha256,
            },
        },
        "privacy_check": {
            "features": feature_privacy,
            "retained_outputs": output_privacy,
            "passed": privacy_ok,
        },
        "stages": {
            "validation": {
                "exit_code": stage_exits["validation"],
                "status": validation.get("status"),
            },
            "extraction": {
                "exit_code": stage_exits["extraction"],
                "status": extraction.get("status"),
                "lineage_verified": lineage_ok,
            },
            "classification": {
                "exit_code": stage_exits["classification"],
                "status": scores.get("status"),
                "formal_result_accepted": classification_ok,
            },
        },
        "outputs": outputs,
    }
    return report, passed


def compare_extraction_inventory(inventory_path: Path, extraction: Mapping[str, Any]) -> tuple[bool, str]:
    if not inventory_path.is_file():
        return False, "PCAP inventory is missing"
    raw_digests = extraction.get("capture_digests")
    if not isinstance(raw_digests, list) or len(raw_digests) != TOTAL_SAMPLES:
        return False, "extraction does not contain 31,510 capture identities"
    extracted: dict[str, tuple[str, int]] = {}
    for item in raw_digests:
        if not isinstance(item, dict):
            return False, "extraction capture identity is malformed"
        sample_id, digest, size = item.get("sample_id"), item.get("sha256"), item.get("bytes")
        if (
            not isinstance(sample_id, str)
            or sample_id in extracted
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(size, int)
        ):
            return False, "extraction capture identity is malformed or duplicated"
        extracted[sample_id] = (digest, size)
    seen = 0
    with inventory_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != INVENTORY_FIELDS:
            return False, "PCAP inventory schema is invalid"
        for row in reader:
            seen += 1
            try:
                expected = (row["sha256"], int(row["bytes"]))
            except (KeyError, ValueError):
                return False, "PCAP inventory row is malformed"
            if extracted.pop(row["sample_id"], None) != expected:
                return False, "extraction capture identity differs from PCAP inventory"
    if seen != TOTAL_SAMPLES or extracted:
        return False, "extraction and PCAP inventory sample sets differ"
    return True, "extraction capture identities match the streamed PCAP inventory"


def formal_classification_result(exit_code: str, scores: Mapping[str, Any]) -> tuple[bool, str]:
    expected = {
        ("0", "pass", "superior_in_preregistered_scope"),
        ("1", "tie", "superiority_not_proven"),
        ("1", "fail", "regression"),
    }
    observed = (exit_code, scores.get("status"), scores.get("decision"))
    if observed not in expected:
        return False, "classification was not a formal pass/superior, tie, or regression result"
    return True, "classification produced a complete formal decision"


def inspect_feature_privacy(
    path: Path, extraction: Mapping[str, Any], scores: Mapping[str, Any]
) -> dict[str, Any]:
    header: list[str] = []
    if path.is_file():
        with path.open(newline="", encoding="utf-8") as handle:
            header = next(csv.reader(handle), [])
    forbidden = sorted(
        name
        for name in header
        if name not in META_COLUMNS
        and FORBIDDEN_FEATURE_TOKENS.intersection(name.lower().replace("-", "_").split("_"))
    )
    leakage = scores.get("leakage_controls")
    leakage_ok = isinstance(leakage, dict) and all(
        leakage.get(key) is False
        for key in (
            "addresses_or_ports_as_features",
            "sample_id_as_feature",
            "capture_path_as_feature",
            "decrypted_fields",
        )
    )
    passed = (
        bool(header)
        and not forbidden
        and extraction.get("address_fields_emitted") is False
        and extraction.get("decryption_used") is False
        and leakage_ok
    )
    return {
        "forbidden_feature_columns": forbidden,
        "address_fields_emitted": extraction.get("address_fields_emitted"),
        "decryption_used": extraction.get("decryption_used"),
        "classifier_leakage_controls": leakage,
        "passed": passed,
    }


def scan_output_secrets(output: Path) -> dict[str, Any]:
    risky_names: list[str] = []
    plaintext_markers: list[str] = []
    for path in sorted(output.iterdir()):
        if not path.is_file() or path.name == "audit.json":
            continue
        if RISKY_NAME_RE.search(path.name):
            risky_names.append(path.name)
        if contains_plaintext_secret(path):
            plaintext_markers.append(path.name)
    return {
        "risky_filenames": risky_names,
        "plaintext_secret_marker_files": plaintext_markers,
        "passed": not risky_names and not plaintext_markers,
    }


def inspect_toolchain(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    checks = {
        "python_version": re.search(r"Python 3\.14\.7(?:\s|$)", text) is not None,
        "tshark_version": re.search(r"TShark[^\n]*4\.6\.6", text) is not None,
        "python_package": "python3-3.14.7-r1" in text,
        "tshark_package": "tshark-4.6.6-r0" in text,
    }
    return {"checks": checks, "passed": all(checks.values())}


def contains_plaintext_secret(path: Path) -> bool:
    """Scan arbitrary-size retained text/binary metadata for ASCII secret markers."""
    pattern = re.compile(
        rb"BEGIN [A-Z ]*PRIVATE KEY|authorization\s*:|bearer\s+|"
        rb"password\s*[:=]|secret\s*[:=]",
        re.IGNORECASE,
    )
    tail = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            candidate = tail + chunk
            if pattern.search(candidate):
                return True
            tail = candidate[-256:]
    return False


def checked_file(root: Path, relative: str) -> Path:
    path = (root / relative).resolve(strict=True)
    require_beneath(root, path, relative)
    if not path.is_file():
        raise AuditError(f"required file is not regular: {relative}")
    return path


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip().splitlines()[-1:] or ["unknown Git error"]
        raise AuditError(f"Git {' '.join(arguments)} failed: {diagnostic[0]}")
    return completed.stdout.rstrip("\n")


def require_beneath(root: Path, path: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AuditError(f"{label} escapes its read-only root") from error


def read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"could not read {label} JSON: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"{label} must be a JSON object")
    return value


def read_optional_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def object_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def compact_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="stealth-full-ledger-self-test.") as directory:
        ledger = Path(directory) / "events.jsonl"

        def pair(sample_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
            variant = "variant-1"
            row = {field: f"value-{field}" for field in MANIFEST_FIELDS}
            row["sample_id"] = sample_id
            started = {
                "event": "sample_started", "at": "2026-09-04T00:00:00Z",
                "sample_id": sample_id, "variant": variant,
            }
            complete = {
                "event": "sample_complete", "at": "2026-09-04T00:00:01Z",
                "sample_id": sample_id, "variant": variant, "packets": 5,
                "pcap_sha256": "a" * 64, "pcap_bytes": 64,
                "manifest_row": row,
            }
            return started, complete

        def write_events(events: Sequence[Mapping[str, Any]]) -> None:
            ledger.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )

        start_a, complete_a = pair("sample-a")
        start_b, complete_b = pair("sample-b")
        complete_b["pcap_sha256"] = "b" * 64
        write_events([start_a, complete_a, start_b, complete_b])
        if list(read_completion_ledger(ledger)) != ["sample-a", "sample-b"]:
            raise AssertionError("valid single-attempt ledger order was not retained")

        failed = {
            "event": "sample_failed", "at": "2026-09-04T00:00:01Z",
            "sample_id": "sample-a", "reason": "self-test failure",
        }
        unknown = {
            "event": "sample_retried", "at": "2026-09-04T00:00:01Z",
            "sample_id": "sample-a",
        }
        invalid_ledgers = (
            [complete_a],
            [start_a],
            [start_a, start_a, complete_a],
            [start_a, failed, start_a, complete_a],
            [start_a, start_b, complete_a, complete_b],
            [start_a, complete_a, start_a],
            [start_a, unknown, complete_a],
        )
        for events in invalid_ledgers:
            write_events(events)
            try:
                read_completion_ledger(ledger)
            except AuditError:
                pass
            else:
                raise AssertionError("retryable or malformed ledger was accepted")

    cells = {
        (f"scenario-{number:02d}", f"workload-{number:02d}", "h3")
        for number in range(21)
    }
    required_counts: Counter[tuple[str, str, str, str]] = Counter()
    group_counts: Counter[tuple[str, str, str, str, str]] = Counter()
    for scenario, workload, wire in cells:
        for product in PRODUCTS:
            key = (product, scenario, workload, wire)
            required_counts[key] = 500
            for group in range(5):
                group_counts[key + (f"run-{group + 1:02d}",)] = 100
    auxiliary = [
        {
            "product": "cover",
            "scenario": "cover_diversity",
            "workload": "browser_h2",
            "wire_profile": "h2",
            "run_id": f"run-{group + 1:02d}",
            "client_implementation": browser,
        }
        for group in range(5)
        for browser in ("Chromium", "Firefox ESR")
    ]
    validate_formal_counts(
        TOTAL_SAMPLES, required_counts, group_counts, auxiliary, cells
    )
    broken = list(auxiliary)
    broken[-1] = {**broken[-1], "workload": "download_128k"}
    try:
        validate_formal_counts(TOTAL_SAMPLES, required_counts, group_counts, broken, cells)
    except AuditError:
        pass
    else:
        raise AssertionError("invalid H2 auxiliary control was accepted")
    for valid in (
        ("0", {"status": "pass", "decision": "superior_in_preregistered_scope"}),
        ("1", {"status": "tie", "decision": "superiority_not_proven"}),
        ("1", {"status": "fail", "decision": "regression"}),
    ):
        if not formal_classification_result(*valid)[0]:
            raise AssertionError("formal classifier outcome was rejected")
    if formal_classification_result("1", {"status": "fail"})[0]:
        raise AssertionError("operational classifier failure was accepted as regression")
    header_report = inspect_feature_privacy(
        Path("/does/not/exist"), {}, {}
    )
    if header_report["passed"]:
        raise AssertionError("missing feature evidence passed privacy checks")

    with tempfile.TemporaryDirectory(prefix="stealth-full-offline-self-test.") as directory:
        root = Path(directory)
        repo = root / "repo"
        repo.mkdir()
        for number, relative in enumerate(TOOL_INPUT_PATHS):
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"tool-{number}\n", encoding="utf-8")
        for command in (
            ["git", "init", "-q", str(repo)],
            ["git", "-C", str(repo), "add", "."],
            [
                "git", "-C", str(repo), "-c", "commit.gpgsign=false",
                "-c", "user.name=AutoCAR Test", "-c", "user.email=test.invalid",
                "commit", "-qm", "self test",
            ],
        ):
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        head = git(repo, "rev-parse", "--verify", "HEAD")
        tree = git(repo, "rev-parse", "HEAD^{tree}")
        plan = root / "plan.json"
        write_json_atomic(
            plan,
            {
                "identity": {
                    "source": {
                        "git_head": head,
                        "git_tree": tree,
                        "git_dirty": False,
                    }
                }
            },
        )
        binding = capture_repo_binding(repo, plan, "self-test")
        if (
            binding["status"] != "pass"
            or binding["git_head"] != head
            or binding["git_tree"] != tree
            or set(binding["tool_sha256"]) != set(TOOL_INPUT_PATHS)
        ):
            raise AssertionError("clean repository binding was not captured")
        snapshot = root / "snapshot"
        for relative in TOOL_INPUT_PATHS:
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((repo / relative).read_bytes())
        snapshot_binding = capture_repo_binding(
            repo, plan, "snapshot-self-test", snapshot
        )
        if snapshot_binding.get("runtime_snapshot_tool_sha256") != binding["tool_sha256"]:
            raise AssertionError("runtime snapshot hashes were not bound to Git HEAD")
        (snapshot / TOOL_INPUT_PATHS[0]).write_text("wrong snapshot\n", encoding="utf-8")
        try:
            capture_repo_binding(repo, plan, "bad-snapshot-self-test", snapshot)
        except AuditError:
            pass
        else:
            raise AssertionError("runtime snapshot drift passed source binding")
        (repo / TOOL_INPUT_PATHS[0]).write_text("drifted\n", encoding="utf-8")
        try:
            capture_repo_binding(repo, plan, "dirty-self-test")
        except AuditError:
            pass
        else:
            raise AssertionError("dirty repository passed source binding")


if __name__ == "__main__":
    raise SystemExit(main())
