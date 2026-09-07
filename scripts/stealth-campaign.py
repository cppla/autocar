#!/usr/bin/env python3
"""Capture passive-comparison samples inside an explicitly owned Docker lab.

There is intentionally no SSH support.  The driver refuses remote Docker
contexts, host interfaces, public/link-local endpoints, unlabelled resources,
shell command strings, writable bind mounts, and shared client namespaces.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import signal
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = 1
PRODUCTS = ("cover", "autocar", "hysteria2")
LABEL_KEY = "com.cppla.autocar.stealth-campaign"
BASE_MANIFEST_FIELDS = (
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
)
PROVENANCE_FIELDS = (
    "client_implementation",
    "server_implementation",
    "implementation_version",
    "runner_image_id",
    "server_container_id",
    "capture_host",
    "docker_engine_fingerprint",
)
MANIFEST_FIELDS = BASE_MANIFEST_FIELDS + PROVENANCE_FIELDS
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
USER_RE = re.compile(r"[1-9][0-9]*(?::[1-9][0-9]*)?")
IFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
TEMPLATE_FIELDS = {
    "campaign_id",
    "sample_id",
    "product",
    "scenario",
    "workload",
    "wire_profile",
    "run_id",
    "seed",
    "sample_seed",
    "server_ip",
    "server_port",
}
RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
BROWSER_WORKLOAD_SPECS = {
    "idle": {"requests": 1, "response_bytes": 0, "upload_bytes": 0},
    "download_1k": {"requests": 1, "response_bytes": 1024, "upload_bytes": 0},
    "download_128k": {
        "requests": 1, "response_bytes": 128 * 1024, "upload_bytes": 0,
    },
    "download_1m": {
        "requests": 1, "response_bytes": 1024 * 1024, "upload_bytes": 0,
    },
    "upload_1m": {
        "requests": 1, "response_bytes": 32, "upload_bytes": 1024 * 1024,
    },
    "parallel_20": {
        "requests": 20, "response_bytes": 20 * 1024, "upload_bytes": 0,
    },
    "interactive": {
        "requests": 8, "response_bytes": 8 * 512, "upload_bytes": 8 * 256,
    },
    "browser_h2": {
        "requests": 1, "response_bytes": 128 * 1024, "upload_bytes": 0,
    },
}


class CampaignError(Exception):
    pass


class CampaignInterrupted(CampaignError):
    pass


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str


@dataclass(frozen=True)
class Variant:
    product: str
    name: str
    client_implementation: str
    server_implementation: str
    implementation_version: str
    real_browser: bool
    browser_binary_sha256: Optional[str]
    runner_image: str
    server_container: str
    server_ip: str
    server_port: int
    transport: str
    command: Tuple[str, ...]
    h2_command: Tuple[str, ...]
    environment: Tuple[Tuple[str, str], ...]
    mounts: Tuple[Mount, ...]
    user: str


@dataclass(frozen=True)
class Sample:
    sample_id: str
    product: str
    scenario: str
    workload: str
    wire_profile: str
    run_id: str
    seed: str
    sample_seed: int
    variant_index: int
    auxiliary: bool = False


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="capture independent PCAPs in a labelled internal Docker lab"
    )
    parser.add_argument("--config")
    parser.add_argument("--output")
    parser.add_argument(
        "--preregistration", default="testdata/stealth/preregistration.json"
    )
    parser.add_argument("--mode", choices=("calibration", "full"), default="calibration")
    parser.add_argument("--groups", type=int)
    parser.add_argument("--samples-per-group", type=int)
    parser.add_argument(
        "--cell", action="append", default=[], metavar="SCENARIO/WORKLOAD"
    )
    parser.add_argument("--include-cover-h2", action="store_true")
    parser.add_argument("--schedule-seed", type=int, default=20260904)
    parser.add_argument("--max-samples", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--docker", default=os.environ.get("DOCKER_BIN", "docker"))
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        print(json.dumps({"schema_version": 1, "status": "pass", "self_test": True}))
        return 0
    if not args.config or not args.output:
        print("--config and --output are required", file=sys.stderr)
        return 2
    signal_guard = SignalGuard()
    signal_guard.install()
    try:
        try:
            result = run_campaign(args)
        except CampaignError as error:
            print(f"stealth campaign: {error}", file=sys.stderr)
            return 1
    finally:
        signal_guard.restore()
    print(json.dumps(result, sort_keys=True))
    return 3 if result["status"] == "checkpoint" else 0


class SignalGuard:
    """Turn the first termination request into a cleanup-safe exception."""

    def __init__(self) -> None:
        self.previous: Dict[int, Any] = {}
        self.triggered: Optional[int] = None

    def install(self) -> None:
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.previous[number] = signal.signal(number, self._handle)

    def restore(self) -> None:
        for number, handler in self.previous.items():
            signal.signal(number, handler)
        self.previous.clear()

    def _handle(self, number: int, _frame: Any) -> None:
        if self.triggered is not None:
            return
        self.triggered = number
        # A second signal must not interrupt the cleanup triggered by the first.
        for target in self.previous:
            signal.signal(target, signal.SIG_IGN)
        try:
            name = signal.Signals(number).name
        except ValueError:
            name = str(number)
        raise CampaignInterrupted(f"received {name}; checkpoint cleanup requested")


def run_campaign(args: argparse.Namespace) -> Dict[str, Any]:
    if not 0 <= args.schedule_seed <= 2**63 - 1:
        raise CampaignError("--schedule-seed must be between 0 and 2^63-1")
    if args.max_samples is not None and args.max_samples <= 0:
        raise CampaignError("--max-samples must be positive")
    if args.plan_only and args.max_samples is not None:
        raise CampaignError("--plan-only and --max-samples cannot be combined")
    repo = Path(__file__).resolve().parent.parent
    config_path = Path(args.config).expanduser().resolve(strict=True)
    prereg_path = Path(args.preregistration).expanduser()
    prereg_path = (
        (repo / prereg_path).resolve(strict=True)
        if not prereg_path.is_absolute()
        else prereg_path.resolve(strict=True)
    )
    output = safe_output(Path(args.output))
    prereg = read_object(prereg_path, "preregistration")
    validate_preregistration(prereg)
    config = validate_config(read_object(config_path, "configuration"), config_path.parent)
    validate_capture_host_binding(prereg, config["lab"]["capture_host"])
    groups, per_group = dimensions(args, prereg)
    cells = select_cells(args, prereg)
    include_h2 = args.include_cover_h2 or args.mode == "full"
    samples = build_schedule(
        prereg, config["products"], cells, groups, per_group, args.schedule_seed, include_h2
    )
    validate_mode(args.mode, config, prereg, prereg_path, repo, samples)
    # Lock by canonical output path outside the output tree.  A failed live-lab
    # inspection must not create a directory or an in-tree lock that poisons a
    # safe non-resume retry.
    output_lock = acquire_output_lock(output)
    network_lock = None
    try:
        runtime = inspect_lab(args.docker, config)
        network_lock = acquire_network_lock(runtime["network_id"])
        source = snapshot_sources(config, prereg_path, repo, args.mode)
        identity = {
            "schema_version": 1,
            "campaign_id": config["campaign_id"],
            "mode": args.mode,
            "groups": groups,
            "samples_per_product_cell_group": per_group,
            "schedule_seed": args.schedule_seed,
            "cells": [list(cell) for cell in cells],
            "include_cover_h2": include_h2,
            "required_sample_count": sum(not sample.auxiliary for sample in samples),
            "auxiliary_sample_count": sum(sample.auxiliary for sample in samples),
            "total_sample_count": len(samples),
            "schedule_sha256": schedule_digest(samples),
            "configuration_sha256": file_sha256(config_path),
            "preregistration_sha256": file_sha256(prereg_path),
            "source": source,
            "docker": runtime,
        }
        output_created = prepare_output(output, args.resume)
        paths = {
            "plan": output / "plan.json",
            "state": output / "state.json",
            "events": output / "events.jsonl",
            "manifest": output / "capture-manifest.csv",
            "campaign": output / "campaign.json",
        }
        if args.resume:
            saved = read_object(paths["plan"], "saved plan")
            if saved.get("identity") != identity:
                raise CampaignError(
                    "live lab, source, configuration, or schedule differs from frozen plan"
                )
            state = read_object(paths["state"], "saved state")
        else:
            plan = {
                "schema_version": 1,
                "created_at": utc_now(),
                "identity": identity,
                "safety": {
                    "local_docker_context": True,
                    "internal_bridge_only": True,
                    "host_interface_capture": False,
                    "host_qdisc_modified": False,
                    "fresh_network_namespace_per_sample": True,
                    "exact_endpoint_bpf": True,
                    "shell_command_strings": False,
                    "workload_writable_bind_mounts": False,
                    "capture_output_bind_mount_only": True,
                },
            }
            state = {
                "schema_version": 1,
                "status": "planned",
                "capture_started_at": None,
                "capture_completed_at": None,
                "completed_samples": 0,
                "total_samples": len(samples),
                "last_error": None,
            }
            initialize_new_output(output, paths, plan, state, output_created)
        completions = load_ledger(paths["events"], samples, output, runtime, config)
        if args.resume:
            cleanup_stale_sample_resources(
                args.docker, config, runtime, samples, completions
            )
        reconcile_pcaps(output, samples, completions)
        manifest_size = reconcile_manifest(
            paths["manifest"], render_manifest(samples, completions)
        )
        update_campaign(
            paths["campaign"], config, prereg, identity, source, state, paths["manifest"],
            samples, completions,
        )
        if args.plan_only:
            return summary("planned", output, samples, completions)
        if len(completions) == len(samples):
            state["status"] = "complete"
            state["capture_completed_at"] = state.get("capture_completed_at") or utc_now()
            write_json(paths["state"], state)
            assert_sources_unchanged(source, config, prereg_path, repo, args.mode)
            update_campaign(
                paths["campaign"], config, prereg, identity, source, state,
                paths["manifest"], samples, completions,
            )
            return summary("complete", output, samples, completions)
        state["status"] = "running"
        state["capture_started_at"] = state.get("capture_started_at") or utc_now()
        state["last_error"] = None
        write_json(paths["state"], state)
        new_count = 0
        for sample in samples:
            if sample.sample_id in completions:
                continue
            if args.max_samples is not None and new_count >= args.max_samples:
                state["status"] = "checkpoint"
                state["completed_samples"] = len(completions)
                write_json(paths["state"], state)
                update_campaign(
                    paths["campaign"], config, prereg, identity, source, state,
                    paths["manifest"], samples, completions,
                )
                return summary("checkpoint", output, samples, completions)
            variant = config["products"][sample.product][sample.variant_index]
            append_event(paths["events"], {
                "event": "sample_started", "at": utc_now(),
                "sample_id": sample.sample_id, "variant": variant.name,
            })
            try:
                complete = capture_one(
                    args.docker, output, config, runtime, sample, variant, paths["events"]
                )
                duplicate = next(
                    (
                        prior_id for prior_id, prior in completions.items()
                        if prior["pcap_sha256"] == complete["pcap_sha256"]
                    ),
                    None,
                )
                if duplicate is not None:
                    quarantine(
                        output, output / complete["manifest_row"]["pcap"],
                        sample.sample_id + "-duplicate",
                    )
                    raise CampaignError(
                        f"samples {duplicate} and {sample.sample_id} produced identical PCAP bytes"
                    )
            except CampaignError as error:
                state["status"] = "failed"
                state["last_error"] = str(error)
                state["completed_samples"] = len(completions)
                write_json(paths["state"], state)
                update_campaign(
                    paths["campaign"], config, prereg, identity, source, state,
                    paths["manifest"], samples, completions,
                )
                raise
            append_event(paths["events"], complete)
            completions[sample.sample_id] = complete
            manifest_size = append_manifest_row(
                paths["manifest"], complete["manifest_row"], manifest_size
            )
            new_count += 1
            state["completed_samples"] = len(completions)
            write_json(paths["state"], state)
        state["status"] = "complete"
        state["capture_completed_at"] = utc_now()
        state["completed_samples"] = len(completions)
        write_json(paths["state"], state)
        expected_manifest = render_manifest(samples, completions)
        if (
            len(expected_manifest) != manifest_size
            or paths["manifest"].read_bytes() != expected_manifest
        ):
            raise CampaignError("capture manifest differs from durable completion ledger")
        assert_sources_unchanged(source, config, prereg_path, repo, args.mode)
        update_campaign(
            paths["campaign"], config, prereg, identity, source, state,
            paths["manifest"], samples, completions,
        )
        return summary("complete", output, samples, completions)
    finally:
        if network_lock is not None:
            network_lock.close()
        output_lock.close()


def dimensions(args: argparse.Namespace, prereg: Mapping[str, Any]) -> Tuple[int, int]:
    frozen_groups = prereg["minimum_groups_per_product_cell"]
    frozen_per_group = prereg["minimum_samples_per_product_cell_group"]
    if args.mode == "full":
        if args.groups not in (None, frozen_groups) or args.samples_per_group not in (
            None, frozen_per_group
        ):
            raise CampaignError("full dimensions are frozen by preregistration")
        if frozen_groups * frozen_per_group != prereg["minimum_samples_per_product_cell"]:
            raise CampaignError("preregistered full dimensions are not internally exact")
        if args.cell:
            raise CampaignError("full mode cannot select a cell subset")
        return frozen_groups, frozen_per_group
    groups = args.groups if args.groups is not None else 1
    per_group = args.samples_per_group if args.samples_per_group is not None else 1
    if not 1 <= groups <= frozen_groups:
        raise CampaignError(f"calibration groups must be in 1..{frozen_groups}")
    if not 1 <= per_group <= frozen_per_group:
        raise CampaignError(f"calibration samples per group must be in 1..{frozen_per_group}")
    return groups, per_group


def select_cells(args: argparse.Namespace, prereg: Mapping[str, Any]) -> List[Tuple[str, str, str]]:
    cells = [cell_tuple(item) for item in prereg["required_common_cells"]]
    if not args.cell:
        return cells
    chosen = []
    for selection in args.cell:
        parts = selection.split("/")
        matches = [
            cell for cell in cells
            if len(parts) == 2 and cell[0] == parts[0] and cell[1] == parts[1]
        ]
        if len(matches) != 1:
            raise CampaignError(f"unknown or ambiguous calibration cell {selection!r}")
        if matches[0] not in chosen:
            chosen.append(matches[0])
    return chosen


def validate_preregistration(value: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "baseline", "minimum_samples_per_product_cell",
        "minimum_groups_per_product_cell", "minimum_samples_per_product_cell_group",
        "required_common_cells", "bootstrap_seed", "active_evidence",
        "sample_attempt_policy",
    }
    if required.difference(value):
        raise CampaignError("preregistration lacks capture-schedule fields")
    baseline = value["baseline"]
    if (
        value["schema_version"] != 1
        or not isinstance(baseline, dict)
        or baseline.get("hysteria2_version") != "v2.12.2"
        or baseline.get("disable_update_check") is not True
        or baseline.get("local_http_proxy_connection_header")
        != "Proxy-Connection: keep-alive"
    ):
        raise CampaignError("unsupported or unpinned preregistration")
    if value["sample_attempt_policy"] != {
        "maximum_attempts_per_sample": 1,
        "retry_failed_or_interrupted_sample": False,
        "checkpoint_boundary": "after_sample_complete",
    }:
        raise CampaignError("preregistration does not enforce first-attempt evidence")
    cells = [cell_tuple(item) for item in value["required_common_cells"]]
    if not cells or len(cells) != len(set(cells)):
        raise CampaignError("preregistered cells are empty or duplicated")
    for scenario, _, wire in cells:
        impairment(scenario)
        if wire != "h3":
            raise CampaignError("comparison cells must use the frozen H3 wire profile")
    for field in (
        "minimum_samples_per_product_cell", "minimum_groups_per_product_cell",
        "minimum_samples_per_product_cell_group", "bootstrap_seed",
    ):
        number = value[field]
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise CampaignError(f"invalid preregistration integer {field}")


def validate_capture_host_binding(
    preregistration: Mapping[str, Any], capture_host: str,
) -> None:
    evidence = require_object(
        preregistration.get("active_evidence"), "preregistration active_evidence"
    )
    registered_host = require_text(
        evidence.get("remote_execution_host"),
        "preregistration active_evidence.remote_execution_host",
    )
    if registered_host != capture_host:
        raise CampaignError(
            "configured capture_host differs from the preregistered remote execution host"
        )


def cell_tuple(value: Any) -> Tuple[str, str, str]:
    if not isinstance(value, dict) or set(value) != {
        "scenario", "workload", "wire_profile"
    }:
        raise CampaignError("each cell must contain exactly scenario/workload/wire_profile")
    result = tuple(value[key] for key in ("scenario", "workload", "wire_profile"))
    if not all(isinstance(item, str) and NAME_RE.fullmatch(item) for item in result):
        raise CampaignError("cell values contain unsupported characters")
    return result  # type: ignore[return-value]


def impairment(scenario: str) -> Tuple[int, str]:
    if scenario == "healthy_h3":
        return 0, "0"
    match = re.fullmatch(r"delay([1-9][0-9]*)_loss([0-9]+(?:\.[0-9]+)?)", scenario)
    if not match:
        raise CampaignError(f"unsupported impairment scenario {scenario!r}")
    delay, loss = int(match.group(1)), float(match.group(2))
    if delay > 1000 or not 0 < loss <= 20:
        raise CampaignError(f"unsafe impairment scenario {scenario!r}")
    return delay, match.group(2)


def build_schedule(
    prereg: Mapping[str, Any],
    products: Mapping[str, Sequence[Variant]],
    cells: Sequence[Tuple[str, str, str]],
    groups: int,
    per_group: int,
    schedule_seed: int,
    include_h2: bool,
) -> List[Sample]:
    del prereg
    blocks: List[List[Sample]] = []
    auxiliary: List[Sample] = []
    for group in range(1, groups + 1):
        run_id = f"run-{group:02d}"
        seed = f"seed-{schedule_seed + group:010d}"
        for cell_index, (scenario, workload, wire) in enumerate(cells):
            for number in range(1, per_group + 1):
                block = []
                block_key = f"{scenario}|{workload}|{wire}|{run_id}|{seed}|{number}"
                for product in PRODUCTS:
                    variant = (group + number + cell_index - 2) % len(products[product])
                    key = f"{product}|{scenario}|{workload}|{wire}|{run_id}|{seed}|{number}"
                    suffix = hashlib.sha256(key.encode()).hexdigest()[:10]
                    block.append(Sample(
                        f"{product}-{scenario}-{workload}-g{group:02d}-n{number:03d}-{suffix}",
                        product, scenario, workload, wire, run_id, seed,
                        sample_seed(schedule_seed, key), variant,
                    ))
                random.Random(
                    sample_seed(schedule_seed, block_key + "|product-order")
                ).shuffle(block)
                blocks.append(block)
        if include_h2:
            for index, variant in enumerate(products["cover"]):
                if variant.h2_command:
                    key = f"cover|h2|{run_id}|{seed}|{variant.name}"
                    suffix = hashlib.sha256(key.encode()).hexdigest()[:10]
                    auxiliary.append(Sample(
                        f"cover-aux-h2-g{group:02d}-{variant.name}-{suffix}",
                        "cover", "cover_diversity", "browser_h2", "h2", run_id, seed,
                        sample_seed(schedule_seed, key), index, True,
                    ))
    random.Random(schedule_seed).shuffle(blocks)
    random.Random(schedule_seed ^ 0x6A09E667).shuffle(auxiliary)
    result = [sample for block in blocks for sample in block] + auxiliary
    if len({item.sample_id for item in result}) != len(result):
        raise CampaignError("generated sample IDs are duplicated")
    return result


def sample_seed(base: int, value: str) -> int:
    return int.from_bytes(
        hashlib.sha256(f"{base}|{value}".encode()).digest()[:4], "big"
    ) & 0x7FFFFFFF


def validate_config(raw: Mapping[str, Any], root: Path) -> Dict[str, Any]:
    exact_keys(raw, {"schema_version", "campaign_id", "lab", "provenance", "products"}, "configuration")
    if raw["schema_version"] != 1:
        raise CampaignError("unsupported configuration schema")
    campaign_id = safe_name(raw["campaign_id"], "campaign_id")
    lab_raw = require_object(raw["lab"], "lab")
    exact_keys(
        lab_raw,
        {
            "docker_network", "ownership_label", "capture_image", "capture_host",
            "interface", "allowed_mount_roots", "minimum_packets",
            "workload_timeout_seconds", "runner_memory_mb", "runner_pids_limit",
        },
        "lab",
    )
    expected_label = f"{LABEL_KEY}={campaign_id}"
    if lab_raw["ownership_label"] != expected_label:
        raise CampaignError(f"ownership_label must be exactly {expected_label!r}")
    interface = lab_raw["interface"]
    if not isinstance(interface, str) or not IFACE_RE.fullmatch(interface):
        raise CampaignError("lab interface must be an explicit Linux interface name")
    roots_value = lab_raw["allowed_mount_roots"]
    if not isinstance(roots_value, list) or not roots_value:
        raise CampaignError("allowed_mount_roots must be a non-empty explicit list")
    roots = []
    for value in roots_value:
        path = resolve_path(root, require_text(value, "allowed mount root"))
        if path == Path("/") or not path.is_dir():
            raise CampaignError("allowed mount roots must be existing non-root directories")
        roots.append(path)
    lab = {
        "docker_network": safe_name(lab_raw["docker_network"], "docker_network"),
        "ownership_label": expected_label,
        "capture_image": require_text(lab_raw["capture_image"], "capture_image"),
        "capture_host": require_text(lab_raw["capture_host"], "capture_host"),
        "interface": interface,
        "allowed_mount_roots": tuple(roots),
        "minimum_packets": bounded_int(lab_raw["minimum_packets"], "minimum_packets", 5, 1000000),
        "workload_timeout_seconds": bounded_int(
            lab_raw["workload_timeout_seconds"], "workload_timeout_seconds", 1, 3600
        ),
        "runner_memory_mb": bounded_int(lab_raw["runner_memory_mb"], "runner_memory_mb", 64, 900),
        "runner_pids_limit": bounded_int(lab_raw["runner_pids_limit"], "runner_pids_limit", 16, 2048),
    }
    provenance_raw = require_object(raw["provenance"], "provenance")
    exact_keys(
        provenance_raw,
        {
            "preregistration_recorded_at", "autocar_binary", "autocar_config",
            "hysteria2_binary", "hysteria2_config",
        },
        "provenance",
    )
    registered = parse_time(
        provenance_raw["preregistration_recorded_at"], "preregistration_recorded_at"
    )
    if registered >= dt.datetime.now(dt.timezone.utc):
        raise CampaignError("preregistration timestamp must be in the past")
    provenance: Dict[str, Any] = {
        "preregistration_recorded_at": format_time(registered)
    }
    for field in (
        "autocar_binary", "autocar_config", "hysteria2_binary", "hysteria2_config"
    ):
        path = resolve_path(root, require_text(provenance_raw[field], field))
        if not path.is_file():
            raise CampaignError(f"{field} must be an existing regular file")
        require_under_roots(path, roots, field)
        provenance[field] = path
    products_raw = require_object(raw["products"], "products")
    if set(products_raw) != set(PRODUCTS):
        raise CampaignError("products must be exactly cover, autocar, and hysteria2")
    products: Dict[str, Tuple[Variant, ...]] = {}
    for product in PRODUCTS:
        section = require_object(products_raw[product], f"products.{product}")
        exact_keys(section, {"variants"}, f"products.{product}")
        values = section["variants"]
        if not isinstance(values, list) or not values:
            raise CampaignError(f"products.{product}.variants must be non-empty")
        variants = tuple(parse_variant(product, item, root, roots) for item in values)
        if len({item.name for item in variants}) != len(variants):
            raise CampaignError(f"{product} variant names are duplicated")
        products[product] = variants
    return {
        "schema_version": 1, "campaign_id": campaign_id, "lab": lab,
        "provenance": provenance, "products": products,
    }


def parse_variant(
    product: str, raw: Any, root: Path, allowed_roots: Sequence[Path]
) -> Variant:
    value = require_object(raw, f"{product} variant")
    required = {
        "name", "client_implementation", "server_implementation",
        "implementation_version", "real_browser", "runner_image",
        "server_container", "server_ip", "server_port", "transport", "command",
        "user",
    }
    optional = {"browser_binary_sha256", "h2_command", "environment", "mounts"}
    exact_keys(value, required | optional, f"{product} variant", optional)
    real_browser = value["real_browser"]
    if not isinstance(real_browser, bool):
        raise CampaignError(f"{product} real_browser must be boolean")
    if product != "cover" and real_browser:
        raise CampaignError("only a cover variant may declare real_browser")
    browser_binary_sha256 = value.get("browser_binary_sha256")
    if real_browser:
        if (
            not isinstance(browser_binary_sha256, str)
            or not SHA_RE.fullmatch(browser_binary_sha256)
        ):
            raise CampaignError("real-browser variant requires browser_binary_sha256")
    elif browser_binary_sha256 is not None:
        raise CampaignError("non-browser variant cannot declare browser_binary_sha256")
    if value["transport"] != "udp":
        raise CampaignError("preregistered H3 comparison variants must use UDP")
    h2_command = command_template(
        value.get("h2_command", []), f"{product} h2_command", allow_empty=True
    )
    if h2_command and (product != "cover" or not real_browser):
        raise CampaignError("h2_command requires a real-browser cover variant")
    environment_value = value.get("environment", {})
    if not isinstance(environment_value, dict):
        raise CampaignError(f"{product} environment must be an object")
    environment = []
    for name in sorted(environment_value):
        if not isinstance(name, str) or not ENV_RE.fullmatch(name):
            raise CampaignError(f"{product} environment has an invalid variable name")
        template = require_text(environment_value[name], f"{product} environment {name}")
        validate_template(template, f"{product} environment {name}")
        environment.append((name, template))
    mounts_value = value.get("mounts", [])
    if not isinstance(mounts_value, list):
        raise CampaignError(f"{product} mounts must be a list")
    mounts = []
    targets = set()
    for index, mount_value in enumerate(mounts_value):
        mount = require_object(mount_value, f"{product} mount {index}")
        exact_keys(mount, {"source", "target", "read_only"}, f"{product} mount {index}")
        if mount["read_only"] is not True:
            raise CampaignError("campaign bind mounts must be explicitly read-only")
        source = resolve_path(root, require_text(mount["source"], "mount source"))
        require_under_roots(source, allowed_roots, "mount source")
        if "," in str(source):
            raise CampaignError("mount source cannot contain a comma")
        target = mount["target"]
        if (
            not isinstance(target, str) or not target.startswith("/") or target == "/"
            or "," in target or ".." in Path(target).parts
        ):
            raise CampaignError("mount target is unsafe")
        if target in targets:
            raise CampaignError("mount targets are duplicated")
        targets.add(target)
        mounts.append(Mount(source, target))
    user = value["user"]
    if not isinstance(user, str) or not USER_RE.fullmatch(user):
        raise CampaignError("runner user must be a non-root numeric UID or UID:GID")
    return Variant(
        product=product,
        name=safe_name(value["name"], f"{product} variant name"),
        client_implementation=require_text(value["client_implementation"], "client implementation"),
        server_implementation=require_text(value["server_implementation"], "server implementation"),
        implementation_version=require_text(value["implementation_version"], "implementation version"),
        real_browser=real_browser,
        browser_binary_sha256=browser_binary_sha256,
        runner_image=require_text(value["runner_image"], "runner image"),
        server_container=safe_name(value["server_container"], "server container"),
        server_ip=str(rfc1918_ip(value["server_ip"], "server_ip")),
        server_port=bounded_int(value["server_port"], "server_port", 1, 65535),
        transport=value["transport"],
        command=command_template(value["command"], f"{product} command"),
        h2_command=h2_command,
        environment=tuple(environment),
        mounts=tuple(mounts),
        user=user,
    )


def validate_mode(
    mode: str,
    config: Mapping[str, Any],
    prereg: Mapping[str, Any],
    prereg_path: Path,
    repo: Path,
    samples: Sequence[Sample],
) -> None:
    if mode != "full":
        auxiliary = [sample for sample in samples if sample.auxiliary]
        if auxiliary:
            cover = config["products"]["cover"]
            expected_variants = {
                index for index, variant in enumerate(cover) if variant.h2_command
            }
            h3_variants = {
                sample.variant_index for sample in samples
                if not sample.auxiliary and sample.product == "cover"
                and sample.wire_profile == "h3"
            }
            h2_variants = {
                sample.variant_index for sample in auxiliary
                if sample.product == "cover" and sample.wire_profile == "h2"
            }
            if (
                len(expected_variants) < 2
                or h3_variants != expected_variants
                or h2_variants != expected_variants
                or any(not cover[index].real_browser for index in expected_variants)
                or len({cover[index].client_implementation for index in expected_variants}) < 2
                or len({cover[index].server_implementation for index in expected_variants}) < 2
            ):
                raise CampaignError(
                    "calibration with H2 controls must cover both real-browser/server variants over H3 and H2"
                )
        return
    cover = config["products"]["cover"]
    if len({item.client_implementation.lower() for item in cover}) < 2:
        raise CampaignError("full mode requires two distinct cover client implementations")
    if len({item.server_implementation.lower() for item in cover}) < 2:
        raise CampaignError("full mode requires two distinct cover server implementations")
    if len(cover) < 2 or any(not item.real_browser or not item.h2_command for item in cover):
        raise CampaignError(
            "full mode requires two real-browser cover variants with H3 and H2 commands"
        )
    expected = (
        len(prereg["required_common_cells"]) * len(PRODUCTS)
        * prereg["minimum_samples_per_product_cell"]
    )
    if sum(not item.auxiliary for item in samples) != expected:
        raise CampaignError(f"full schedule must contain exactly {expected} required PCAPs")
    expected_auxiliary = prereg["minimum_groups_per_product_cell"] * sum(
        bool(item.h2_command) for item in cover
    )
    if sum(item.auxiliary for item in samples) != expected_auxiliary:
        raise CampaignError(
            f"full schedule must contain exactly {expected_auxiliary} auxiliary H2 PCAPs"
        )
    if prereg_path != (repo / "testdata/stealth/preregistration.json").resolve():
        raise CampaignError("full mode must use the checked-in preregistration")


def command_template(value: Any, label: str, allow_empty: bool = False) -> Tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise CampaignError(f"{label} must be a shell-free argv array")
    result = []
    for index, part in enumerate(value):
        text = require_text(part, f"{label}[{index}]")
        validate_template(text, f"{label}[{index}]")
        result.append(text)
    if result and Path(result[0]).name.lower() in {
        "sh", "bash", "dash", "ash", "zsh", "csh", "ksh", "fish"
    }:
        raise CampaignError(f"{label} cannot invoke a shell entrypoint")
    return tuple(result)


def validate_template(value: str, label: str) -> None:
    try:
        fields = [field for _, field, _, _ in string.Formatter().parse(value) if field]
    except ValueError as error:
        raise CampaignError(f"{label} contains malformed template braces") from error
    if any(field not in TEMPLATE_FIELDS for field in fields):
        raise CampaignError(f"{label} contains an unsupported template field")


def render_template(value: str, variables: Mapping[str, str]) -> str:
    validate_template(value, "runtime template")
    try:
        return value.format_map(variables)
    except (KeyError, ValueError) as error:
        raise CampaignError("workload template could not be rendered") from error


def inspect_lab(docker: str, config: Mapping[str, Any]) -> Dict[str, Any]:
    context = command([docker, "context", "show"], "read Docker context").stdout.strip()
    context_doc = one_inspect(
        json_command([docker, "context", "inspect", context], "inspect Docker context"),
        "Docker context",
    )
    endpoint = ((context_doc.get("Endpoints") or {}).get("docker") or {}).get("Host")
    if not isinstance(endpoint, str) or not (
        endpoint.startswith("unix://") or endpoint.startswith("npipe://")
    ):
        raise CampaignError("remote Docker contexts are refused; run this driver on the lab host")
    lab = config["lab"]
    network = one_inspect(
        json_command([docker, "network", "inspect", lab["docker_network"]], "inspect lab network"),
        "lab network",
    )
    if (
        network.get("Driver") != "bridge" or network.get("Internal") is not True
        or network.get("Scope") != "local"
    ):
        raise CampaignError("lab network must be an internal local-scope Docker bridge")
    label_key, label_value = split_label(lab["ownership_label"])
    if (network.get("Labels") or {}).get(label_key) != label_value:
        raise CampaignError("lab network lacks the exact campaign ownership label")
    subnets = []
    for item in ((network.get("IPAM") or {}).get("Config") or []):
        try:
            subnet = ipaddress.ip_network(item.get("Subnet"), strict=False)
        except (AttributeError, ValueError, TypeError) as error:
            raise CampaignError("lab network reports an invalid subnet") from error
        if not isinstance(subnet, ipaddress.IPv4Network) or not any(
            subnet.subnet_of(private) for private in RFC1918
        ):
            raise CampaignError("lab network must use only RFC1918 IPv4 subnets")
        subnets.append(subnet)
    if not subnets:
        raise CampaignError("lab network has no RFC1918 subnet")
    capture_image = inspect_image(docker, lab["capture_image"])
    helper_versions = {}
    for tool, arguments in (
        ("tcpdump", ("--version",)), ("tc", ("-V",)),
        ("ip", ("-Version",)), ("sleep", ("0",)),
    ):
        completed = command(
            [
                docker, "run", "--rm", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--entrypoint", tool, capture_image["id"], *arguments,
            ],
            f"verify helper tool {tool}",
        )
        helper_versions[tool] = first_line(completed.stdout or completed.stderr)
    runner_images = {}
    servers = {}
    for product in PRODUCTS:
        for variant in config["products"][product]:
            key = f"{product}/{variant.name}"
            runner_images[key] = inspect_image(docker, variant.runner_image)
            if variant.server_container not in servers:
                server = one_inspect(
                    json_command(
                        [docker, "container", "inspect", variant.server_container],
                        f"inspect server {variant.server_container}",
                    ),
                    "server container",
                )
                state = server.get("State") or {}
                labels = (server.get("Config") or {}).get("Labels") or {}
                networks = (server.get("NetworkSettings") or {}).get("Networks") or {}
                if state.get("Running") is not True or labels.get(label_key) != label_value:
                    raise CampaignError("server must be running and carry the exact campaign label")
                if set(networks) != {lab["docker_network"]}:
                    raise CampaignError(
                        "server must be attached only to the dedicated internal lab network"
                    )
                actual_ip = (networks[lab["docker_network"]] or {}).get("IPAddress")
                if actual_ip != variant.server_ip:
                    raise CampaignError("configured server IP does not match Docker inspection")
                address = rfc1918_ip(actual_ip, "server IP")
                if not any(address in subnet for subnet in subnets):
                    raise CampaignError("server IP is outside the dedicated lab subnet")
                servers[variant.server_container] = {
                    "id": server.get("Id"), "image_id": server.get("Image"),
                    "ip": variant.server_ip,
                }
            elif servers[variant.server_container]["ip"] != variant.server_ip:
                raise CampaignError("one server container has conflicting configured IPs")
            verify_interface(
                docker, capture_image["id"], servers[variant.server_container]["id"],
                lab["interface"], variant.server_ip, lab["ownership_label"],
            )
    engine_id = command(
        [docker, "info", "--format", "{{.ID}}"], "read Docker engine identity"
    ).stdout.strip()
    if not engine_id:
        raise CampaignError("Docker engine did not report an identity")
    return {
        "context": context,
        "endpoint_scheme": endpoint.split(":", 1)[0],
        "engine_fingerprint": hashlib.sha256(engine_id.encode()).hexdigest(),
        "network_id": network.get("Id"),
        "network_name": lab["docker_network"],
        "network_subnets": [str(subnet) for subnet in subnets],
        "capture_host": lab["capture_host"],
        "capture_image": capture_image,
        "helper_versions": helper_versions,
        "runner_images": runner_images,
        "servers": servers,
    }


def inspect_image(docker: str, value: str) -> Dict[str, Any]:
    image = one_inspect(
        json_command([docker, "image", "inspect", value], f"inspect image {value}"), "image"
    )
    identifier = image.get("Id")
    if not isinstance(identifier, str) or not identifier.startswith("sha256:") or not SHA_RE.fullmatch(
        identifier[7:]
    ):
        raise CampaignError("image reference did not resolve to an immutable image ID")
    return {"id": identifier, "repo_digests": sorted(image.get("RepoDigests") or [])}


def verify_interface(
    docker: str, image: str, container_id: str, interface: str, expected_ip: str, label: str
) -> None:
    result = json_command(
        helper_command(
            docker, image, container_id, label, "ip",
            ("-j", "-4", "address", "show", "dev", interface), False,
        ),
        "verify container interface",
    )
    addresses = []
    if isinstance(result, list):
        for iface in result:
            for address in (iface.get("addr_info") or []) if isinstance(iface, dict) else []:
                if address.get("family") == "inet":
                    addresses.append(address.get("local"))
    if expected_ip not in addresses:
        raise CampaignError(
            f"configured capture interface {interface!r} does not own {expected_ip}"
        )


def snapshot_sources(
    config: Mapping[str, Any], prereg_path: Path, repo: Path, mode: str
) -> Dict[str, Any]:
    head = git(repo, "rev-parse", "--verify", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    dirty = bool(git(repo, "status", "--porcelain=v1", "--untracked-files=all"))
    if mode == "full" and dirty:
        raise CampaignError("full capture requires a clean Git worktree")
    if mode == "full":
        relative = prereg_path.relative_to(repo).as_posix()
        checked = subprocess.run(
            ["git", "-C", str(repo), "show", f"HEAD:{relative}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if checked.returncode != 0 or checked.stdout != prereg_path.read_bytes():
            raise CampaignError("preregistration is not identical to the checked-in HEAD")
    provenance = config["provenance"]
    files = {
        name: file_snapshot(path)
        for name, path in provenance.items()
        if name != "preregistration_recorded_at"
    }
    prereg = read_object(prereg_path, "preregistration")
    pinned = {
        prereg["baseline"]["linux_amd64_sha256"],
        prereg["baseline"]["linux_arm64_sha256"],
    }
    if mode == "full" and files["hysteria2_binary"]["sha256"] not in pinned:
        raise CampaignError("Hysteria binary does not match a pinned official release")
    return {
        "git_head": head, "git_tree": tree, "git_dirty": dirty,
        "preregistration": file_snapshot(prereg_path),
        "preregistration_recorded_at": provenance["preregistration_recorded_at"],
        "files": files,
    }


def assert_sources_unchanged(
    expected: Mapping[str, Any], config: Mapping[str, Any],
    prereg_path: Path, repo: Path, mode: str,
) -> None:
    if snapshot_sources(config, prereg_path, repo, mode) != expected:
        raise CampaignError("source, preregistration, binary, or config changed during capture")


def sample_resource_names(campaign_id: str, sample: Sample) -> Dict[str, str]:
    token = hashlib.sha256(f"{campaign_id}|{sample.sample_id}".encode()).hexdigest()[:16]
    return {
        "anchor": f"autocar-cap-anchor-{token}",
        "capture": f"autocar-cap-tcpdump-{token}",
        "runner": f"autocar-cap-runner-{token}",
    }


def capture_one(
    docker: str,
    output: Path,
    config: Mapping[str, Any],
    runtime: Mapping[str, Any],
    sample: Sample,
    variant: Variant,
    events: Path,
) -> Dict[str, Any]:
    lab = config["lab"]
    names = sample_resource_names(config["campaign_id"], sample)
    helper_image = runtime["capture_image"]["id"]
    runner_image = runtime["runner_images"][f"{sample.product}/{variant.name}"]["id"]
    server_id = runtime["servers"][variant.server_container]["id"]
    transport = capture_transport(sample, variant)
    pcap_dir = output / "pcaps"
    pcap_dir.mkdir(mode=0o700, exist_ok=True)
    partial = pcap_dir / f".{sample.sample_id}.partial.pcap"
    final = pcap_dir / f"{sample.sample_id}.pcap"
    if partial.exists() or final.exists():
        raise CampaignError("refusing to overwrite a sample capture")
    owned = []
    qdiscs: List[Tuple[str, str, Optional[str]]] = []
    try:
        anchor_id = command(
            [
                docker, "run", "-d", "--name", names["anchor"], "--label",
                lab["ownership_label"], "--network", lab["docker_network"],
                "--read-only", "--cap-drop", "ALL", "--security-opt",
                "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
                "--entrypoint", "sleep", helper_image, "2147483647",
            ],
            "start fresh sample network namespace",
        ).stdout.strip()
        owned.append(names["anchor"])
        client_ip = container_ip(docker, anchor_id, lab["docker_network"])
        address = rfc1918_ip(client_ip, "sample client IP")
        if not any(
            address in ipaddress.ip_network(subnet) for subnet in runtime["network_subnets"]
        ):
            raise CampaignError("sample client IP escaped the frozen lab subnet")
        verify_interface(
            docker, helper_image, anchor_id, lab["interface"], client_ip,
            lab["ownership_label"],
        )
        ensure_default_qdisc(
            docker, helper_image, anchor_id, lab["interface"],
            lab["ownership_label"], "sample client",
        )
        ensure_default_qdisc(
            docker, helper_image, server_id, lab["interface"],
            lab["ownership_label"], "dedicated server",
        )
        delay, loss = impairment(sample.scenario) if not sample.auxiliary else (0, "0")
        if delay:
            handle = qdisc_handle(config["campaign_id"])
            qdiscs.append(("client", anchor_id, None))
            add_root_netem(
                docker, helper_image, anchor_id, lab["interface"],
                lab["ownership_label"], handle, delay, loss, sample.sample_seed,
            )
            qdiscs.append(("server", server_id, client_ip))
            add_server_netem(
                docker, helper_image, server_id, lab["interface"],
                lab["ownership_label"], handle, client_ip, delay, loss,
                sample.sample_seed ^ 0x5A5A5A5A,
            )
        capture_id = command(
            [
                docker, "run", "-d", "--name", names["capture"], "--label",
                lab["ownership_label"], "--network", f"container:{anchor_id}",
                "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_RAW",
                "--security-opt", "no-new-privileges", "--mount",
                f"type=bind,src={pcap_dir},dst=/captures", "--entrypoint",
                "tcpdump", helper_image, "--immediate-mode", "-p", "-i",
                lab["interface"], "-s", "0", "-U", "-nn", "-w",
                f"/captures/{partial.name}",
                f"{transport} and host {variant.server_ip} and port {variant.server_port}",
            ],
            "start endpoint-scoped tcpdump",
        ).stdout.strip()
        owned.append(names["capture"])
        wait_capture(docker, capture_id)
        time.sleep(0.1)
        workload_receipt = run_workload(
            docker, config, sample, variant, runner_image, anchor_id, names["runner"]
        )
        time.sleep(0.2)
        stop_capture(docker, capture_id)
        remove_container(docker, names["capture"], lab["ownership_label"])
        owned.remove(names["capture"])
        if not partial.is_file() or partial.stat().st_size <= 24:
            raise CampaignError("tcpdump produced no usable PCAP")
        os.replace(partial, final)
        os.chmod(final, 0o600)
        packets = verify_pcap(
            docker, helper_image, final, variant.server_ip, variant.server_port,
            transport, lab["minimum_packets"],
        )
        row = {
            "sample_id": sample.sample_id,
            "product": sample.product,
            "scenario": sample.scenario,
            "workload": sample.workload,
            "wire_profile": sample.wire_profile,
            "run_id": sample.run_id,
            "seed": sample.seed,
            "pcap": f"pcaps/{final.name}",
            "client_ip": client_ip,
            "server_ip": variant.server_ip,
            "client_implementation": variant.client_implementation,
            "server_implementation": variant.server_implementation,
            "implementation_version": variant.implementation_version,
            "runner_image_id": runner_image,
            "server_container_id": server_id,
            "capture_host": runtime["capture_host"],
            "docker_engine_fingerprint": runtime["engine_fingerprint"],
        }
        result = {
            "event": "sample_complete", "at": utc_now(),
            "sample_id": sample.sample_id, "variant": variant.name,
            "packets": packets, "pcap_sha256": file_sha256(final),
            "pcap_bytes": final.stat().st_size, "manifest_row": row,
        }
        if workload_receipt is not None:
            result["workload_receipt"] = workload_receipt
        return result
    except Exception as error:
        append_event(events, {
            "event": "sample_failed", "at": utc_now(),
            "sample_id": sample.sample_id, "reason": str(error),
        })
        quarantine(output, partial, sample.sample_id)
        quarantine(output, final, sample.sample_id + "-uncommitted")
        if isinstance(error, CampaignError):
            raise
        raise CampaignError(f"sample {sample.sample_id} failed: {error}") from error
    finally:
        cleanup_errors = []
        for kind, container_id, client_ip in reversed(qdiscs):
            try:
                handle = qdisc_handle(config["campaign_id"])
                if kind == "server":
                    remove_server_netem(
                        docker, helper_image, container_id, lab["interface"],
                        lab["ownership_label"], handle, {client_ip} if client_ip else None,
                        runtime["network_subnets"],
                    )
                else:
                    remove_root_netem(
                        docker, helper_image, container_id, lab["interface"],
                        lab["ownership_label"], handle,
                    )
            except CampaignError as error:
                cleanup_errors.append(str(error))
        for name in reversed(owned):
            try:
                remove_container(docker, name, lab["ownership_label"])
            except CampaignError as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise CampaignError("cleanup failed: " + "; ".join(cleanup_errors))


def run_workload(
    docker: str, config: Mapping[str, Any], sample: Sample, variant: Variant,
    image: str, anchor_id: str, name: str,
) -> Optional[Dict[str, Any]]:
    lab = config["lab"]
    values = {
        "campaign_id": config["campaign_id"], "sample_id": sample.sample_id,
        "product": sample.product, "scenario": sample.scenario,
        "workload": sample.workload, "wire_profile": sample.wire_profile,
        "run_id": sample.run_id, "seed": sample.seed,
        "sample_seed": str(sample.sample_seed), "server_ip": variant.server_ip,
        "server_port": str(variant.server_port),
    }
    template = variant.h2_command if sample.auxiliary else variant.command
    rendered = [render_template(value, values) for value in template]
    arguments = [
        docker, "run", "--name", name, "--label", lab["ownership_label"],
        "--network", f"container:{anchor_id}", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit",
        str(lab["runner_pids_limit"]), "--memory", f"{lab['runner_memory_mb']}m",
        "--user", variant.user, "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--tmpfs", "/run:rw,nosuid,nodev,size=32m", "--tmpfs",
        "/dev/shm:rw,nosuid,nodev,size=256m",
    ]
    for key, value in variant.environment:
        arguments.extend(["--env", f"{key}={render_template(value, values)}"])
    for mount in variant.mounts:
        arguments.extend([
            "--mount", f"type=bind,src={mount.source},dst={mount.target},readonly"
        ])
    arguments.extend(["--entrypoint", rendered[0], image, *rendered[1:]])
    try:
        completed = command(
            arguments, f"run {sample.product} workload",
            timeout=lab["workload_timeout_seconds"],
        )
    except subprocess.TimeoutExpired as error:
        raise CampaignError(
            f"workload exceeded {lab['workload_timeout_seconds']} seconds"
        ) from error
    finally:
        remove_container(docker, name, lab["ownership_label"])
    if not variant.real_browser:
        if completed.stdout.strip():
            raise CampaignError("non-browser workload emitted an unexpected receipt")
        return None
    return validate_browser_receipt(completed.stdout, sample, variant)


def validate_browser_receipt(
    value: Any, sample: Sample, variant: Variant
) -> Dict[str, Any]:
    if isinstance(value, str):
        if len(value.encode()) > 8192 or len(value.strip().splitlines()) != 1:
            raise CampaignError("real-browser workload must emit one bounded JSON receipt")
        try:
            receipt = json.loads(value)
        except json.JSONDecodeError as error:
            raise CampaignError("real-browser workload receipt is not JSON") from error
    else:
        receipt = value
    if not isinstance(receipt, dict):
        raise CampaignError("real-browser workload receipt must be an object")
    if len(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()) > 8192:
        raise CampaignError("real-browser workload receipt exceeds the size limit")
    fields = {
        "schema_version", "status", "kind", "client_implementation",
        "implementation_version", "browser_binary_sha256", "protocol",
        "workload", "sample_seed", "next_hop_protocols", "request_count",
        "response_bytes", "result_sha256",
    }
    exact_keys(receipt, fields, "real-browser workload receipt")
    expected = {
        "schema_version": 1,
        "status": "pass",
        "kind": "real-browser-workload",
        "client_implementation": variant.client_implementation,
        "implementation_version": variant.implementation_version,
        "protocol": sample.wire_profile,
        "workload": sample.workload,
        "sample_seed": sample.sample_seed,
    }
    if any(receipt.get(name) != expected_value for name, expected_value in expected.items()):
        raise CampaignError("real-browser workload receipt does not match the frozen sample")
    digest = receipt.get("browser_binary_sha256")
    result_digest = receipt.get("result_sha256")
    if not isinstance(digest, str) or not SHA_RE.fullmatch(digest):
        raise CampaignError("real-browser receipt has an invalid executable digest")
    if digest != variant.browser_binary_sha256:
        raise CampaignError("real-browser receipt executable digest changed")
    if not isinstance(result_digest, str) or not SHA_RE.fullmatch(result_digest):
        raise CampaignError("real-browser receipt has an invalid result digest")
    spec = BROWSER_WORKLOAD_SPECS.get(sample.workload)
    if spec is None:
        raise CampaignError("real-browser workload is not in the frozen receipt matrix")
    protocols = receipt.get("next_hop_protocols")
    if (
        not isinstance(protocols, list) or len(protocols) != spec["requests"]
        or any(item != sample.wire_profile for item in protocols)
    ):
        raise CampaignError("real-browser receipt reports the wrong negotiated protocol")
    expected_numbers = {
        "request_count": spec["requests"],
        "response_bytes": spec["response_bytes"],
    }
    for name, expected_number in expected_numbers.items():
        number = receipt.get(name)
        if (
            not isinstance(number, int) or isinstance(number, bool)
            or number != expected_number
        ):
            raise CampaignError(f"real-browser receipt has invalid {name}")
    expected_result_digest = browser_result_digest(sample, protocols, spec)
    if result_digest != expected_result_digest:
        raise CampaignError("real-browser receipt result digest does not bind its workload")
    return receipt


def browser_result_digest(
    sample: Sample, protocols: Sequence[str], spec: Mapping[str, int],
) -> str:
    result_document = {
        "protocol": sample.wire_profile,
        "workload": sample.workload,
        "sample_seed": sample.sample_seed,
        "request_count": spec["requests"],
        "response_bytes": spec["response_bytes"],
        "upload_bytes": spec["upload_bytes"],
        "resources": [
            {"request_index": index, "next_hop_protocol": protocol}
            for index, protocol in enumerate(protocols)
        ],
    }
    return hashlib.sha256(json.dumps(
        result_document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def capture_transport(sample: Sample, variant: Variant) -> str:
    if sample.wire_profile == "h2":
        if not sample.auxiliary or sample.product != "cover":
            raise CampaignError("TCP capture is allowed only for auxiliary cover H2")
        return "tcp"
    if sample.wire_profile != "h3" or variant.transport != "udp":
        raise CampaignError("comparison capture must use H3 over UDP")
    return "udp"


def helper_command(
    docker: str, image: str, container_id: str, label: str,
    entrypoint: str, arguments: Sequence[str], net_admin: bool,
) -> List[str]:
    result = [
        docker, "run", "--rm", "--label", label, "--network",
        f"container:{container_id}", "--read-only", "--cap-drop", "ALL",
    ]
    if net_admin:
        result.extend(["--cap-add", "NET_ADMIN"])
    result.extend([
        "--security-opt", "no-new-privileges", "--entrypoint", entrypoint,
        image, *arguments,
    ])
    return result


def qdisc_show(
    docker: str, image: str, container_id: str, interface: str, label: str
) -> str:
    return command(
        helper_command(
            docker, image, container_id, label, "tc",
            ("qdisc", "show", "dev", interface), False,
        ),
        "inspect container qdisc",
    ).stdout


def ensure_default_qdisc(
    docker: str, image: str, container_id: str, interface: str,
    label: str, description: str,
) -> None:
    current = qdisc_show(docker, image, container_id, interface, label)
    if not qdisc_is_default(current):
        raise CampaignError(
            f"{description} has a non-default qdisc; refusing to replace it"
        )


def add_root_netem(
    docker: str, image: str, container_id: str, interface: str, label: str,
    handle: str, delay: int, loss: str, seed: int,
) -> None:
    command(
        helper_command(
            docker, image, container_id, label, "tc",
            (
                "qdisc", "add", "dev", interface, "root", "handle", f"{handle}:",
                "netem", "delay", f"{delay}ms", "loss", f"{loss}%",
                "seed", str(seed),
            ),
            True,
        ),
        "apply namespace-local netem",
    )
    installed = qdisc_show(docker, image, container_id, interface, label)
    validate_root_netem_state(installed, handle, require_present=True)


def remove_root_netem(
    docker: str, image: str, container_id: str, interface: str,
    label: str, handle: str,
) -> None:
    current = qdisc_show(docker, image, container_id, interface, label)
    if not validate_root_netem_state(current, handle, require_present=False):
        return
    command(
        helper_command(
            docker, image, container_id, label, "tc",
            ("qdisc", "del", "dev", interface, "root", "handle", f"{handle}:"),
            True,
        ),
        "remove namespace-local netem",
    )
    validate_default_qdisc(
        qdisc_show(docker, image, container_id, interface, label),
        "sample client",
    )


def add_server_netem(
    docker: str, image: str, container_id: str, interface: str, label: str,
    handle: str, client_ip: str, delay: int, loss: str, seed: int,
) -> None:
    client = str(rfc1918_ip(client_ip, "server netem client IP"))
    child = qdisc_child_handle(handle)
    common = (docker, image, container_id, label)
    command(
        helper_command(
            *common, "tc",
            (
                "qdisc", "add", "dev", interface, "root", "handle", f"{handle}:",
                "prio", "bands", "3", "priomap", *("0",) * 16,
            ),
            True,
        ),
        "apply server egress classifier",
    )
    command(
        helper_command(
            *common, "tc",
            (
                "qdisc", "add", "dev", interface, "parent", f"{handle}:3",
                "handle", f"{child}:", "netem", "delay", f"{delay}ms",
                "loss", f"{loss}%", "seed", str(seed),
            ),
            True,
        ),
        "apply client-scoped server netem",
    )
    command(
        helper_command(
            *common, "tc",
            (
                "filter", "add", "dev", interface, "protocol", "ip",
                "parent", f"{handle}:", "prio", "1", "u32", "match",
                "ip", "dst", f"{client}/32", "flowid", f"{handle}:3",
            ),
            True,
        ),
        "apply client destination filter",
    )
    validate_server_netem_state(
        qdisc_show(docker, image, container_id, interface, label),
        filter_show(docker, image, container_id, interface, label, handle),
        handle, {client}, (), require_complete=True,
    )


def remove_server_netem(
    docker: str, image: str, container_id: str, interface: str, label: str,
    handle: str, expected_client_ips: Optional[Iterable[str]],
    allowed_subnets: Sequence[str],
) -> None:
    current = qdisc_show(docker, image, container_id, interface, label)
    if qdisc_is_default(current):
        return
    filters = filter_show(docker, image, container_id, interface, label, handle)
    expected = (
        {str(rfc1918_ip(item, "stale netem client IP")) for item in expected_client_ips}
        if expected_client_ips is not None else None
    )
    validate_server_netem_state(
        current, filters, handle, expected, allowed_subnets, require_complete=False,
    )
    command(
        helper_command(
            docker, image, container_id, label, "tc",
            ("qdisc", "del", "dev", interface, "root", "handle", f"{handle}:"),
            True,
        ),
        "remove client-scoped server netem",
    )
    validate_default_qdisc(
        qdisc_show(docker, image, container_id, interface, label),
        "dedicated server",
    )


def filter_show(
    docker: str, image: str, container_id: str, interface: str,
    label: str, handle: str,
) -> str:
    return command(
        helper_command(
            docker, image, container_id, label, "tc",
            ("filter", "show", "dev", interface, "parent", f"{handle}:"), False,
        ),
        "inspect container traffic filter",
    ).stdout


def qdisc_lines(value: str) -> List[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def qdisc_is_default(value: str) -> bool:
    lines = qdisc_lines(value)
    return not lines or all(
        line.startswith("qdisc noqueue 0:") and re.search(r"\broot\b", line)
        for line in lines
    )


def validate_default_qdisc(value: str, description: str) -> None:
    if not qdisc_is_default(value):
        raise CampaignError(f"{description} qdisc was not safely restored")


def validate_root_netem_state(
    value: str, handle: str, require_present: bool,
) -> bool:
    if qdisc_is_default(value):
        if require_present:
            raise CampaignError("owned client netem handle was not installed")
        return False
    lines = qdisc_lines(value)
    pattern = re.compile(
        rf"^qdisc netem {re.escape(handle)}: .*\broot\b"
    )
    if len(lines) != 1 or not pattern.search(lines[0]):
        raise CampaignError("refusing to alter a client qdisc not owned by this campaign")
    return True


def validate_server_netem_state(
    qdiscs: str, filters: str, handle: str,
    expected_client_ips: Optional[Iterable[str]], allowed_subnets: Sequence[str],
    require_complete: bool,
) -> bool:
    if qdisc_is_default(qdiscs):
        if filters.strip():
            raise CampaignError("server has traffic filters without the campaign qdisc")
        if require_complete:
            raise CampaignError("owned server netem handle was not installed")
        return False
    child = qdisc_child_handle(handle)
    lines = qdisc_lines(qdiscs)
    roots = [line for line in lines if re.search(r"\broot\b", line)]
    root_pattern = re.compile(rf"^qdisc prio {re.escape(handle)}: ")
    if len(roots) != 1 or not root_pattern.search(roots[0]):
        raise CampaignError("refusing to alter a server qdisc not owned by this campaign")
    if not re.search(r"\bbands 3\b", roots[0]):
        raise CampaignError("campaign server qdisc has unexpected bands")
    if "priomap" not in roots[0] or roots[0].split("priomap", 1)[1].split()[:16] != ["0"] * 16:
        raise CampaignError("campaign server qdisc could impair unmatched traffic")
    children = [line for line in lines if line not in roots]
    child_pattern = re.compile(
        rf"^qdisc netem {re.escape(child)}: parent {re.escape(handle)}:3(?:\s|$)"
    )
    if len(children) > 1 or (children and not child_pattern.search(children[0])):
        raise CampaignError("campaign server qdisc has an unexpected child")
    if require_complete and not children:
        raise CampaignError("campaign server netem child is missing")

    if filters.strip():
        if "u32" not in filters or not re.search(r"\bprotocol ip\b", filters):
            raise CampaignError("campaign server filter is not an IPv4 u32 filter")
        matches = re.findall(
            r"^\s*match\s+([0-9A-Fa-f]{8})/([0-9A-Fa-f]{8})\s+at\s+16\s*$",
            filters, re.MULTILINE,
        )
        if len(matches) != 1 or matches[0][1].lower() != "ffffffff":
            raise CampaignError("campaign server filter lacks one exact destination")
        try:
            destination = ipaddress.IPv4Address(bytes.fromhex(matches[0][0]))
        except ValueError as error:
            raise CampaignError("campaign server filter destination is invalid") from error
        address = str(destination)
        if expected_client_ips is not None:
            expected = {
                str(rfc1918_ip(item, "expected netem client IP"))
                for item in expected_client_ips
            }
            if address not in expected:
                raise CampaignError("campaign server filter targets another client")
        else:
            parsed_subnets = [ipaddress.ip_network(item) for item in allowed_subnets]
            if not parsed_subnets or not any(
                destination in item for item in parsed_subnets
            ):
                raise CampaignError("stale server filter escaped the frozen lab subnet")
        classes = re.findall(
            r"\b(?:classid|flowid)\s+([0-9A-Fa-f]+:[0-9A-Fa-f]+)\b", filters
        )
        if not classes or set(classes) != {f"{handle}:3"}:
            raise CampaignError("campaign server filter targets an unexpected class")
    elif require_complete:
        raise CampaignError("campaign server destination filter is missing")
    return True


def qdisc_handle(campaign_id: str) -> str:
    number = (
        int(hashlib.sha256(campaign_id.encode()).hexdigest()[:4], 16) % 0xFFFE
    ) + 1
    return format(number, "x")


def qdisc_child_handle(handle: str) -> str:
    number = (int(handle, 16) % 0xFFFE) + 1
    return format(number, "x")


def wait_capture(docker: str, capture_id: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        logs = command([docker, "logs", capture_id], "read tcpdump logs", check=False)
        if "listening on" in logs.stdout + logs.stderr:
            return
        running = command(
            [docker, "inspect", "--format", "{{.State.Running}}", capture_id],
            "inspect tcpdump", check=False,
        ).stdout.strip()
        if running == "false":
            raise CampaignError("tcpdump exited before readiness")
        time.sleep(0.1)
    raise CampaignError("timed out waiting for tcpdump")


def stop_capture(docker: str, capture_id: str) -> None:
    command(
        [docker, "kill", "--signal", "INT", capture_id],
        "interrupt tcpdump", check=False,
    )
    waited = command(
        [docker, "wait", capture_id], "wait for tcpdump", timeout=10, check=False
    )
    try:
        exit_code = int(waited.stdout.strip())
    except ValueError as error:
        raise CampaignError("tcpdump did not report an exit code") from error
    if exit_code not in (0, 130):
        raise CampaignError(f"tcpdump exited with status {exit_code}")


def verify_pcap(
    docker: str, image: str, path: Path, server_ip: str,
    server_port: int, transport: str, minimum_packets: int,
) -> int:
    result = command(
        [
            docker, "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,src={path},dst=/capture.pcap,readonly",
            "--entrypoint", "tcpdump", image, "-nn", "-r", "/capture.pcap",
            f"{transport} and host {server_ip} and port {server_port}",
        ],
        "validate endpoint-scoped PCAP",
    )
    packets = sum(bool(line.strip()) for line in result.stdout.splitlines())
    if packets < minimum_packets:
        raise CampaignError(
            f"PCAP has {packets} endpoint packets; need at least {minimum_packets}"
        )
    return packets


def remove_container(docker: str, name: str, expected_label: str) -> None:
    document = inspect_owned_container(docker, name, expected_label)
    if document is None:
        return
    command([docker, "container", "rm", "-f", name], "remove owned container")


def inspect_owned_container(
    docker: str, name: str, expected_label: str,
) -> Optional[Mapping[str, Any]]:
    inspected = command(
        [docker, "container", "inspect", name], "inspect owned container", check=False
    )
    if inspected.returncode != 0:
        return None
    try:
        document = one_inspect(json.loads(inspected.stdout), "owned container")
    except (json.JSONDecodeError, CampaignError) as error:
        raise CampaignError(f"cannot verify ownership of container {name!r}") from error
    key, value = split_label(expected_label)
    actual_name = document.get("Name")
    if actual_name != f"/{name}":
        raise CampaignError(f"container inspection did not resolve exact name {name!r}")
    if ((document.get("Config") or {}).get("Labels") or {}).get(key) != value:
        raise CampaignError(
            f"refusing to use container {name!r} with mismatched ownership"
        )
    return document


def container_ip(docker: str, container_id: str, network: str) -> str:
    document = one_inspect(
        json_command([docker, "container", "inspect", container_id], "inspect anchor"),
        "anchor",
    )
    networks = (document.get("NetworkSettings") or {}).get("Networks") or {}
    if set(networks) != {network}:
        raise CampaignError("sample namespace is attached outside the lab network")
    address = (networks[network] or {}).get("IPAddress")
    return str(rfc1918_ip(address, "anchor IP"))


def cleanup_stale_sample_resources(
    docker: str, config: Mapping[str, Any], runtime: Mapping[str, Any],
    samples: Sequence[Sample], completed: Mapping[str, Any],
) -> None:
    """Remove only frozen unfinished-sample resources after both locks are held."""
    lab = config["lab"]
    unfinished = [sample for sample in samples if sample.sample_id not in completed]
    expected = unfinished_resource_map(config["campaign_id"], samples, completed)

    listed = command(
        [
            docker, "container", "ls", "--all", "--filter",
            f"label={lab['ownership_label']}", "--format", "{{.Names}}",
        ],
        "list campaign-labelled containers",
    ).stdout.splitlines()
    stale_names = {name.strip() for name in listed if name.strip()} & set(expected)

    stale_anchors: Dict[str, Tuple[str, str]] = {}
    server_clients: Dict[str, set] = {}
    for name in sorted(stale_names):
        sample, kind = expected[name]
        if kind != "anchor":
            continue
        document = inspect_owned_container(docker, name, lab["ownership_label"])
        if document is None:
            continue
        container_id = document.get("Id")
        if not isinstance(container_id, str) or not container_id:
            raise CampaignError(f"stale anchor {name!r} has no immutable ID")
        state = document.get("State") or {}
        if state.get("Running") is not True:
            # A stopped container has no live network namespace or qdisc to clean.
            continue
        client_ip = container_ip(docker, container_id, lab["docker_network"])
        stale_anchors[name] = (container_id, client_ip)
        variant = config["products"][sample.product][sample.variant_index]
        server_id = runtime["servers"][variant.server_container]["id"]
        server_clients.setdefault(server_id, set()).add(client_ip)

    handle = qdisc_handle(config["campaign_id"])
    unfinished_server_ids = {
        runtime["servers"][
            config["products"][sample.product][sample.variant_index].server_container
        ]["id"]
        for sample in unfinished
    }
    for server_id in sorted(unfinished_server_ids):
        remove_server_netem(
            docker, runtime["capture_image"]["id"], server_id, lab["interface"],
            lab["ownership_label"], handle, server_clients.get(server_id),
            runtime["network_subnets"],
        )
    for container_id, _client_ip in stale_anchors.values():
        remove_root_netem(
            docker, runtime["capture_image"]["id"], container_id,
            lab["interface"], lab["ownership_label"], handle,
        )
    for kind in ("runner", "capture", "anchor"):
        for name in sorted(stale_names):
            if expected[name][1] == kind:
                remove_container(docker, name, lab["ownership_label"])


def unfinished_resource_map(
    campaign_id: str, samples: Sequence[Sample], completed: Mapping[str, Any],
) -> Dict[str, Tuple[Sample, str]]:
    expected: Dict[str, Tuple[Sample, str]] = {}
    for sample in samples:
        if sample.sample_id in completed:
            continue
        for kind, name in sample_resource_names(campaign_id, sample).items():
            if name in expected:
                raise CampaignError("frozen sample resource names collide")
            expected[name] = (sample, kind)
    return expected


def load_ledger(
    path: Path, samples: Sequence[Sample], output: Path, runtime: Mapping[str, Any],
    config: Mapping[str, Any],
) -> Dict[str, Dict[str, Any]]:
    expected = {sample.sample_id: sample for sample in samples}
    completed: Dict[str, Dict[str, Any]] = {}
    hashes: Dict[str, str] = {}
    open_sample: Optional[str] = None
    next_sample_index = 0
    if not path.is_file():
        raise CampaignError("event ledger is missing")
    for line_number, event in read_ledger_events(path):
        if not isinstance(event, dict):
            raise CampaignError(f"unsupported event at ledger line {line_number}")
        event_type = event.get("event")
        if event_type not in {"sample_started", "sample_failed", "sample_complete"}:
            raise CampaignError(f"unsupported event at ledger line {line_number}")
        sample_id = event.get("sample_id")
        if not isinstance(sample_id, str) or sample_id not in expected:
            raise CampaignError(f"ledger references unknown sample {sample_id!r}")
        if sample_id in completed:
            raise CampaignError(f"ledger contains an event after completion for {sample_id}")
        parse_time(event.get("at"), f"ledger line {line_number} timestamp")
        sample = expected[sample_id]
        variant = config["products"][sample.product][sample.variant_index]
        if event_type == "sample_started":
            if set(event) != {"event", "at", "sample_id", "variant"}:
                raise CampaignError(f"invalid start event at ledger line {line_number}")
            if event.get("variant") != variant.name:
                raise CampaignError(f"sample {sample_id} changed its frozen variant")
            if open_sample is not None:
                raise CampaignError(
                    f"ledger starts {sample_id} while {open_sample} is still open; "
                    "start a new campaign output to avoid retry selection bias"
                )
            if (
                next_sample_index >= len(samples)
                or sample_id != samples[next_sample_index].sample_id
            ):
                raise CampaignError(
                    f"ledger sample {sample_id} is outside the frozen schedule order"
                )
            open_sample = sample_id
            continue
        if event_type == "sample_failed":
            if set(event) != {"event", "at", "sample_id", "reason"}:
                raise CampaignError(f"invalid failure event at ledger line {line_number}")
            reason = event.get("reason")
            if (
                sample_id != open_sample
                or not isinstance(reason, str) or not reason or len(reason) > 4096
                or reason != reason.strip() or "\x00" in reason
            ):
                raise CampaignError(f"invalid failure event at ledger line {line_number}")
            raise CampaignError(
                f"ledger records a failed attempt for {sample_id}; "
                "start a new campaign output to preserve first-attempt evidence"
            )
        complete_fields = {
            "event", "at", "sample_id", "variant", "packets", "pcap_sha256",
            "pcap_bytes", "manifest_row",
        }
        if variant.real_browser:
            complete_fields.add("workload_receipt")
        if set(event) != complete_fields:
            raise CampaignError(f"invalid completion event at ledger line {line_number}")
        if sample_id != open_sample:
            raise CampaignError(f"completion for {sample_id} has no preceding start")
        if event.get("variant") != variant.name:
            raise CampaignError(f"sample {sample_id} changed its frozen variant")
        if variant.real_browser:
            validate_browser_receipt(event.get("workload_receipt"), sample, variant)
        row = event.get("manifest_row")
        if not isinstance(row, dict) or set(row) != set(MANIFEST_FIELDS):
            raise CampaignError(f"invalid manifest row ledger for {sample_id}")
        metadata = {
            "sample_id": sample.sample_id, "product": sample.product,
            "scenario": sample.scenario, "workload": sample.workload,
            "wire_profile": sample.wire_profile, "run_id": sample.run_id,
            "seed": sample.seed, "pcap": f"pcaps/{sample.sample_id}.pcap",
        }
        if any(row.get(key) != value for key, value in metadata.items()):
            raise CampaignError(f"frozen sample metadata changed for {sample_id}")
        for field in PROVENANCE_FIELDS:
            if not isinstance(row.get(field), str) or not row[field]:
                raise CampaignError(f"sample {sample_id} lacks {field} provenance")
        expected_server = runtime["servers"][variant.server_container]
        expected_provenance = {
            "client_implementation": variant.client_implementation,
            "server_implementation": variant.server_implementation,
            "implementation_version": variant.implementation_version,
            "runner_image_id": runtime["runner_images"][
                f"{sample.product}/{variant.name}"
            ]["id"],
            "server_container_id": expected_server["id"],
            "capture_host": runtime["capture_host"],
            "docker_engine_fingerprint": runtime["engine_fingerprint"],
            "server_ip": variant.server_ip,
        }
        if any(row.get(key) != value for key, value in expected_provenance.items()):
            raise CampaignError(f"sample {sample_id} runtime provenance binding changed")
        client = rfc1918_ip(row.get("client_ip"), "ledger client IP")
        server = rfc1918_ip(row.get("server_ip"), "ledger server IP")
        subnets = [ipaddress.ip_network(item) for item in runtime["network_subnets"]]
        if not any(client in subnet for subnet in subnets) or not any(
            server in subnet for subnet in subnets
        ):
            raise CampaignError(f"sample {sample_id} escaped the lab subnet")
        digest, size = event.get("pcap_sha256"), event.get("pcap_bytes")
        packets = event.get("packets")
        if (
            not isinstance(packets, int) or isinstance(packets, bool)
            or packets < config["lab"]["minimum_packets"]
        ):
            raise CampaignError(f"invalid PCAP packet count for {sample_id}")
        if not isinstance(digest, str) or not SHA_RE.fullmatch(digest):
            raise CampaignError(f"invalid PCAP digest for {sample_id}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 24:
            raise CampaignError(f"invalid PCAP byte count for {sample_id}")
        capture = output / row["pcap"]
        if (
            not capture.is_file() or capture.stat().st_size != size
            or file_sha256(capture) != digest
        ):
            raise CampaignError(f"completed PCAP changed for {sample_id}")
        if digest in hashes:
            raise CampaignError(
                f"samples {hashes[digest]} and {sample_id} reuse identical PCAP bytes"
            )
        hashes[digest] = sample_id
        completed[sample_id] = event
        open_sample = None
        next_sample_index += 1
    if open_sample is not None:
        raise CampaignError(
            f"ledger ends during the first attempt for {open_sample}; "
            "start a new campaign output to avoid retry selection bias"
        )
    return completed


def read_ledger_events(path: Path) -> List[Tuple[int, Any]]:
    recover_final_ledger_tail(path)
    events = []
    try:
        handle = path.open(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CampaignError("cannot read event ledger") from error
    with handle:
        try:
            for line_number, line in enumerate(handle, 1):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise CampaignError(
                        f"event ledger line {line_number} is malformed"
                    ) from error
                events.append((line_number, event))
        except UnicodeError as error:
            raise CampaignError("event ledger contains invalid UTF-8") from error
    return events


def recover_final_ledger_tail(path: Path) -> None:
    """Recover only a final record interrupted before its terminating newline."""
    descriptor = os.open(path, os.O_RDWR)
    try:
        with os.fdopen(descriptor, "r+b", closefd=False) as handle:
            contents = handle.read()
        if not contents or contents.endswith(b"\n"):
            return
        boundary = contents.rfind(b"\n") + 1
        tail = contents[boundary:]
        try:
            json.loads(tail.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            os.ftruncate(descriptor, boundary)
        else:
            os.lseek(descriptor, 0, os.SEEK_END)
            write_all(descriptor, b"\n", "event ledger")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reconcile_pcaps(
    output: Path, samples: Sequence[Sample], completed: Mapping[str, Any]
) -> None:
    directory = output / "pcaps"
    directory.mkdir(mode=0o700, exist_ok=True)
    expected = {sample.sample_id for sample in samples}
    for path in directory.iterdir():
        if path.name.startswith(".") and path.name.endswith(".partial.pcap"):
            quarantine(output, path, path.name)
        elif path.suffix != ".pcap":
            raise CampaignError(f"unexpected file in PCAP directory: {path.name}")
        elif path.stem not in expected:
            raise CampaignError(f"unexpected PCAP outside frozen schedule: {path.name}")
        elif path.stem not in completed:
            quarantine(output, path, path.stem + "-orphan")


def quarantine(output: Path, path: Path, label: str) -> None:
    if not path.exists():
        return
    directory = output / "quarantine"
    directory.mkdir(mode=0o700, exist_ok=True)
    suffix = hashlib.sha256(f"{label}|{time.time_ns()}".encode()).hexdigest()[:12]
    os.replace(path, directory / f"{Path(label).name}.{suffix}.pcap")


def render_manifest(
    samples: Sequence[Sample], completed: Mapping[str, Mapping[str, Any]]
) -> bytes:
    with tempfile.TemporaryFile(mode="w+", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, lineterminator="\n")
        writer.writeheader()
        for sample in samples:
            event = completed.get(sample.sample_id)
            if event:
                writer.writerow(event["manifest_row"])
        handle.seek(0)
        return handle.read().encode()


def reconcile_manifest(path: Path, expected: bytes) -> int:
    """Repair only a manifest that is an exact byte prefix of the durable ledger."""
    if path.exists():
        current = path.read_bytes()
        if not expected.startswith(current):
            raise CampaignError("capture manifest differs from durable completion ledger")
        suffix = expected[len(current):]
        if suffix:
            append_bytes(path, suffix, len(current))
    else:
        write_bytes(path, expected)
    return len(expected)


def render_manifest_row(row: Mapping[str, Any]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, lineterminator="\n")
    writer.writerow(row)
    return handle.getvalue().encode()


def append_manifest_row(path: Path, row: Mapping[str, Any], expected_size: int) -> int:
    data = render_manifest_row(row)
    append_bytes(path, data, expected_size)
    return expected_size + len(data)


def append_bytes(path: Path, data: bytes, expected_size: int) -> None:
    if not path.is_file() or path.stat().st_size != expected_size:
        raise CampaignError("capture manifest changed during campaign")
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        write_all(descriptor, data, "capture manifest")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, data: bytes, label: str) -> None:
    written = 0
    while written < len(data):
        try:
            count = os.write(descriptor, data[written:])
        except InterruptedError:
            continue
        if count <= 0:
            raise CampaignError(f"could not append {label}")
        written += count


def update_campaign(
    path: Path, config: Mapping[str, Any], prereg: Mapping[str, Any],
    identity: Mapping[str, Any], source: Mapping[str, Any], state: Mapping[str, Any],
    manifest_path: Path, samples: Sequence[Sample],
    completed: Mapping[str, Mapping[str, Any]],
) -> None:
    full = (
        identity["mode"] == "full" and state.get("status") == "complete"
        and len(completed) == len(samples)
    )
    cover = config["products"]["cover"]
    cover_events = [
        event for event in completed.values()
        if event["manifest_row"]["product"] == "cover"
    ]
    variants = {event["variant"] for event in cover_events}
    h2_variants = {
        event["variant"] for event in cover_events
        if event["manifest_row"]["wire_profile"] == "h2"
        and isinstance(event.get("workload_receipt"), dict)
    }
    h3_variants = {
        event["variant"] for event in cover_events
        if event["manifest_row"]["wire_profile"] == "h3"
        and isinstance(event.get("workload_receipt"), dict)
    }
    browser_h2_h3 = full and all(
        variant.real_browser and variant.name in h3_variants and variant.name in h2_variants
        for variant in cover
    )
    files = source["files"]
    document = {
        "schema_version": 1,
        "status": "pass" if full else "insufficient_evidence",
        "campaign_id": config["campaign_id"],
        "claim_scope": "hysteria2-v2.12.2-standard",
        "autocar_commit": source["git_head"],
        "preregistration_git_commit": source["git_head"],
        "preregistration_sha256": source["preregistration"]["sha256"],
        "preregistration_recorded_before_capture": bool(
            state.get("capture_started_at")
            and parse_time(source["preregistration_recorded_at"], "registration")
            < parse_time(state["capture_started_at"], "capture start")
        ),
        "preregistration_recorded_at": source["preregistration_recorded_at"],
        "capture_manifest_sha256": file_sha256(manifest_path),
        "products": {
            "autocar": {
                "commit": source["git_head"],
                "binary_sha256": files["autocar_binary"]["sha256"],
                "config_sha256": files["autocar_config"]["sha256"],
            },
            "hysteria2": {
                "version": prereg["baseline"]["hysteria2_version"],
                "commit": prereg["baseline"]["hysteria2_commit"],
                "binary_sha256": files["hysteria2_binary"]["sha256"],
                "config_sha256": files["hysteria2_config"]["sha256"],
            },
            "cover": {
                "client_implementations": sorted({
                    variant.client_implementation for variant in cover
                    if variant.name in variants
                }),
                "server_implementations": sorted({
                    variant.server_implementation for variant in cover
                    if variant.name in variants
                }),
                "real_browser_h2_h3_present": browser_h2_h3,
            },
        },
        "driver": {
            "mode": identity["mode"],
            "configuration_sha256": identity["configuration_sha256"],
            "schedule_sha256": identity["schedule_sha256"],
            "required_samples": identity["required_sample_count"],
            "auxiliary_samples": identity["auxiliary_sample_count"],
            "completed_samples": len(completed),
            "per_sample_provenance_in_capture_manifest": list(PROVENANCE_FIELDS),
            "fresh_network_namespace_per_sample": True,
            "host_interface_capture": False,
            "host_qdisc_modified": False,
        },
    }
    if state.get("capture_started_at"):
        document["capture_started_at"] = state["capture_started_at"]
    if state.get("capture_completed_at"):
        document["capture_completed_at"] = state["capture_completed_at"]
    write_json(path, document)


def summary(
    status: str, output: Path, samples: Sequence[Sample], completed: Mapping[str, Any]
) -> Dict[str, Any]:
    return {
        "status": status, "output": str(output), "total_samples": len(samples),
        "completed_samples": len(completed),
    }


def schedule_digest(samples: Sequence[Sample]) -> str:
    digest = hashlib.sha256()
    for sample in samples:
        digest.update(json.dumps(
            {
                "sample_id": sample.sample_id, "product": sample.product,
                "scenario": sample.scenario, "workload": sample.workload,
                "wire_profile": sample.wire_profile, "run_id": sample.run_id,
                "seed": sample.seed, "sample_seed": sample.sample_seed,
                "variant_index": sample.variant_index, "auxiliary": sample.auxiliary,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def prepare_output(path: Path, resume: bool) -> bool:
    if resume:
        if not path.is_dir():
            raise CampaignError("--resume requires an existing output directory")
        recover_legacy_campaign_lock(path)
        return False
    created = not path.exists()
    if path.exists() and not path.is_dir():
        raise CampaignError("refusing to overwrite non-empty output")
    if path.is_dir():
        entries = list(path.iterdir())
        if len(entries) == 1 and entries[0].name == ".campaign.lock":
            recover_legacy_campaign_lock(path)
            entries = []
        if entries:
            raise CampaignError("refusing to overwrite non-empty output")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return created


def recover_legacy_campaign_lock(output: Path) -> None:
    legacy_path = output / ".campaign.lock"
    if not legacy_path.exists() and not legacy_path.is_symlink():
        return
    if legacy_path.is_symlink() or not legacy_path.is_file():
        raise CampaignError("legacy campaign lock is not a regular file")
    legacy_lock = acquire_lock(legacy_path, "legacy campaign")
    try:
        legacy_path.unlink()
    finally:
        legacy_lock.close()


def initialize_new_output(
    output: Path, paths: Mapping[str, Path], plan: Mapping[str, Any],
    state: Mapping[str, Any], remove_output_on_failure: bool,
) -> None:
    try:
        write_json(paths["plan"], plan)
        write_json(paths["state"], state)
        descriptor = os.open(
            paths["events"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(output, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        # The directory was proven empty immediately before initialization, so
        # these are the only exact paths this transaction can have created.
        for initialized_path in (paths["events"], paths["state"], paths["plan"]):
            try:
                initialized_path.unlink()
            except FileNotFoundError:
                pass
        if remove_output_on_failure:
            try:
                output.rmdir()
            except FileNotFoundError:
                pass
        raise


def safe_output(value: Path) -> Path:
    path = value.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    result = path.resolve(strict=False)
    if result == Path("/") or path.name in {"", ".", ".."}:
        raise CampaignError("unsafe output path")
    return result


def acquire_lock(path: Path, label: str):
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        handle.close()
        raise CampaignError(f"another process holds the {label} lock") from error
    return handle


def acquire_output_lock(output: Path):
    return acquire_lock(output_lock_path(output), "campaign output")


def output_lock_path(output: Path) -> Path:
    digest = hashlib.sha256(str(output).encode("utf-8")).hexdigest()[:24]
    return Path(tempfile.gettempdir()) / (
        f"autocar-stealth-output-{os.getuid()}-{digest}.lock"
    )


def acquire_network_lock(network_id: str):
    if not isinstance(network_id, str) or not network_id:
        raise CampaignError("network has no immutable Docker ID")
    digest = hashlib.sha256(network_id.encode()).hexdigest()[:24]
    return acquire_lock(
        Path(tempfile.gettempdir()) / f"autocar-stealth-network-{digest}.lock",
        "lab network",
    )


def command(
    arguments: Sequence[str], label: str, timeout: Optional[int] = 30,
    check: bool = True,
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            list(arguments), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as error:
        raise CampaignError(f"{label}: executable not found") from error
    if check and result.returncode:
        diagnostic = result.stderr.strip().splitlines()[-1:] or ["no diagnostic"]
        raise CampaignError(
            f"{label} failed with exit {result.returncode}: {diagnostic[0]}"
        )
    return result


def json_command(arguments: Sequence[str], label: str) -> Any:
    result = command(arguments, label)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CampaignError(f"{label} did not return JSON") from error


def one_inspect(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise CampaignError(f"{label} inspection returned an unexpected shape")
    return value[0]


def exact_keys(
    value: Mapping[str, Any], fields: Iterable[str], label: str,
    optional: Iterable[str] = (),
) -> None:
    allowed, optional_set = set(fields), set(optional)
    unknown = set(value).difference(allowed)
    missing = allowed.difference(optional_set).difference(value)
    if unknown:
        raise CampaignError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise CampaignError(f"{label} lacks fields: {', '.join(sorted(missing))}")


def require_object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CampaignError(f"{label} must be an object")
    return value


def require_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or "\x00" in value or "\n" in value or "\r" in value
    ):
        raise CampaignError(f"{label} must be a trimmed, non-empty single-line string")
    return value


def safe_name(value: Any, label: str) -> str:
    text = require_text(value, label)
    if not NAME_RE.fullmatch(text):
        raise CampaignError(f"{label} contains unsupported characters")
    return text


def bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int) or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise CampaignError(f"{label} must be in {minimum}..{maximum}")
    return value


def rfc1918_ip(value: Any, label: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as error:
        raise CampaignError(f"{label} must be numeric RFC1918 IPv4") from error
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in network for network in RFC1918
    ):
        raise CampaignError(f"{label} must be numeric RFC1918 IPv4")
    return address


def split_label(value: str) -> Tuple[str, str]:
    if value.count("=") != 1:
        raise CampaignError("ownership label must contain one equals sign")
    key, label_value = value.split("=", 1)
    if key != LABEL_KEY or not NAME_RE.fullmatch(label_value):
        raise CampaignError("ownership label is malformed")
    return key, label_value


def resolve_path(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise CampaignError(f"configured path does not exist: {value}") from error


def require_under_roots(path: Path, roots: Sequence[Path], label: str) -> None:
    for root in roots:
        try:
            path.relative_to(root)
            return
        except ValueError:
            pass
    raise CampaignError(f"{label} is outside allowed_mount_roots")


def read_object(path: Path, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise CampaignError(f"{label} file is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"cannot parse {label}") from error
    if not isinstance(value, dict):
        raise CampaignError(f"{label} must be a JSON object")
    return value


def file_snapshot(path: Path) -> Dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise CampaignError(f"provenance file is empty or missing: {path.name}")
    return {
        "name": path.name, "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    write_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def write_bytes(path: Path, value: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def append_event(path: Path, event: Mapping[str, Any]) -> None:
    encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        write_all(descriptor, encoded, "event ledger")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise CampaignError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CampaignError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise CampaignError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def utc_now() -> str:
    return format_time(dt.datetime.now(dt.timezone.utc))


def git(repo: Path, *arguments: str) -> str:
    return command(
        ["git", "-C", str(repo), *arguments], "read Git provenance"
    ).stdout.strip()


def first_line(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return lines[0][:300] if lines else "available"


def self_test() -> None:
    prereg_path = (
        Path(__file__).resolve().parent.parent / "testdata/stealth/preregistration.json"
    )
    prereg = read_object(prereg_path, "preregistration")
    validate_preregistration(prereg)
    if len(prereg["required_common_cells"]) != 21:
        raise AssertionError("frozen campaign must contain 21 cells")
    products = {}
    for product in PRODUCTS:
        count = 2 if product == "cover" else 1
        products[product] = tuple(
            Variant(
                product=product, name=f"v{index}",
                client_implementation=f"client-{index}",
                server_implementation=f"server-{index}",
                implementation_version="test-1",
                real_browser=product == "cover",
                browser_binary_sha256=("1" * 64) if product == "cover" else None,
                runner_image="runner", server_container=f"server-{index}",
                server_ip=f"10.23.0.{index + 2}", server_port=8443,
                transport="udp",
                command=("/runner", "{workload}", "{server_ip}", "{sample_seed}"),
                h2_command=("/runner", "h2") if product == "cover" else (),
                environment=(), mounts=(), user="65532:65532",
            )
            for index in range(count)
        )
    cells = [cell_tuple(item) for item in prereg["required_common_cells"]]
    full = build_schedule(prereg, products, cells, 5, 100, 20260904, True)
    if sum(not sample.auxiliary for sample in full) != 21 * 3 * 500:
        raise AssertionError("full schedule is not 31,500 required samples")
    if sum(sample.auxiliary for sample in full) != 10 or len(full) != 31_510:
        raise AssertionError("full schedule is not exactly 31,500 required plus 10 H2 auxiliary")
    validate_mode(
        "full", {"products": products}, prereg, prereg_path,
        Path(__file__).resolve().parent.parent, full,
    )
    if len({sample.sample_id for sample in full}) != len(full):
        raise AssertionError("sample IDs are not unique")
    calibration = build_schedule(prereg, products, cells, 1, 1, 7, True)
    calibration_required = [sample for sample in calibration if not sample.auxiliary]
    calibration_auxiliary = [sample for sample in calibration if sample.auxiliary]
    if len(calibration_required) != 63 or len(calibration_auxiliary) != 2 or len(calibration) != 65:
        raise AssertionError("calibration schedule is not exactly 63 required plus two H2 controls")
    if {
        sample.variant_index for sample in calibration_required
        if sample.product == "cover" and sample.wire_profile == "h3"
    } != {0, 1}:
        raise AssertionError("calibration H3 cover cells do not exercise both browsers")
    if {sample.variant_index for sample in calibration_auxiliary} != {0, 1}:
        raise AssertionError("calibration H2 controls do not exercise both browsers")
    validate_mode(
        "calibration", {"products": products}, prereg, prereg_path,
        Path(__file__).resolve().parent.parent, calibration,
    )
    tiny = build_schedule(prereg, products, cells[:1], 1, 1, 7, False)
    if len(tiny) != 3 or {sample.product for sample in tiny} != set(PRODUCTS):
        raise AssertionError("calibration schedule is not balanced")
    if {sample.product for sample in tiny[:3]} != set(PRODUCTS):
        raise AssertionError("paired product triplet is not adjacent")
    try:
        validate_mode(
            "calibration", {"products": products}, prereg, prereg_path,
            Path(__file__).resolve().parent.parent,
            build_schedule(prereg, products, cells[:1], 1, 1, 7, True),
        )
    except CampaignError:
        pass
    else:
        raise AssertionError("underspecified browser-diversity calibration was accepted")
    auxiliary = Sample(
        "aux", "cover", "cover_diversity", "browser_h2", "h2",
        "run-01", "seed-1", 1, 0, True,
    )
    if capture_transport(tiny[0], products[tiny[0].product][0]) != "udp":
        raise AssertionError("H3 capture transport is not UDP")
    if capture_transport(auxiliary, products["cover"][0]) != "tcp":
        raise AssertionError("auxiliary H2 capture transport is not TCP")
    registered_host = prereg["active_evidence"]["remote_execution_host"]
    validate_capture_host_binding(prereg, registered_host)
    try:
        validate_capture_host_binding(prereg, "198.51.100.1:22")
    except CampaignError:
        pass
    else:
        raise AssertionError("non-preregistered capture host was accepted")
    browser_sample = next(item for item in tiny if item.product == "cover")
    browser_variant = products["cover"][browser_sample.variant_index]
    browser_spec = BROWSER_WORKLOAD_SPECS[browser_sample.workload]
    browser_protocols = [browser_sample.wire_profile] * browser_spec["requests"]
    browser_receipt = {
        "schema_version": 1,
        "status": "pass",
        "kind": "real-browser-workload",
        "client_implementation": browser_variant.client_implementation,
        "implementation_version": browser_variant.implementation_version,
        "browser_binary_sha256": "1" * 64,
        "protocol": browser_sample.wire_profile,
        "workload": browser_sample.workload,
        "sample_seed": browser_sample.sample_seed,
        "next_hop_protocols": browser_protocols,
        "request_count": browser_spec["requests"],
        "response_bytes": browser_spec["response_bytes"],
        "result_sha256": browser_result_digest(
            browser_sample, browser_protocols, browser_spec
        ),
    }
    if validate_browser_receipt(browser_receipt, browser_sample, browser_variant) != browser_receipt:
        raise AssertionError("valid browser receipt changed during validation")
    wrong_protocol = dict(browser_receipt, next_hop_protocols=["h2"])
    try:
        validate_browser_receipt(wrong_protocol, browser_sample, browser_variant)
    except CampaignError:
        pass
    else:
        raise AssertionError("wrong browser protocol receipt was accepted")
    for invalid_receipt in (
        dict(browser_receipt, request_count=browser_receipt["request_count"] + 1),
        dict(browser_receipt, response_bytes=browser_receipt["response_bytes"] + 1),
        dict(browser_receipt, result_sha256="2" * 64),
    ):
        try:
            validate_browser_receipt(invalid_receipt, browser_sample, browser_variant)
        except CampaignError:
            pass
        else:
            raise AssertionError("unbound browser workload receipt was accepted")
    if impairment("delay35_loss0.5") != (35, "0.5"):
        raise AssertionError("scenario parser failed")
    for address in ("127.0.0.1", "169.254.1.1", "8.8.8.8", "::1"):
        try:
            rfc1918_ip(address, "test")
        except CampaignError:
            pass
        else:
            raise AssertionError(f"unsafe address accepted: {address}")
    validate_template("https://{server_ip}:{server_port}/{workload}", "test")
    for value in ("{unknown}", "{server_ip.__class__}", "{"):
        try:
            validate_template(value, "test")
        except CampaignError:
            pass
        else:
            raise AssertionError(f"unsafe template accepted: {value}")
    if qdisc_handle("one") == qdisc_handle("two"):
        raise AssertionError("qdisc handles unexpectedly collide in fixture")
    handle = qdisc_handle("self-test-campaign")
    child = qdisc_child_handle(handle)
    if child == handle:
        raise AssertionError("server child qdisc handle collides with its root")
    root_fixture = (
        f"qdisc netem {handle}: root refcnt 2 limit 1000 delay 35ms loss 0.5%\n"
    )
    if not validate_root_netem_state(root_fixture, handle, require_present=True):
        raise AssertionError("owned root netem fixture was not recognized")
    server_qdisc_fixture = (
        f"qdisc netem {child}: parent {handle}:3 limit 1000 delay 35ms loss 0.5%\n"
        f"qdisc prio {handle}: root refcnt 2 bands 3 priomap "
        + " ".join(["0"] * 16) + "\n"
    )
    server_filter_fixture = (
        "filter protocol ip pref 1 u32 chain 0\n"
        "filter protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1\n"
        f"filter protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 "
        f"key ht 800 bkt 0 flowid {handle}:3 not_in_hw\n"
        "  match 0a17000a/ffffffff at 16\n"
    )
    if not validate_server_netem_state(
        server_qdisc_fixture, server_filter_fixture, handle, {"10.23.0.10"}, (), True
    ):
        raise AssertionError("client-scoped server netem fixture was not recognized")
    try:
        validate_server_netem_state(
            server_qdisc_fixture,
            server_filter_fixture.replace("0a17000a", "0a17000b"),
            handle, {"10.23.0.10"}, (), True,
        )
    except CampaignError:
        pass
    else:
        raise AssertionError("server netem for another client was accepted")
    unsafe_priomap = server_qdisc_fixture.replace(
        "priomap 0", "priomap 2", 1
    )
    try:
        validate_server_netem_state(
            unsafe_priomap, server_filter_fixture, handle, {"10.23.0.10"}, (), True
        )
    except CampaignError:
        pass
    else:
        raise AssertionError("server netem with an unsafe default band was accepted")
    names = sample_resource_names("self-test-campaign", tiny[0])
    if set(names) != {"anchor", "capture", "runner"} or len(set(names.values())) != 3:
        raise AssertionError("frozen sample resource names are not exact and unique")
    unfinished_names = unfinished_resource_map(
        "self-test-campaign", tiny, {tiny[0].sample_id: {"complete": True}}
    )
    completed_names = set(sample_resource_names("self-test-campaign", tiny[0]).values())
    if completed_names & set(unfinished_names) or len(unfinished_names) != 6:
        raise AssertionError("stale cleanup resource map escaped unfinished samples")
    guard = SignalGuard()
    cleaned = False
    try:
        guard._handle(signal.SIGTERM, None)
    except CampaignInterrupted as error:
        if "SIGTERM" not in str(error):
            raise AssertionError("controlled signal error lost its signal identity") from error
    else:
        raise AssertionError("termination signal did not raise a controlled exception")
    finally:
        cleaned = True
    if not cleaned or guard.triggered != signal.SIGTERM:
        raise AssertionError("controlled signal path did not execute finally")
    with tempfile.TemporaryDirectory(prefix="stealth-campaign-output-test.") as directory:
        output = Path(directory) / "campaign"
        first_lock = acquire_output_lock(output)
        try:
            try:
                acquire_output_lock(output)
            except CampaignError:
                pass
            else:
                raise AssertionError("campaign output lock did not prevent a concurrent writer")
        finally:
            first_lock.close()
            output_lock_path(output).unlink(missing_ok=True)
        output.mkdir()
        (output / ".campaign.lock").write_text("", encoding="utf-8")
        if prepare_output(output, False) or any(output.iterdir()):
            raise AssertionError("stale legacy lock poisoned a safe non-resume retry")
        output.rmdir()
        created = prepare_output(output, False)
        initialization_paths = {
            "plan": output / "plan.json",
            "state": output / "state.json",
            "events": output / "events.jsonl",
        }
        try:
            initialize_new_output(
                output, initialization_paths, {"schema_version": 1},
                {"not_json": {1}}, created,
            )
        except TypeError:
            pass
        else:
            raise AssertionError("invalid initial state unexpectedly initialized output")
        if output.exists():
            raise AssertionError("failed initialization left a poisoned output directory")
        created = prepare_output(output, False)
        initialize_new_output(
            output, initialization_paths, {"schema_version": 1},
            {"schema_version": 1}, created,
        )
        (output / ".campaign.lock").write_text("", encoding="utf-8")
        if prepare_output(output, True) or (output / ".campaign.lock").exists():
            raise AssertionError("resume did not recover a stale legacy campaign lock")
        if not all(initialization_paths[key].is_file() for key in ("plan", "state", "events")):
            raise AssertionError("resume recovery removed meaningful campaign state")
    fake_events = {
        tiny[0].sample_id: {
            "manifest_row": {
                **{
                    "sample_id": tiny[0].sample_id, "product": tiny[0].product,
                    "scenario": tiny[0].scenario, "workload": tiny[0].workload,
                    "wire_profile": tiny[0].wire_profile, "run_id": tiny[0].run_id,
                    "seed": tiny[0].seed, "pcap": f"pcaps/{tiny[0].sample_id}.pcap",
                    "client_ip": "10.23.0.10", "server_ip": "10.23.0.2",
                },
                **{field: "fixture" for field in PROVENANCE_FIELDS},
            }
        }
    }
    manifest = render_manifest(tiny, fake_events).decode()
    header = manifest.splitlines()[0].split(",")
    if tuple(header) != MANIFEST_FIELDS or "client_implementation" not in header:
        raise AssertionError("per-sample provenance columns are missing")
    with tempfile.TemporaryDirectory(prefix="stealth-campaign-manifest-test.") as directory:
        manifest_path = Path(directory) / "capture-manifest.csv"
        header_bytes = (",".join(MANIFEST_FIELDS) + "\n").encode()
        manifest_size = reconcile_manifest(manifest_path, header_bytes)
        row = fake_events[tiny[0].sample_id]["manifest_row"]
        manifest_size = append_manifest_row(manifest_path, row, manifest_size)
        expected = render_manifest(tiny, fake_events)
        if manifest_size != len(expected) or manifest_path.read_bytes() != expected:
            raise AssertionError("append-only manifest differs from canonical rendering")
        manifest_path.write_bytes(expected[:-7])
        if reconcile_manifest(manifest_path, expected) != len(expected):
            raise AssertionError("manifest prefix recovery did not restore the ledger")
        if manifest_path.read_bytes() != expected:
            raise AssertionError("manifest prefix recovery produced different bytes")
        manifest_path.write_bytes(expected + b"tampered")
        try:
            reconcile_manifest(manifest_path, expected)
        except CampaignError:
            pass
        else:
            raise AssertionError("non-prefix manifest tampering was accepted")
    with tempfile.TemporaryDirectory(prefix="stealth-campaign-ledger-binding-test.") as directory:
        ledger_output = Path(directory)
        (ledger_output / "pcaps").mkdir()
        ledger_sample = next(sample for sample in tiny if sample.product == "autocar")
        ledger_variant = products["autocar"][ledger_sample.variant_index]
        capture = ledger_output / "pcaps" / f"{ledger_sample.sample_id}.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"ledger-fixture" * 3)
        runner_id = "sha256:" + "a" * 64
        server_id = "b" * 64
        engine_fingerprint = "c" * 64
        ledger_runtime = {
            "capture_host": registered_host,
            "engine_fingerprint": engine_fingerprint,
            "network_subnets": ["10.23.0.0/24"],
            "runner_images": {
                f"autocar/{ledger_variant.name}": {"id": runner_id},
            },
            "servers": {
                ledger_variant.server_container: {
                    "id": server_id, "ip": ledger_variant.server_ip,
                },
            },
        }
        ledger_config = {
            "products": products,
            "lab": {"minimum_packets": 5},
        }
        ledger_row = {
            "sample_id": ledger_sample.sample_id,
            "product": ledger_sample.product,
            "scenario": ledger_sample.scenario,
            "workload": ledger_sample.workload,
            "wire_profile": ledger_sample.wire_profile,
            "run_id": ledger_sample.run_id,
            "seed": ledger_sample.seed,
            "pcap": f"pcaps/{ledger_sample.sample_id}.pcap",
            "client_ip": "10.23.0.10",
            "server_ip": ledger_variant.server_ip,
            "client_implementation": ledger_variant.client_implementation,
            "server_implementation": ledger_variant.server_implementation,
            "implementation_version": ledger_variant.implementation_version,
            "runner_image_id": runner_id,
            "server_container_id": server_id,
            "capture_host": registered_host,
            "docker_engine_fingerprint": engine_fingerprint,
        }
        start_event = {
            "event": "sample_started", "at": "2026-09-04T00:00:00Z",
            "sample_id": ledger_sample.sample_id, "variant": ledger_variant.name,
        }
        complete_event = {
            "event": "sample_complete", "at": "2026-09-04T00:00:01Z",
            "sample_id": ledger_sample.sample_id, "variant": ledger_variant.name,
            "packets": 5, "pcap_sha256": file_sha256(capture),
            "pcap_bytes": capture.stat().st_size, "manifest_row": ledger_row,
        }
        ledger = ledger_output / "events.jsonl"

        def write_ledger_fixture(events: Sequence[Mapping[str, Any]]) -> None:
            ledger.write_text(
                "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
                encoding="utf-8",
            )

        write_ledger_fixture([start_event, complete_event])
        if set(load_ledger(
            ledger, [ledger_sample], ledger_output, ledger_runtime, ledger_config
        )) != {ledger_sample.sample_id}:
            raise AssertionError("single-attempt completion did not replay from the ledger")
        malformed_completions = []
        no_start = dict(complete_event)
        malformed_completions.append([no_start])
        failed_event = {
            "event": "sample_failed", "at": "2026-09-04T00:00:01Z",
            "sample_id": ledger_sample.sample_id, "reason": "self-test failure",
        }
        malformed_completions.append(
            [start_event, failed_event, start_event, complete_event]
        )
        malformed_completions.append([start_event, start_event, complete_event])
        malformed_completions.append([start_event])
        too_few_packets = json.loads(json.dumps(complete_event))
        too_few_packets["packets"] = 4
        malformed_completions.append([start_event, too_few_packets])
        wrong_runner = json.loads(json.dumps(complete_event))
        wrong_runner["manifest_row"]["runner_image_id"] = "sha256:" + "d" * 64
        malformed_completions.append([start_event, wrong_runner])
        extra_field = dict(complete_event, unbound=True)
        malformed_completions.append([start_event, extra_field])
        for malformed in malformed_completions:
            write_ledger_fixture(malformed)
            try:
                load_ledger(
                    ledger, [ledger_sample], ledger_output, ledger_runtime, ledger_config
                )
            except CampaignError:
                pass
            else:
                raise AssertionError("malformed or unbound ledger event was accepted")
    with tempfile.TemporaryDirectory(prefix="stealth-campaign-ledger-test.") as directory:
        ledger = Path(directory) / "events.jsonl"
        first = b'{"event":"sample_started","sample_id":"one"}'
        second = b'{"event":"sample_failed","sample_id":"two"}'
        ledger.write_bytes(first)
        events = read_ledger_events(ledger)
        if len(events) != 1 or ledger.read_bytes() != first + b"\n":
            raise AssertionError("valid final ledger record was not newline-committed")
        ledger.write_bytes(first + b"\n" + second[:-3])
        events = read_ledger_events(ledger)
        if len(events) != 1 or ledger.read_bytes() != first + b"\n":
            raise AssertionError("invalid final ledger tail was not truncated")
        ledger.write_bytes(first + b"\nnot-json\n" + second)
        try:
            read_ledger_events(ledger)
        except CampaignError as error:
            if "line 2" not in str(error):
                raise AssertionError("middle ledger corruption reported the wrong line") from error
        else:
            raise AssertionError("middle ledger corruption was recovered")
        if not ledger.read_bytes().endswith(b"\n") or b"not-json\n" not in ledger.read_bytes():
            raise AssertionError("middle ledger corruption was modified")
        original_write = os.write

        def short_write(descriptor: int, value: bytes) -> int:
            return original_write(descriptor, value[:3])

        os.write = short_write
        try:
            ledger.write_bytes(b"")
            append_event(ledger, {"event": "sample_started", "sample_id": "short"})
        finally:
            os.write = original_write
        parsed = read_ledger_events(ledger)
        if len(parsed) != 1 or parsed[0][1].get("sample_id") != "short":
            raise AssertionError("short event-ledger writes were not completed")


if __name__ == "__main__":
    sys.exit(main())
