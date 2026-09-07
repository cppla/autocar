#!/usr/bin/env python3
"""Run pre-registered, group-held-out traffic distinguishability models.

Lower ROC-AUC and lower TPR at 1% FPR are better for the candidate transport.
The release decision is driven by a checked-in preregistration file; missing
cells, captures, runs, or products are ``insufficient_evidence`` rather than a
pass. Only observer-visible numeric features are accepted.
"""

from __future__ import annotations

import argparse

import csv
import hashlib
import json
import math
import os
import random
import statistics
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence


SCHEMA_VERSION = 1
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


class InsufficientEvidence(RuntimeError):
    pass


@dataclass(frozen=True)
class Sample:
    sample_id: str
    product: str
    cell: tuple[str, str, str]
    group: str
    values: tuple[float, ...]


@dataclass(frozen=True)
class Prediction:
    sample_id: str
    cell: tuple[str, str, str]
    group: str
    label: int
    score: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", help="address-free feature CSV")
    parser.add_argument(
        "--preregistration",
        default="testdata/stealth/preregistration.json",
        help="checked-in release-gate contract",
    )
    parser.add_argument("--output", help="JSON score report")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print(json.dumps({"status": "pass", "self_test": True}, sort_keys=True))
        return 0
    if not args.features or not args.output:
        print("--features and --output are required", file=sys.stderr)
        return 2
    output = Path(args.output)
    try:
        report = classify(Path(args.features), Path(args.preregistration))
    except InsufficientEvidence as error:
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "insufficient_evidence",
            "reason": str(error),
        }
        write_json_atomic(output, report)
        print(json.dumps(report, sort_keys=True))
        return 2
    except Exception as error:
        report = {"schema_version": SCHEMA_VERSION, "status": "fail", "reason": str(error)}
        write_json_atomic(output, report)
        print(json.dumps(report, sort_keys=True))
        return 1
    write_json_atomic(output, report)
    print(json.dumps({key: report[key] for key in ("status", "decision", "reason")}, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


def classify(features_path: Path, preregistration_path: Path) -> dict:
    if not features_path.is_file() or features_path.stat().st_size == 0:
        raise InsufficientEvidence(f"feature table not found or empty: {features_path}")
    if not preregistration_path.is_file():
        raise InsufficientEvidence(f"preregistration not found: {preregistration_path}")
    prereg = json.loads(preregistration_path.read_text(encoding="utf-8"))
    validate_preregistration(prereg)
    samples, feature_names = load_samples(features_path)
    required_cells = [cell_key(item) for item in prereg["required_common_cells"]]
    if len(required_cells) != len(set(required_cells)):
        raise InsufficientEvidence("required_common_cells contains duplicate cells")
    validate_coverage(samples, required_cells, prereg)

    model_names = prereg["models"]
    predictions: dict[str, dict[str, dict[tuple[str, str, str], list[Prediction]]]] = {}
    cell_reports: list[dict] = []
    for model_name in model_names:
        predictions[model_name] = {}
        for product in ("autocar", "hysteria2"):
            predictions[model_name][product] = {}
            for cell in required_cells:
                cell_samples = [sample for sample in samples if sample.cell == cell and sample.product in {"cover", product}]
                predicted = grouped_cross_validation(cell_samples, product, model_name)
                predictions[model_name][product][cell] = predicted
                overall = binary_metrics(predicted)
                group_metrics = {
                    group: binary_metrics([item for item in predicted if item.group == group])
                    for group in sorted({item.group for item in predicted})
                }
                cell_reports.append(
                    {
                        "model": model_name,
                        "product": product,
                        "scenario": cell[0],
                        "workload": cell[1],
                        "wire_profile": cell[2],
                        "samples": len(predicted),
                        "groups": len(group_metrics),
                        **overall,
                        "per_group": group_metrics,
                    }
                )

    comparisons: list[dict] = []
    model_gates: dict[str, dict] = {}
    gates = prereg["gates"]
    bootstrap_iterations = prereg["bootstrap_iterations"]
    bootstrap_seed = prereg["bootstrap_seed"]
    for model_index, model_name in enumerate(model_names):
        pair_differences: list[float] = []
        pair_differences_by_group: dict[str, list[float]] = {}
        healthy_regressions: list[float] = []
        cell_regressions: list[float] = []
        for cell in required_cells:
            auto_predictions = predictions[model_name]["autocar"][cell]
            hy_predictions = predictions[model_name]["hysteria2"][cell]
            auto_metric = binary_metrics(auto_predictions)
            hy_metric = binary_metrics(hy_predictions)
            difference = auto_metric["tpr_at_fpr_1pct"] - hy_metric["tpr_at_fpr_1pct"]
            cell_regressions.append(difference)
            if cell[0] == prereg["healthy_h3_scenario"] and cell[2] == "h3":
                healthy_regressions.append(difference)

            auto_by_group = group_predictions(auto_predictions)
            hy_by_group = group_predictions(hy_predictions)
            common_groups = sorted(set(auto_by_group).intersection(hy_by_group))
            group_differences = []
            for group in common_groups:
                auto_group = binary_metrics(auto_by_group[group])
                hy_group = binary_metrics(hy_by_group[group])
                group_difference = auto_group["tpr_at_fpr_1pct"] - hy_group["tpr_at_fpr_1pct"]
                group_differences.append(group_difference)
                pair_differences.append(group_difference)
                pair_differences_by_group.setdefault(group, []).append(group_difference)
            comparisons.append(
                {
                    "model": model_name,
                    "scenario": cell[0],
                    "workload": cell[1],
                    "wire_profile": cell[2],
                    "autocar": auto_metric,
                    "hysteria2": hy_metric,
                    "autocar_minus_hysteria2_tpr": difference,
                    "paired_groups": len(group_differences),
                    "paired_group_mean_difference": statistics.fmean(group_differences),
                }
            )

        if not healthy_regressions:
            raise InsufficientEvidence(f"model {model_name} has no pre-registered healthy H3 cells")
        block_differences = [statistics.fmean(values) for _, values in sorted(pair_differences_by_group.items())]
        if len(block_differences) < prereg["minimum_paired_groups"]:
            raise InsufficientEvidence(
                f"model {model_name} has {len(block_differences)} independent paired run/seed groups; need {prereg['minimum_paired_groups']}"
            )
        ci_low, ci_high = bootstrap_mean_ci(
            block_differences, bootstrap_iterations, bootstrap_seed + model_index
        )
        aggregate_difference = statistics.fmean(block_differences)
        healthy_ok = max(healthy_regressions) <= gates["healthy_h3_max_tpr_regression"]
        per_cell_ok = max(cell_regressions) <= gates["any_cell_max_tpr_regression"]
        margin_ok = aggregate_difference <= -gates["aggregate_min_tpr_improvement"]
        ci_ok = ci_high < 0.0
        model_gates[model_name] = {
            "healthy_h3_no_regression": healthy_ok,
            "no_hidden_cell_regression": per_cell_ok,
            "aggregate_superiority_margin": margin_ok,
            "paired_ci_below_zero": ci_ok,
            "aggregate_autocar_minus_hysteria2_tpr": aggregate_difference,
            "paired_bootstrap_95pct": [ci_low, ci_high],
            "paired_cell_groups": len(pair_differences),
            "bootstrap_run_seed_groups": len(block_differences),
            "passed": healthy_ok and per_cell_ok and margin_ok and ci_ok,
        }

    regressions = any(
        not value["healthy_h3_no_regression"] or not value["no_hidden_cell_regression"]
        for value in model_gates.values()
    )
    all_passed = all(value["passed"] for value in model_gates.values())
    if all_passed:
        status = "pass"
        decision = "superior_in_preregistered_scope"
        reason = "every pre-registered model and statistical gate passed"
    elif regressions:
        status = "fail"
        decision = "regression"
        reason = "at least one model exceeded a pre-registered non-regression bound"
    else:
        status = "tie"
        decision = "superiority_not_proven"
        reason = "evidence was complete but the superiority margin or confidence bound was not met"

    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "decision": decision,
        "reason": reason,
        "lower_is_better": True,
        "feature_table_sha256": file_sha256(features_path),
        "preregistration_sha256": file_sha256(preregistration_path),
        "feature_count": len(feature_names),
        "sample_count": len(samples),
        "models": model_gates,
        "cells": cell_reports,
        "comparisons": comparisons,
        "leakage_controls": {
            "split_unit": "run_id+seed",
            "addresses_or_ports_as_features": False,
            "sample_id_as_feature": False,
            "capture_path_as_feature": False,
            "decrypted_fields": False,
        },
    }


def validate_preregistration(prereg: dict) -> None:
    required = {
        "schema_version",
        "baseline",
        "models",
        "minimum_samples_per_product_cell",
        "minimum_groups_per_product_cell",
        "minimum_samples_per_product_cell_group",
        "minimum_paired_groups",
        "bootstrap_iterations",
        "bootstrap_seed",
        "healthy_h3_scenario",
        "required_common_cells",
        "gates",
        "sample_attempt_policy",
    }
    missing = required.difference(prereg)
    if missing:
        raise InsufficientEvidence("preregistration keys missing: " + ", ".join(sorted(missing)))
    if prereg["schema_version"] != SCHEMA_VERSION:
        raise InsufficientEvidence("unsupported preregistration schema version")
    if (
        prereg["baseline"].get("hysteria2_version") != "v2.12.2"
        or prereg["baseline"].get("disable_update_check") is not True
        or prereg["baseline"].get("local_http_proxy_connection_header")
        != "Proxy-Connection: keep-alive"
    ):
        raise InsufficientEvidence("release gate must remain pinned to Hysteria v2.12.2")
    if prereg["sample_attempt_policy"] != {
        "maximum_attempts_per_sample": 1,
        "retry_failed_or_interrupted_sample": False,
        "checkpoint_boundary": "after_sample_complete",
    }:
        raise InsufficientEvidence("release gate requires first-attempt-only evidence")
    if prereg["models"] != ["single_feature_rule", "logistic_l2", "tree_depth_3"]:
        raise InsufficientEvidence("the three pre-registered model families may not be changed post-capture")
    for key in (
        "minimum_samples_per_product_cell",
        "minimum_groups_per_product_cell",
        "minimum_paired_groups",
        "bootstrap_iterations",
    ):
        if not isinstance(prereg[key], int) or prereg[key] <= 0:
            raise InsufficientEvidence(f"invalid preregistration value {key}")
    if prereg["bootstrap_iterations"] < 10000:
        raise InsufficientEvidence("bootstrap_iterations must be at least 10000")
    if prereg["minimum_samples_per_product_cell_group"] < 100:
        raise InsufficientEvidence("1% FPR requires at least 100 negatives in every held-out group")
    implied_minimum = (
        prereg["minimum_groups_per_product_cell"] * prereg["minimum_samples_per_product_cell_group"]
    )
    if prereg["minimum_samples_per_product_cell"] < implied_minimum:
        raise InsufficientEvidence(
            "minimum_samples_per_product_cell is smaller than the per-group held-out requirement"
        )
    gates = prereg["gates"]
    for key in (
        "healthy_h3_max_tpr_regression",
        "any_cell_max_tpr_regression",
        "aggregate_min_tpr_improvement",
    ):
        if key not in gates or not 0 <= gates[key] <= 1:
            raise InsufficientEvidence(f"invalid or missing gate {key}")
    if not prereg["required_common_cells"]:
        raise InsufficientEvidence("no required common cells were pre-registered")


def load_samples(path: Path) -> tuple[list[Sample], list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames or []
        if len(header) != len(set(header)):
            raise InsufficientEvidence("feature table contains duplicate column names")
        missing = META_COLUMNS.difference(header)
        if missing:
            raise InsufficientEvidence("feature metadata columns missing: " + ", ".join(sorted(missing)))
        forbidden_tokens = {
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
        forbidden = {
            name
            for name in header
            if name not in META_COLUMNS and forbidden_tokens.intersection(name.lower().replace("-", "_").split("_"))
        }
        if forbidden:
            raise InsufficientEvidence("forbidden observer-feature columns present: " + ", ".join(sorted(forbidden)))
        feature_names = [name for name in header if name not in META_COLUMNS]
        if not feature_names:
            raise InsufficientEvidence("feature table has no numeric features")
        rows = list(reader)
    if not rows:
        raise InsufficientEvidence("feature table has no samples")
    samples: list[Sample] = []
    identifiers: set[str] = set()
    for line, row in enumerate(rows, start=2):
        if row["schema_version"] != str(SCHEMA_VERSION):
            raise InsufficientEvidence(f"row {line} has unsupported feature schema")
        identifier = row["sample_id"].strip()
        if not identifier or identifier in identifiers:
            raise InsufficientEvidence(f"row {line} has empty or duplicate sample_id")
        identifiers.add(identifier)
        product = row["product"].strip().lower()
        if product not in {"cover", "autocar", "hysteria2"}:
            raise InsufficientEvidence(f"row {line} has unsupported product")
        cell = (row["scenario"].strip(), row["workload"].strip(), row["wire_profile"].strip())
        if not all(cell):
            raise InsufficientEvidence(f"row {line} has incomplete cell metadata")
        run_id = row["run_id"].strip()
        seed = row["seed"].strip()
        if not run_id or not seed:
            raise InsufficientEvidence(f"row {line} has incomplete split metadata")
        values: list[float] = []
        for name in feature_names:
            try:
                value = float(row[name])
            except (TypeError, ValueError):
                raise InsufficientEvidence(f"row {line} feature {name} is not numeric") from None
            if not math.isfinite(value):
                raise InsufficientEvidence(f"row {line} feature {name} is not finite")
            values.append(value)
        samples.append(Sample(identifier, product, cell, run_id + "\x1f" + seed, tuple(values)))
    return samples, feature_names


def cell_key(item: dict) -> tuple[str, str, str]:
    try:
        cell = (item["scenario"], item["workload"], item["wire_profile"])
    except KeyError as error:
        raise InsufficientEvidence(f"required cell missing field {error}") from None
    if not all(isinstance(value, str) and value for value in cell):
        raise InsufficientEvidence("required cell values must be non-empty strings")
    return cell


def validate_coverage(samples: Sequence[Sample], cells: Sequence[tuple[str, str, str]], prereg: dict) -> None:
    minimum_samples = prereg["minimum_samples_per_product_cell"]
    minimum_groups = prereg["minimum_groups_per_product_cell"]
    minimum_group_samples = prereg["minimum_samples_per_product_cell_group"]
    required_pairs = {(cell, product) for cell in cells for product in ("cover", "autocar", "hysteria2")}
    pairs_by_group: dict[str, set[tuple[tuple[str, str, str], str]]] = {}
    for sample in samples:
        if sample.cell in cells:
            pairs_by_group.setdefault(sample.group, set()).add((sample.cell, sample.product))
    for cell in cells:
        for product in ("cover", "autocar", "hysteria2"):
            selected = [sample for sample in samples if sample.cell == cell and sample.product == product]
            if len(selected) < minimum_samples:
                raise InsufficientEvidence(
                    f"cell {cell} product {product} has {len(selected)} samples; need {minimum_samples}"
                )
            groups = {sample.group for sample in selected}
            if len(groups) < minimum_groups:
                raise InsufficientEvidence(
                    f"cell {cell} product {product} has {len(groups)} run/seed groups; need {minimum_groups}"
                )
        products_by_group: dict[str, set[str]] = {}
        for sample in samples:
            if sample.cell == cell:
                products_by_group.setdefault(sample.group, set()).add(sample.product)
        complete_groups = [group for group, products in products_by_group.items() if products == {"cover", "autocar", "hysteria2"}]
        if len(complete_groups) < minimum_groups:
            raise InsufficientEvidence(
                f"cell {cell} has {len(complete_groups)} complete paired run/seed groups; need {minimum_groups}"
            )
        for group in complete_groups:
            counts = {
                product: sum(
                    sample.cell == cell and sample.group == group and sample.product == product
                    for sample in samples
                )
                for product in ("cover", "autocar", "hysteria2")
            }
            if min(counts.values()) < minimum_group_samples:
                raise InsufficientEvidence(
                    f"cell {cell} group {group!r} has per-product samples {counts}; "
                    f"need at least {minimum_group_samples} each for 1% FPR"
                )
            if len(set(counts.values())) != 1:
                raise InsufficientEvidence(
                    f"cell {cell} group {group!r} is not balanced across products: {counts}"
                )
    complete_campaign_groups = [group for group, pairs in pairs_by_group.items() if required_pairs.issubset(pairs)]
    if len(complete_campaign_groups) < prereg["minimum_paired_groups"]:
        raise InsufficientEvidence(
            "campaign has "
            f"{len(complete_campaign_groups)} run/seed groups complete across every product and cell; "
            f"need {prereg['minimum_paired_groups']}"
        )
    incomplete_campaign_groups = sorted(set(pairs_by_group).difference(complete_campaign_groups))
    if incomplete_campaign_groups:
        preview = ", ".join(repr(group) for group in incomplete_campaign_groups[:3])
        raise InsufficientEvidence(
            f"run/seed groups are incomplete across the frozen cell matrix: {preview}"
        )


def grouped_cross_validation(samples: Sequence[Sample], positive_product: str, model_name: str) -> list[Prediction]:
    groups = sorted({sample.group for sample in samples})
    predictions: list[Prediction] = []
    for group in groups:
        train = [sample for sample in samples if sample.group != group]
        test = [sample for sample in samples if sample.group == group]
        if not train or not test:
            continue
        train_labels = [int(sample.product == positive_product) for sample in train]
        test_labels = [int(sample.product == positive_product) for sample in test]
        if set(train_labels) != {0, 1} or set(test_labels) != {0, 1}:
            raise InsufficientEvidence(
                f"group {group!r} lacks both cover and {positive_product} samples in train or test"
            )
        train_x, test_x = standardize([sample.values for sample in train], [sample.values for sample in test])
        predictor = fit_model(model_name, train_x, train_labels)
        for sample, values, label in zip(test, test_x, test_labels):
            score = predictor(values)
            if not math.isfinite(score):
                raise InsufficientEvidence(f"model {model_name} produced a non-finite score")
            predictions.append(Prediction(sample.sample_id, sample.cell, sample.group, label, score))
    if len(predictions) != len(samples):
        raise InsufficientEvidence("group-held-out prediction did not cover every sample")
    return predictions


def standardize(
    train: Sequence[Sequence[float]], test: Sequence[Sequence[float]]
) -> tuple[list[list[float]], list[list[float]]]:
    columns = list(zip(*train))
    means = [statistics.fmean(column) for column in columns]
    scales = [statistics.pstdev(column) or 1.0 for column in columns]

    def transform(rows: Sequence[Sequence[float]]) -> list[list[float]]:
        return [[(value - mean) / scale for value, mean, scale in zip(row, means, scales)] for row in rows]

    return transform(train), transform(test)


def fit_model(name: str, values: Sequence[Sequence[float]], labels: Sequence[int]) -> Callable[[Sequence[float]], float]:
    if name == "single_feature_rule":
        return fit_single_feature(values, labels)
    if name == "logistic_l2":
        return fit_logistic(values, labels)
    if name == "tree_depth_3":
        tree = build_tree(values, labels, depth=0, max_depth=3)
        return lambda row: predict_tree(tree, row)
    raise InsufficientEvidence(f"unsupported model {name}")


def fit_single_feature(values: Sequence[Sequence[float]], labels: Sequence[int]) -> Callable[[Sequence[float]], float]:
    best_auc = -1.0
    best_feature = 0
    best_direction = 1.0
    width = len(values[0])
    for feature in range(width):
        raw = [row[feature] for row in values]
        for direction in (1.0, -1.0):
            predictions = [Prediction(str(index), ("", "", ""), "", label, direction * value) for index, (value, label) in enumerate(zip(raw, labels))]
            auc = roc_auc(predictions)
            if auc > best_auc:
                best_auc, best_feature, best_direction = auc, feature, direction
    return lambda row: best_direction * row[best_feature]


def fit_logistic(values: Sequence[Sequence[float]], labels: Sequence[int]) -> Callable[[Sequence[float]], float]:
    width = len(values[0])
    weights = [0.0] * width
    prevalence = min(0.999, max(0.001, statistics.fmean(labels)))
    intercept = math.log(prevalence / (1.0 - prevalence))
    count = len(values)
    regularization = 0.02
    for iteration in range(800):
        gradient = [0.0] * width
        intercept_gradient = 0.0
        for row, label in zip(values, labels):
            linear = intercept + sum(weight * value for weight, value in zip(weights, row))
            probability = sigmoid(linear)
            residual = probability - label
            intercept_gradient += residual
            for index, value in enumerate(row):
                gradient[index] += residual * value
        rate = 0.15 / math.sqrt(1.0 + iteration / 40.0)
        intercept -= rate * intercept_gradient / count
        for index in range(width):
            weights[index] -= rate * (gradient[index] / count + regularization * weights[index])
    return lambda row: sigmoid(intercept + sum(weight * value for weight, value in zip(weights, row)))


@dataclass
class TreeNode:
    probability: float
    feature: int | None = None
    threshold: float = 0.0
    left: "TreeNode | None" = None
    right: "TreeNode | None" = None


def build_tree(
    values: Sequence[Sequence[float]], labels: Sequence[int], depth: int, max_depth: int
) -> TreeNode:
    probability = statistics.fmean(labels)
    node = TreeNode(probability)
    if depth >= max_depth or len(values) < 10 or probability in {0.0, 1.0}:
        return node
    best_gain = 0.0
    best: tuple[int, float, list[int], list[int]] | None = None
    parent_impurity = gini(labels)
    for feature in range(len(values[0])):
        unique = sorted({row[feature] for row in values})
        if len(unique) > 24:
            thresholds = [percentile(unique, index / 24.0) for index in range(1, 24)]
        else:
            thresholds = [(left + right) / 2.0 for left, right in zip(unique, unique[1:])]
        for threshold in thresholds:
            left = [index for index, row in enumerate(values) if row[feature] <= threshold]
            right = [index for index, row in enumerate(values) if row[feature] > threshold]
            if len(left) < 3 or len(right) < 3:
                continue
            impurity = (len(left) * gini([labels[index] for index in left]) + len(right) * gini([labels[index] for index in right])) / len(values)
            gain = parent_impurity - impurity
            if gain > best_gain + 1e-12:
                best_gain = gain
                best = (feature, threshold, left, right)
    if best is None:
        return node
    feature, threshold, left_indices, right_indices = best
    node.feature = feature
    node.threshold = threshold
    node.left = build_tree(
        [values[index] for index in left_indices], [labels[index] for index in left_indices], depth + 1, max_depth
    )
    node.right = build_tree(
        [values[index] for index in right_indices], [labels[index] for index in right_indices], depth + 1, max_depth
    )
    return node


def predict_tree(node: TreeNode, row: Sequence[float]) -> float:
    while node.feature is not None:
        next_node = node.left if row[node.feature] <= node.threshold else node.right
        if next_node is None:
            break
        node = next_node
    return node.probability


def gini(labels: Sequence[int]) -> float:
    probability = statistics.fmean(labels)
    return 2.0 * probability * (1.0 - probability)


def sigmoid(value: float) -> float:
    if value >= 0:
        exponential = math.exp(-min(value, 700.0))
        return 1.0 / (1.0 + exponential)
    exponential = math.exp(max(value, -700.0))
    return exponential / (1.0 + exponential)


def binary_metrics(predictions: Sequence[Prediction]) -> dict[str, float]:
    labels = {item.label for item in predictions}
    if labels != {0, 1}:
        raise InsufficientEvidence("metric set lacks both positive and negative samples")
    return {
        "roc_auc": roc_auc(predictions),
        "tpr_at_fpr_1pct": tpr_at_fpr(predictions, 0.01),
    }


def roc_auc(predictions: Sequence[Prediction]) -> float:
    positives = [item.score for item in predictions if item.label == 1]
    negatives = [item.score for item in predictions if item.label == 0]
    if not positives or not negatives:
        raise InsufficientEvidence("ROC-AUC needs both classes")
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            if positive > negative:
                wins += 1.0
            elif positive == negative:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def tpr_at_fpr(predictions: Sequence[Prediction], maximum_fpr: float) -> float:
    positives = [item.score for item in predictions if item.label == 1]
    negatives = sorted((item.score for item in predictions if item.label == 0), reverse=True)
    if not positives or not negatives:
        raise InsufficientEvidence("TPR needs both classes")
    required_negatives = math.ceil(1.0 / maximum_fpr)
    if len(negatives) < required_negatives:
        raise InsufficientEvidence(
            f"TPR at {maximum_fpr:.2%} FPR needs at least {required_negatives} negative samples; "
            f"got {len(negatives)}"
        )
    allowed_false_positives = math.floor(maximum_fpr * len(negatives) + 1e-12)
    if allowed_false_positives == 0:
        threshold = negatives[0]
        return sum(score > threshold for score in positives) / len(positives)
    threshold = negatives[min(allowed_false_positives - 1, len(negatives) - 1)]
    false_positives = sum(score >= threshold for score in negatives)
    if false_positives / len(negatives) > maximum_fpr + 1e-12:
        # A tied score block cannot be partially accepted without a randomized
        # detector. Move above it to preserve the declared FPR bound.
        return sum(score > threshold for score in positives) / len(positives)
    return sum(score >= threshold for score in positives) / len(positives)


def group_predictions(predictions: Sequence[Prediction]) -> dict[str, list[Prediction]]:
    result: dict[str, list[Prediction]] = {}
    for prediction in predictions:
        result.setdefault(prediction.group, []).append(prediction)
    return result


def bootstrap_mean_ci(values: Sequence[float], iterations: int, seed: int) -> tuple[float, float]:
    if not values:
        raise InsufficientEvidence("bootstrap needs paired differences")
    generator = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        estimates.append(statistics.fmean(generator.choice(values) for _ in values))
    estimates.sort()
    return percentile(estimates, 0.025), percentile(estimates, 0.975)


def percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower]) * (1.0 - weight) + float(ordered[upper]) * weight


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
    cell = ("healthy_h3", "download_1k", "h3")
    predictions = [Prediction(f"n{index}", cell, "g1", 0, index / 1000.0) for index in range(100)]
    predictions += [Prediction(f"p{index}", cell, "g1", 1, 0.8 + index / 1000.0) for index in range(100)]
    metrics = binary_metrics(predictions)
    assert metrics["roc_auc"] == 1.0
    assert metrics["tpr_at_fpr_1pct"] == 1.0
    inverse = [Prediction(item.sample_id, item.cell, item.group, item.label, -item.score) for item in predictions]
    assert roc_auc(inverse) == 0.0
    low, high = bootstrap_mean_ci([-0.1, -0.2, -0.3], 10000, 7)
    assert low < high < 0
    values = [[-2.0], [-1.0], [1.0], [2.0]]
    labels = [0, 0, 1, 1]
    for name in ("single_feature_rule", "logistic_l2", "tree_depth_3"):
        predictor = fit_model(name, values * 3, labels * 3)
        assert predictor([2.0]) >= predictor([-2.0])

    preregistration = {
        "schema_version": SCHEMA_VERSION,
        "baseline": {
            "hysteria2_version": "v2.12.2",
            "disable_update_check": True,
            "local_http_proxy_connection_header": "Proxy-Connection: keep-alive",
        },
        "models": ["single_feature_rule", "logistic_l2", "tree_depth_3"],
        "minimum_samples_per_product_cell": 500,
        "minimum_groups_per_product_cell": 5,
        "minimum_samples_per_product_cell_group": 100,
        "minimum_paired_groups": 5,
        "bootstrap_iterations": 10000,
        "bootstrap_seed": 7,
        "healthy_h3_scenario": "healthy_h3",
        "sample_attempt_policy": {
            "maximum_attempts_per_sample": 1,
            "retry_failed_or_interrupted_sample": False,
            "checkpoint_boundary": "after_sample_complete",
        },
        "required_common_cells": [
            {"scenario": "healthy_h3", "workload": "download_1k", "wire_profile": "h3"}
        ],
        "gates": {
            "healthy_h3_max_tpr_regression": 0.02,
            "any_cell_max_tpr_regression": 0.02,
            "aggregate_min_tpr_improvement": 0.05,
        },
    }
    with tempfile.TemporaryDirectory(prefix="autocar-stealth-classifier-test.") as temporary:
        root = Path(temporary)
        preregistration_path = root / "preregistration.json"
        features_path = root / "features.csv"
        preregistration_path.write_text(json.dumps(preregistration), encoding="utf-8")
        with features_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(META_COLUMNS) + ["observer_feature"])
            writer.writeheader()
            for group in range(5):
                for sample_index in range(100):
                    ordinary_value = float(group * 100 + sample_index) / 1000.0
                    for product, value in (
                        ("cover", ordinary_value),
                        ("autocar", ordinary_value),
                        ("hysteria2", ordinary_value + 100.0),
                    ):
                        writer.writerow(
                            {
                                "schema_version": SCHEMA_VERSION,
                                "sample_id": f"{product}-{group}-{sample_index}",
                                "product": product,
                                "scenario": "healthy_h3",
                                "workload": "download_1k",
                                "wire_profile": "h3",
                                "run_id": f"run-{group}",
                                "seed": f"seed-{group}",
                                "observer_feature": value,
                            }
                        )
        report = classify(features_path, preregistration_path)
        assert report["status"] == "pass"
        for gate in report["models"].values():
            assert gate["bootstrap_run_seed_groups"] == 5
            assert gate["paired_cell_groups"] == 5


if __name__ == "__main__":
    raise SystemExit(main())
