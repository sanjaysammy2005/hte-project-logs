"""Metric formulas (docs/EXPERIMENTS.md §4). Pure functions over raw trial records.

Nothing here estimates or rounds results toward a target: every value is computed from the
stored raw data, and groups with no data report None.
"""

import math
import statistics
from collections import defaultdict
from collections.abc import Iterable
from typing import Any


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for a binomial proportion (None when n = 0)."""
    if n == 0:
        return None
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def proportion(successes: int, n: int) -> dict[str, Any]:
    interval = wilson_interval(successes, n)
    return {
        "successes": successes,
        "n": n,
        "rate": successes / n if n else None,
        "ci95": list(interval) if interval else None,
    }


def describe(values: Iterable[float]) -> dict[str, Any]:
    """Median, quartiles (inclusive method), IQR, min and max."""
    data = sorted(values)
    if not data:
        return {
            "n": 0,
            "median": None,
            "q1": None,
            "q3": None,
            "iqr": None,
            "min": None,
            "max": None,
        }
    if len(data) == 1:
        q1 = q3 = data[0]
    else:
        q1, _, q3 = statistics.quantiles(data, n=4, method="inclusive")
    return {
        "n": len(data),
        "median": statistics.median(data),
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1,
        "min": data[0],
        "max": data[-1],
    }


def _group(rows: Iterable[dict[str, Any]], *keys: str) -> dict[tuple, list[dict[str, Any]]]:
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[k] for k in keys)].append(row)
    return dict(sorted(groups.items(), key=lambda item: tuple(str(v).zfill(12) for v in item[0])))


def detection_summary(trials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """DR(T) = detected / trials; LA(T) = located at ground truth / detected-with-ground-truth."""
    out = []
    for (size, scenario), rows in _group(trials, "size", "scenario").items():
        valid = [r for r in rows if r.get("error") is None]
        detected = [r for r in valid if r["detected"]]
        locatable = [r for r in detected if r["true_first_index"] is not None]
        located = [r for r in locatable if r["first_failure_index"] == r["true_first_index"]]
        expected = {r["expected_detected"] for r in valid}
        out.append(
            {
                "size": size,
                "scenario": scenario,
                "expected_detected": expected.pop() if len(expected) == 1 else None,
                "detection": proportion(len(detected), len(valid)),
                "localization": proportion(len(located), len(locatable)),
                "as_expected": sum(r["detected"] == r["expected_detected"] for r in valid),
                "errors": len(rows) - len(valid),
                "verify_ms": describe(r["verify_ms"] for r in valid),
            }
        )
    return out


def false_positive_summary(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """FPR = runs on untampered streams reporting TAMPERING_DETECTED / untampered runs."""
    out = []
    for (size,), rows in _group(runs, "size").items():
        flagged = [r for r in rows if r["status"] != "VALID"]
        out.append(
            {
                "size": size,
                "false_positive": proportion(len(flagged), len(rows)),
                "findings_on_untampered": sum(r["findings"] for r in rows),
                "records_checked": sum(r["records"] for r in rows),
            }
        )
    return out


def timing_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Verification time per (size, batch size), excluding warm-up repetitions."""
    out = []
    for (size, batch_size), group in _group(rows, "size", "batch_size").items():
        measured = [r for r in group if not r["warmup"]]
        out.append(
            {
                "size": size,
                "batch_size": batch_size,
                "records": group[0]["records"],
                "batches": group[0]["batches"],
                "all_valid": all(r["status"] == "VALID" for r in measured),
                "total_ms": describe(r["load_ms"] + r["check_ms"] for r in measured),
                "load_ms": describe(r["load_ms"] for r in measured),
                "check_ms": describe(r["check_ms"] for r in measured),
                "chain_ms": describe(r["chain_ms"] for r in measured),
                "provenance_ms": describe(r["provenance_ms"] for r in measured),
                "merkle_ms": describe(r["merkle_ms"] for r in measured),
                "check_us_per_record": describe(
                    r["check_ms"] * 1000 / r["records"] for r in measured if r["records"]
                ),
                "merkle_ms_per_batch": describe(
                    r["merkle_ms"] / r["batches"] for r in measured if r["batches"]
                ),
            }
        )
    return out


def proof_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "batch_size": r["batch_size"],
            "proof_length": r["proof_length"],
            "generate_us": describe(r["generate_us"]),
            "verify_us": describe(r["verify_us"]),
        }
        for r in sorted(rows, key=lambda r: r["batch_size"])
    ]


def storage_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-record overhead of the added context/hash columns and of the batch table.

    tuple overhead/record = (tuple bytes(full) - tuple bytes(baseline)) / N
    page overhead/record  = (used pages(full) - used pages(baseline)) x page size / N
    batch bytes/record    = tuple bytes(batches) / N
    """
    return [
        {
            "size": r["size"],
            "records": r["records"],
            "tuple_overhead_bytes_per_record": (r["full_tuple_bytes"] - r["baseline_tuple_bytes"])
            / r["records"],
            "page_overhead_bytes_per_record": (
                (r["full_used_pages"] - r["baseline_used_pages"]) * r["page_bytes"] / r["records"]
            ),
            "batch_bytes_per_record": r["batch_tuple_bytes"] / r["records"],
            "full_used_pages": r["full_used_pages"],
            "baseline_used_pages": r["baseline_used_pages"],
            "batch_rows": r["batch_rows"],
        }
        for r in sorted(rows, key=lambda r: r["size"])
        if r["records"]
    ]


def summarize(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "detection": detection_summary(raw.get("detection", [])),
        "false_positive": false_positive_summary(raw.get("false_positive", [])),
        "timing": timing_summary(raw.get("timing", [])),
        "proofs": proof_summary(raw.get("proofs", [])),
        "storage": storage_summary(raw.get("storage", [])),
    }
