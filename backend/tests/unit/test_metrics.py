"""T9.1: metric formulas on small hand-computed fixtures."""

import pytest

from app.experiments.metrics import (
    describe,
    detection_summary,
    false_positive_summary,
    proportion,
    storage_summary,
    summarize,
    timing_summary,
    wilson_interval,
)


def test_wilson_interval_known_values() -> None:
    # Hand-computed with z = 1.96:
    # 0/10 -> (0, 0.2775); 10/10 -> (0.7225, 1); 5/10 -> (0.2366, 0.7634)
    assert wilson_interval(0, 10) == pytest.approx((0.0, 0.2775), abs=1e-4)
    assert wilson_interval(10, 10) == pytest.approx((0.7225, 1.0), abs=1e-4)
    assert wilson_interval(5, 10) == pytest.approx((0.2366, 0.7634), abs=1e-4)
    assert wilson_interval(0, 0) is None


def test_proportion_with_no_data_is_none_not_zero() -> None:
    assert proportion(0, 0) == {"successes": 0, "n": 0, "rate": None, "ci95": None}
    assert proportion(3, 4)["rate"] == 0.75


def test_describe_quartiles_and_edge_cases() -> None:
    stats = describe([5, 1, 4, 2, 3])

    assert (stats["median"], stats["q1"], stats["q3"], stats["iqr"]) == (3, 2, 4, 2)
    assert (stats["min"], stats["max"], stats["n"]) == (1, 5, 5)
    assert describe([7])["median"] == 7 and describe([7])["iqr"] == 0
    assert describe([])["median"] is None


def _trial(
    scenario: str,
    detected: bool,
    expected: bool,
    true: int | None,
    first: int | None,
    size: int = 1000,
    error: str | None = None,
) -> dict:
    return {
        "size": size,
        "scenario": scenario,
        "detected": detected,
        "expected_detected": expected,
        "true_first_index": true,
        "first_failure_index": first,
        "verify_ms": 2.0,
        "error": error,
    }


def test_detection_rate_and_localization_accuracy() -> None:
    trials = [
        _trial("S1", True, True, 5, 5),
        _trial("S1", True, True, 9, 10),  # detected, wrong location
        _trial("S1", False, True, 3, None),  # missed
        _trial("S1", True, True, 4, 4),
        _trial("S1", None, None, None, None, error="stream too short"),  # type: ignore[arg-type]
        _trial("S10", False, False, None, None),
    ]

    s1, s10 = detection_summary(trials)

    assert (s1["detection"]["successes"], s1["detection"]["n"]) == (3, 4)  # error excluded
    assert s1["detection"]["rate"] == 0.75
    assert (s1["localization"]["successes"], s1["localization"]["n"]) == (2, 3)
    assert (s1["as_expected"], s1["errors"], s1["expected_detected"]) == (3, 1, True)
    assert s10["detection"]["rate"] == 0.0 and s10["localization"]["rate"] is None
    assert s10["as_expected"] == 1


def test_false_positive_rate() -> None:
    runs = [
        {"size": 1000, "status": "VALID", "findings": 0, "records": 1000},
        {"size": 1000, "status": "TAMPERING_DETECTED", "findings": 2, "records": 1000},
        {"size": 1000, "status": "VALID", "findings": 0, "records": 1000},
        {"size": 1000, "status": "VALID", "findings": 0, "records": 1000},
    ]

    (row,) = false_positive_summary(runs)

    assert row["false_positive"]["rate"] == 0.25
    assert (row["findings_on_untampered"], row["records_checked"]) == (2, 4000)


def test_timing_excludes_warmup_and_normalises() -> None:
    def rep(i: int, check: float, warmup: bool = False) -> dict:
        return {
            "size": 1000,
            "batch_size": 64,
            "repetition": i,
            "warmup": warmup,
            "records": 1000,
            "batches": 16,
            "status": "VALID",
            "load_ms": 10.0,
            "check_ms": check,
            "chain_ms": 1.0,
            "provenance_ms": 1.0,
            "merkle_ms": 3.2,
        }

    (row,) = timing_summary([rep(0, 999.0, warmup=True), rep(1, 20.0), rep(2, 30.0), rep(3, 40.0)])

    assert row["check_ms"]["median"] == 30.0 and row["check_ms"]["n"] == 3  # warm-up dropped
    assert row["total_ms"]["median"] == 40.0
    assert row["check_us_per_record"]["median"] == 30.0  # 30 ms * 1000 / 1000 records
    assert row["merkle_ms_per_batch"]["median"] == pytest.approx(0.2)
    assert row["all_valid"] is True


def test_storage_overhead_per_record() -> None:
    (row,) = storage_summary(
        [
            {
                "size": 1000,
                "records": 1000,
                "page_bytes": 8192,
                "full_tuple_bytes": 220_000,
                "baseline_tuple_bytes": 130_000,
                "full_used_pages": 30,
                "baseline_used_pages": 18,
                "batch_rows": 16,
                "batch_tuple_bytes": 2_000,
            }
        ]
    )

    assert row["tuple_overhead_bytes_per_record"] == 90.0
    assert row["page_overhead_bytes_per_record"] == pytest.approx(12 * 8192 / 1000)
    assert row["batch_bytes_per_record"] == 2.0


def test_summarize_handles_empty_raw_results() -> None:
    assert summarize({}) == {
        "detection": [],
        "false_positive": [],
        "timing": [],
        "proofs": [],
        "storage": [],
    }
