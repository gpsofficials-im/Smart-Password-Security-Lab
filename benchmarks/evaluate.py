"""Benchmark and Quality Evaluation Suite for Smart Password Security Lab.

Measures:
- Precision, Recall, False-Positive Rate (FPR), and False-Negative Rate (FNR)
  across synthetic pattern cases.
- Verification against the target thresholds:
    * >= 90% recall on synthetic pattern fixtures
    * <= 5% false positive rate on benign high-entropy fixtures
    * 100% pass rate on golden vector regression fixtures
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

# Ensure workspace is on sys.path
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

import password_analyzer as core


def run_benchmark_evaluation() -> bool:
    synthetic_path = os.path.join(WORKSPACE_DIR, "benchmarks", "synthetic_cases.json")
    with open(synthetic_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    print("=" * 70)
    print("      SMART PASSWORD SECURITY LAB — BENCHMARK EVALUATION")
    print("=" * 70)

    # Metrics aggregation
    rule_stats: dict[str, dict[str, int]] = {
        "PATTERN_ASCENDING_SEQUENCE": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "PATTERN_REPEATED_RUN": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "PATTERN_KEYBOARD_WALK": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "PATTERN_YEAR_SUFFIX": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "PATTERN_COMMON_VARIANT": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
    }

    benign_total = 0
    benign_false_positives = 0

    for item in cases:
        candidate = item["candidate"]
        expected_rule = item["expected_rule"]
        category = item["category"]

        result = core.analyze_password(candidate)
        detected_rules = {p["rule_id"] for p in result["pattern_penalties"]}

        if category == "BENIGN_HIGH_ENTROPY":
            benign_total += 1
            # Benign high-entropy passwords should trigger 0 pattern rules
            pattern_triggers = [r for r in detected_rules if r.startswith("PATTERN_")]
            if pattern_triggers:
                benign_false_positives += 1
                print(f"  [FALSE POSITIVE] Benign candidate '{candidate}' flagged with: {pattern_triggers}")

        for rule in rule_stats:
            expected = (expected_rule == rule)
            actual = (rule in detected_rules)
            if expected and actual:
                rule_stats[rule]["tp"] += 1
            elif not expected and actual:
                rule_stats[rule]["fp"] += 1
            elif expected and not actual:
                rule_stats[rule]["fn"] += 1
            else:
                rule_stats[rule]["tn"] += 1

    print("\n--- Rule-Level Metrics ---")
    print(f"{'Rule ID':<30} {'TP':<5} {'FP':<5} {'FN':<5} {'Prec':<8} {'Recall':<8} {'FPR':<8}")
    print("-" * 70)

    total_tp = 0
    total_fn = 0
    total_fp = 0

    all_passed = True

    for rule, stats in rule_stats.items():
        tp = stats["tp"]
        fp = stats["fp"]
        fn = stats["fn"]
        tn = stats["tn"]

        total_tp += tp
        total_fn += fn
        total_fp += fp

        prec = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 100.0
        rec = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 100.0
        fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0.0

        print(f"{rule:<30} {tp:<5} {fp:<5} {fn:<5} {prec:>6.1f}%  {rec:>6.1f}%  {fpr:>6.1f}%")

        if rec < 90.0:
            print(f"  [WARNING] Rule {rule} recall ({rec:.1f}%) fell below target (90%)")
            all_passed = False

    overall_recall = (total_tp / (total_tp + total_fn)) * 100 if (total_tp + total_fn) > 0 else 0.0
    overall_prec = (total_tp / (total_tp + total_fp)) * 100 if (total_tp + total_fp) > 0 else 0.0
    benign_fpr = (benign_false_positives / benign_total) * 100 if benign_total > 0 else 0.0

    print("-" * 70)
    print(f"Overall Pattern Recall:      {overall_recall:.1f}% (Target: >= 90.0%)")
    print(f"Overall Pattern Precision:   {overall_prec:.1f}%")
    print(f"Benign False-Positive Rate:  {benign_fpr:.1f}% ({benign_false_positives}/{benign_total}) (Target: <= 5.0%)")

    if benign_fpr > 5.0:
        print("  [FAILURE] Benign False-Positive Rate exceeded 5.0% threshold!")
        all_passed = False

    # Golden Vectors Pass Rate
    golden_path = os.path.join(WORKSPACE_DIR, "tests", "golden_vectors.json")
    with open(golden_path, "r", encoding="utf-8") as f:
        golden_cases = json.load(f)

    golden_pass = 0
    for g in golden_cases:
        custom_set = frozenset(w.casefold() for w in g["custom_dict"]) if g["custom_dict"] else None
        res = core.analyze_password(g["password"], custom_dict=custom_set)
        exp = g["expected"]

        score_ok = (res["score"] == exp["score"])
        class_ok = (res["classification"] == exp["classification"])
        entropy_ok = (res["entropy_estimate"]["status"] == exp["entropy_status"])
        if score_ok and class_ok and entropy_ok:
            golden_pass += 1

    golden_rate = (golden_pass / len(golden_cases)) * 100
    print(f"Golden Vector Pass Rate:     {golden_rate:.1f}% ({golden_pass}/{len(golden_cases)}) (Target: 100.0%)")

    if golden_pass < len(golden_cases):
        all_passed = False

    print("=" * 70)
    if all_passed:
        print("ALL BENCHMARK QUALITY TARGETS PASSED!")
    else:
        print("ONE OR MORE BENCHMARK TARGETS FAILED!")
    print("=" * 70 + "\n")

    return all_passed


if __name__ == "__main__":
    success = run_benchmark_evaluation()
    sys.exit(0 if success else 1)
