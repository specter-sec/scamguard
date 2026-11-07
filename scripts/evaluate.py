"""Evaluate ScamGuard's binary safe-vs-scam screening on samples.csv."""

import argparse
import csv
from pathlib import Path
from typing import Sequence

from scamguard import ScamDetector


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "samples.csv"
POSITIVE_LABELS = {"SUSPICIOUS", "HIGH RISK"}


def evaluate(dataset: Path) -> dict[str, float | int]:
    """Return binary accuracy, precision, recall, and confusion counts."""
    detector = ScamDetector()
    total = correct = true_positive = false_positive = false_negative = 0
    with dataset.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            expected = row["label"].strip().upper() in POSITIVE_LABELS
            predicted = detector.scan(row["text"]).risk_level.value != "SAFE"
            total += 1
            correct += int(expected == predicted)
            true_positive += int(expected and predicted)
            false_positive += int(not expected and predicted)
            false_negative += int(expected and not predicted)
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    return {
        "samples": total,
        "accuracy": correct / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    args = parser.parse_args(argv)
    if not args.dataset.is_file():
        parser.error(f"Dataset not found: {args.dataset}")
    metrics = evaluate(args.dataset)
    print(f"Dataset: {args.dataset}")
    print(f"Samples: {metrics['samples']}")
    print(f"Accuracy:  {metrics['accuracy']:.3f}")
    print(f"Precision: {metrics['precision']:.3f}")
    print(f"Recall:    {metrics['recall']:.3f}")
    print(
        "Confusion: "
        f"TP={metrics['true_positive']} FP={metrics['false_positive']} "
        f"FN={metrics['false_negative']}"
    )
    print("Note: these metrics describe this small curated sample, not real-world performance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
