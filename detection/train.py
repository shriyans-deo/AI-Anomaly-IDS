"""
Train the anomaly detector and report how well it performs.

Run from the repo root:
    python -m detection.train
    python -m detection.train --data data/traffic.csv --no-save

What it does:
    1. loads flow records
    2. fits the detector on the normal-traffic baseline only
    3. scores the full dataset (including the unseen attacks)
    4. prints an evaluation -- per-class recall, false-positive rate, and a
       breakdown of what caught each attack
    5. saves the fitted model to detection/model/

On the evaluation: accuracy is deliberately not reported. The dataset is
~99.5% normal, so a detector that flags nothing at all would score 99.5%
accuracy while being completely useless. Per-class recall and false-positive
rate are the numbers that actually mean something here.
"""

import argparse
import os
import sys

from .detector import AnomalyDetector
from .preprocessing import LABEL_COLUMN, NORMAL_LABEL, load_flows

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATA = os.path.join(REPO_ROOT, "data", "traffic.csv")
DEFAULT_MODEL_DIR = os.path.join(REPO_ROOT, "detection", "model")

FLAGGED = {"high", "medium"}


def evaluate(results):
    """Compute detection metrics from scored results. Returns a dict."""
    labelled = [r for r in results if LABEL_COLUMN in r]
    if not labelled:
        return None

    normals = [r for r in labelled if r[LABEL_COLUMN] == NORMAL_LABEL]
    attacks = [r for r in labelled if r[LABEL_COLUMN] != NORMAL_LABEL]

    per_class = {}
    for record in attacks:
        label = record[LABEL_COLUMN]
        bucket = per_class.setdefault(
            label, {"total": 0, "caught": 0, "by_rule": 0, "by_ml": 0, "ml_only": 0}
        )
        bucket["total"] += 1
        if record["severity"] in FLAGGED:
            bucket["caught"] += 1

        # Each layer is credited independently -- a record caught by both
        # counts for both. Counting only "exclusive" catches would make a
        # layer look useless simply because the other one also caught it.
        if record["rules_triggered"]:
            bucket["by_rule"] += 1
        if record["ml_flagged"]:
            bucket["by_ml"] += 1
        if record["ml_flagged"] and not record["rules_triggered"]:
            bucket["ml_only"] += 1

    false_positives = [r for r in normals if r["severity"] in FLAGGED]

    attack_scores = [r["anomaly_score"] for r in attacks]
    normal_scores = [r["anomaly_score"] for r in normals]
    separation = {
        "attack_min": min(attack_scores) if attack_scores else 0,
        "attack_mean": sum(attack_scores) / len(attack_scores) if attack_scores else 0,
        "normal_max": max(normal_scores) if normal_scores else 0,
        "normal_mean": sum(normal_scores) / len(normal_scores) if normal_scores else 0,
    }

    return {
        "total": len(labelled),
        "normal_count": len(normals),
        "attack_count": len(attacks),
        "per_class": per_class,
        "false_positives": len(false_positives),
        "false_positive_rate": len(false_positives) / len(normals) if normals else 0.0,
        "attacks_caught": sum(b["caught"] for b in per_class.values()),
        "separation": separation,
    }


def print_report(metrics):
    if metrics is None:
        print("\n  No label column found -- skipping evaluation.\n")
        return

    print("\n" + "=" * 62)
    print("  DETECTION PERFORMANCE")
    print("=" * 62)

    print(f"\n  Dataset: {metrics['total']} flows "
          f"({metrics['normal_count']} normal, {metrics['attack_count']} attack)")

    print("\n  Recall by attack type (each layer credited independently)")
    print(f"    {'attack':<14} {'caught':>10} {'recall':>8}   {'rules':>6} {'ml':>5}")
    print("    " + "-" * 50)
    for label in sorted(metrics["per_class"]):
        bucket = metrics["per_class"][label]
        recall = bucket["caught"] / bucket["total"] * 100
        print(f"    {label:<14} {bucket['caught']:>4}/{bucket['total']:<5} "
              f"{recall:>7.1f}%   {bucket['by_rule']:>6} {bucket['by_ml']:>5}")

    total_attacks = metrics["attack_count"]
    overall = metrics["attacks_caught"] / total_attacks * 100 if total_attacks else 0
    print(f"\n    {'OVERALL':<14} {metrics['attacks_caught']:>4}/{total_attacks:<5} "
          f"{overall:>7.1f}%")

    print(f"\n  False positives: {metrics['false_positives']} of "
          f"{metrics['normal_count']} normal flows "
          f"({metrics['false_positive_rate'] * 100:.2f}%)")

    sep = metrics["separation"]
    print(f"\n  Score separation")
    print(f"    attacks       min {sep['attack_min']:>3}   mean {sep['attack_mean']:>5.1f}")
    print(f"    normal        max {sep['normal_max']:>3}   mean {sep['normal_mean']:>5.1f}")
    if sep["attack_min"] <= sep["normal_max"]:
        print(f"    ! ranges overlap -- no single score threshold separates them,")
        print(f"      which is exactly why the rule layer is carrying precision here.")

    print("=" * 62 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate the IDS detector.")
    parser.add_argument("--data", default=DEFAULT_DATA, help="path to the flow CSV")
    parser.add_argument("--model-dir", default=DEFAULT_MODEL_DIR,
                        help="where to save the fitted model")
    parser.add_argument("--no-save", action="store_true",
                        help="evaluate without writing the model artifact")
    parser.add_argument("--contamination", type=float, default=0.01,
                        help="expected outlier fraction (default: 0.01). Raise it "
                             "to flag more aggressively, lower it to reduce noise.")
    args = parser.parse_args()

    if not os.path.exists(args.data):
        print(f"error: no dataset at {args.data}", file=sys.stderr)
        print("Generate one first:  python data/generate_data.py", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {args.data} ...")
    df = load_flows(args.data)
    print(f"  {len(df)} flow records loaded")

    print(f"\nTraining Isolation Forest (contamination={args.contamination}) ...")
    detector = AnomalyDetector(contamination=args.contamination).fit(df)
    print("  fitted on normal-traffic baseline only")

    print("\nScoring full dataset ...")
    results = detector.score_dataframe(df)

    print_report(evaluate(results))

    if not args.no_save:
        path = detector.save(args.model_dir)
        print(f"Model saved to {path}")
        print("The backend can now load it with AnomalyDetector.load('detection/model')\n")


if __name__ == "__main__":
    main()