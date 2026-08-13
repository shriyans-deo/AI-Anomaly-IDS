"""
Tests for the detection package.

Run from the repo root:
    python -m pytest tests/ -v
    python tests/test_detection.py      # works without pytest installed

The tests that matter most here are the contract tests -- they pin down the
output shape the backend depends on. If someone changes a key name in
score_one(), these fail loudly instead of the dashboard silently rendering
blank fields during the demo.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from detection import AnomalyDetector, FEATURE_COLUMNS
from detection.preprocessing import load_flows

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(REPO_ROOT, "data", "traffic.csv")

REQUIRED_OUTPUT_KEYS = {"anomaly_score", "ml_flagged", "rules_triggered", "severity"}
VALID_SEVERITIES = {"high", "medium", "none"}


def _load():
    if not os.path.exists(DATA_PATH):
        raise RuntimeError(
            f"No dataset at {DATA_PATH}. Run: python data/generate_data.py"
        )
    return load_flows(DATA_PATH)


def _fitted_detector(df=None):
    return AnomalyDetector().fit(df if df is not None else _load())


# -- contract tests --------------------------------------------------------

def test_score_one_returns_required_keys():
    """The backend reads these four keys. They must always be present."""
    df = _load()
    detector = _fitted_detector(df)
    flow = df.iloc[0].to_dict()

    result = detector.score_one(flow)

    assert REQUIRED_OUTPUT_KEYS.issubset(result.keys()), \
        f"missing keys: {REQUIRED_OUTPUT_KEYS - set(result.keys())}"


def test_score_one_output_types():
    """Types matter -- these get JSON-serialised by the API."""
    df = _load()
    detector = _fitted_detector(df)
    result = detector.score_one(df.iloc[0].to_dict())

    assert isinstance(result["anomaly_score"], int)
    assert isinstance(result["ml_flagged"], bool)
    assert isinstance(result["rules_triggered"], list)
    assert result["severity"] in VALID_SEVERITIES


def test_score_one_preserves_input_fields():
    """Timestamp and src_ip must survive scoring -- the dashboard needs them."""
    df = _load()
    detector = _fitted_detector(df)
    flow = df.iloc[0].to_dict()

    result = detector.score_one(flow)

    assert result["src_ip"] == flow["src_ip"]
    assert result["timestamp"] == flow["timestamp"]


def test_anomaly_score_in_range():
    df = _load()
    detector = _fitted_detector(df)
    for result in detector.score_dataframe(df):
        assert 0 <= result["anomaly_score"] <= 100, \
            f"score out of range: {result['anomaly_score']}"


# -- detection quality tests -----------------------------------------------

def test_all_attacks_are_flagged():
    """Every labelled attack should reach medium or high severity."""
    df = _load()
    detector = _fitted_detector(df)
    results = detector.score_dataframe(df)

    attacks = [r for r in results if r["label"] != "normal"]
    assert attacks, "dataset contains no attack rows"

    missed = [r for r in attacks if r["severity"] == "none"]
    assert not missed, f"{len(missed)} attacks went undetected: {missed[:3]}"


def test_false_positive_rate_is_acceptable():
    """
    Guards against a change that makes the detector flag everything.
    A detector screaming on 10% of normal traffic is useless in practice.
    """
    df = _load()
    detector = _fitted_detector(df)
    results = detector.score_dataframe(df)

    normals = [r for r in results if r["label"] == "normal"]
    flagged = [r for r in normals if r["severity"] in ("high", "medium")]
    rate = len(flagged) / len(normals)

    assert rate < 0.05, f"false positive rate too high: {rate:.2%}"


def test_attacks_score_higher_than_average_normal():
    df = _load()
    detector = _fitted_detector(df)
    results = detector.score_dataframe(df)

    attack_mean = sum(r["anomaly_score"] for r in results if r["label"] != "normal") / \
        max(1, sum(1 for r in results if r["label"] != "normal"))
    normal_mean = sum(r["anomaly_score"] for r in results if r["label"] == "normal") / \
        max(1, sum(1 for r in results if r["label"] == "normal"))

    assert attack_mean > normal_mean, \
        f"attacks ({attack_mean:.1f}) do not score above normal ({normal_mean:.1f})"


# -- rule tests ------------------------------------------------------------

def test_brute_force_rule_fires():
    detector = _fitted_detector()
    flow = {
        "num_connections": 40, "unique_dst_ports": 1, "bytes_sent": 2000,
        "bytes_recv": 1000, "failed_logins": 30, "syn_ratio": 0.3,
        "avg_conn_duration": 0.8,
    }
    result = detector.score_one(flow)
    assert "Excessive failed logins" in result["rules_triggered"]
    assert result["severity"] == "high"


def test_port_scan_rule_fires():
    detector = _fitted_detector()
    flow = {
        "num_connections": 200, "unique_dst_ports": 180, "bytes_sent": 5000,
        "bytes_recv": 200, "failed_logins": 0, "syn_ratio": 0.95,
        "avg_conn_duration": 0.05,
    }
    result = detector.score_one(flow)
    assert "Port scan pattern" in result["rules_triggered"]


def test_quiet_normal_flow_is_not_flagged():
    detector = _fitted_detector()
    flow = {
        "num_connections": 3, "unique_dst_ports": 2, "bytes_sent": 4000,
        "bytes_recv": 20000, "failed_logins": 0, "syn_ratio": 0.15,
        "avg_conn_duration": 6.0,
    }
    result = detector.score_one(flow)
    assert result["rules_triggered"] == []
    assert result["severity"] == "none"


# -- persistence tests -----------------------------------------------------

def test_save_and_load_roundtrip():
    """A loaded model must score identically to the one that was saved."""
    df = _load()
    detector = _fitted_detector(df)
    flow = df.iloc[0].to_dict()
    before = detector.score_one(flow)

    with tempfile.TemporaryDirectory() as tmpdir:
        detector.save(tmpdir)
        reloaded = AnomalyDetector.load(tmpdir)
        after = reloaded.score_one(flow)

    assert before["anomaly_score"] == after["anomaly_score"]
    assert before["severity"] == after["severity"]


def test_load_missing_model_raises():
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            AnomalyDetector.load(tmpdir)
        except FileNotFoundError:
            return
    raise AssertionError("loading a missing model should raise FileNotFoundError")


def test_unfitted_detector_raises():
    detector = AnomalyDetector()
    try:
        detector.score_one({c: 1 for c in FEATURE_COLUMNS})
    except RuntimeError:
        return
    raise AssertionError("scoring before fit() should raise RuntimeError")


def test_missing_feature_raises():
    detector = _fitted_detector()
    incomplete = {c: 1 for c in FEATURE_COLUMNS[:-1]}
    try:
        detector.score_one(incomplete)
    except ValueError:
        return
    raise AssertionError("a flow missing a feature should raise ValueError")


# -- runner for use without pytest -----------------------------------------

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0

    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {test.__name__}: {exc}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)