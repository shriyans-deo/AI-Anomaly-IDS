"""
Anomaly-based intrusion detection.

This package is the detection layer only -- it has no knowledge of the API,
the dashboard, or how events get delivered. That separation is deliberate:
the backend depends on this package, not the other way around.

Public API (this is the contract the backend depends on):

    from detection import AnomalyDetector

    detector = AnomalyDetector.load("detection/model")
    result = detector.score_one(flow_dict)

`score_one` returns the input record plus four added keys:

    anomaly_score     int, 0-100, higher = more anomalous
    ml_flagged        bool, whether Isolation Forest flagged it
    rules_triggered   list[str], names of any rules that fired
    severity          "high" | "medium" | "none"

Changing those four keys or their types is a breaking change for the
backend -- coordinate before touching them.
"""

from .detector import AnomalyDetector, RULES
from .preprocessing import FEATURE_COLUMNS, load_flows

__all__ = ["AnomalyDetector", "RULES", "FEATURE_COLUMNS", "load_flows"]

__version__ = "0.1.0"