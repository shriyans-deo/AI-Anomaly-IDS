"""
The detection engine.

Combines two layers:

  1. Isolation Forest (unsupervised ML) -- learns what normal traffic looks
     like and flags statistical outliers. Catches attacks nobody wrote a rule
     for, but its output is a score, not an explanation.

  2. Rule checks (deterministic) -- encode well-understood attack signatures.
     Fast, explainable, and they fire regardless of what the model thinks.

Real IDS/SIEM products layer these the same way, for the same reason: rules
give you precision and a human-readable reason on known attacks, ML gives you
coverage on unknown ones.
"""

import os
import joblib

from sklearn.ensemble import IsolationForest

from .preprocessing import (
    FEATURE_COLUMNS,
    FeatureScaler,
    extract_features,
    split_baseline,
)

# --------------------------------------------------------------------------
# Rules
#
# Each rule is (name, predicate). The predicate receives one flow record as a
# dict and returns True if the rule fires. Add rules here -- they need no
# retraining, which is exactly why this layer is useful during a hackathon.
# --------------------------------------------------------------------------

RULES = [
    (
        "Excessive failed logins",
        lambda f: f["failed_logins"] >= 10,
    ),
    (
        "Port scan pattern",
        lambda f: f["unique_dst_ports"] >= 40 and f["syn_ratio"] >= 0.8,
    ),
    (
        "Traffic flood",
        lambda f: f["num_connections"] >= 400,
    ),
]

# Isolation Forest's decision_function returns roughly [-0.1, 0.2] on this
# data (higher = more normal). These bounds map it onto a 0-100 scale that is
# readable on a dashboard. They are calibrated from the baseline distribution
# at fit time, not hardcoded guesses -- see AnomalyDetector.fit().
SCORE_FLOOR_PERCENTILE = 1

# An ML flag only escalates to "high" once the score clears this.
HIGH_SEVERITY_SCORE = 70


class AnomalyDetector:
    """
    Trains on baseline traffic, then scores arbitrary flows.

    Typical use:
        detector = AnomalyDetector().fit(df)
        results = detector.score_dataframe(df)
        detector.save("detection/model")

    And on the serving side:
        detector = AnomalyDetector.load("detection/model")
        result = detector.score_one(flow_dict)
    """

    MODEL_FILENAME = "detector.joblib"

    def __init__(self, n_estimators=200, contamination=0.01, random_state=42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state

        self.model = None
        self.scaler = None
        self._score_lo = None
        self._score_hi = None

    # -- training ----------------------------------------------------------

    def fit(self, df):
        """
        Fit on the normal-traffic baseline only.

        Attack rows are deliberately excluded so they stay unseen, which
        makes the evaluation in train.py an honest test rather than a
        measurement of memorisation.
        """
        baseline = split_baseline(df)
        if len(baseline) < 50:
            raise ValueError(
                f"Only {len(baseline)} baseline rows available -- too few to "
                f"learn a stable notion of 'normal'. Generate more data."
            )

        self.scaler = FeatureScaler()
        X = self.scaler.fit_transform(baseline)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X)

        # Calibrate the 0-100 display scale against the baseline's own score
        # distribution, so the mapping adapts if the data changes.
        baseline_scores = self.model.decision_function(X)
        self._score_hi = float(baseline_scores.max())
        self._score_lo = float(
            baseline_scores.min() - (baseline_scores.max() - baseline_scores.min()) * 0.5
        )
        return self

    # -- scoring -----------------------------------------------------------

    def _to_display_score(self, raw_score):
        """Map decision_function output onto 0-100, where 100 = most anomalous."""
        span = self._score_hi - self._score_lo
        if span <= 0:
            return 0
        pct = (self._score_hi - raw_score) / span * 100
        return int(max(0, min(100, round(pct))))

    @staticmethod
    def _check_rules(flow):
        return [name for name, predicate in RULES if predicate(flow)]

    @staticmethod
    def _severity(triggered_rules, ml_flagged, anomaly_score):
        if triggered_rules:
            return "high"
        if ml_flagged and anomaly_score >= HIGH_SEVERITY_SCORE:
            return "high"
        if ml_flagged:
            return "medium"
        return "none"

    def score_dataframe(self, df):
        """
        Score every row. Returns a list of dicts: the original record plus
        anomaly_score, ml_flagged, rules_triggered, and severity.

        Vectorised on purpose -- sklearn has fixed per-call overhead, so
        scoring row-by-row is ~600x slower on a dataset this size.
        """
        self._require_fitted()

        X = self.scaler.transform(df)
        raw_scores = self.model.decision_function(X)
        ml_flags = self.model.predict(X) == -1

        results = []
        for record, raw_score, ml_flagged in zip(
            df.to_dict(orient="records"), raw_scores, ml_flags
        ):
            anomaly_score = self._to_display_score(raw_score)
            triggered_rules = self._check_rules(record)
            results.append({
                **record,
                "anomaly_score": anomaly_score,
                "ml_flagged": bool(ml_flagged),
                "rules_triggered": triggered_rules,
                "severity": self._severity(triggered_rules, ml_flagged, anomaly_score),
            })
        return results

    def score_one(self, flow):
        """
        Score a single flow record (a plain dict).

        This is the entry point the backend calls per event. Any extra keys
        in the dict are passed through untouched, so timestamps and IPs
        survive into the response.
        """
        self._require_fitted()

        import pandas as pd
        missing = [c for c in FEATURE_COLUMNS if c not in flow]
        if missing:
            raise ValueError(f"flow record is missing features: {missing}")

        X = self.scaler.transform(pd.DataFrame([flow]))
        raw_score = float(self.model.decision_function(X)[0])
        ml_flagged = bool(self.model.predict(X)[0] == -1)

        anomaly_score = self._to_display_score(raw_score)
        triggered_rules = self._check_rules(flow)
        return {
            **flow,
            "anomaly_score": anomaly_score,
            "ml_flagged": ml_flagged,
            "rules_triggered": triggered_rules,
            "severity": self._severity(triggered_rules, ml_flagged, anomaly_score),
        }

    # -- persistence -------------------------------------------------------

    def save(self, model_dir):
        """
        Persist the fitted detector so the backend never has to retrain.

        The scaler is saved alongside the model deliberately -- a model
        loaded without its matching scaler would silently produce garbage
        scores, which is a nasty bug to chase during a demo.
        """
        self._require_fitted()
        os.makedirs(model_dir, exist_ok=True)
        path = os.path.join(model_dir, self.MODEL_FILENAME)
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "score_lo": self._score_lo,
                "score_hi": self._score_hi,
                "feature_columns": FEATURE_COLUMNS,
            },
            path,
        )
        return path

    @classmethod
    def load(cls, model_dir):
        path = os.path.join(model_dir, cls.MODEL_FILENAME)
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"No trained model at {path}. Run: python -m detection.train"
            )

        payload = joblib.load(path)

        # Guard against a stale model trained on a different feature set.
        saved_features = payload.get("feature_columns")
        if saved_features != FEATURE_COLUMNS:
            raise ValueError(
                f"Saved model expects features {saved_features} but the code "
                f"now defines {FEATURE_COLUMNS}. Retrain with: "
                f"python -m detection.train"
            )

        detector = cls()
        detector.model = payload["model"]
        detector.scaler = payload["scaler"]
        detector._score_lo = payload["score_lo"]
        detector._score_hi = payload["score_hi"]
        return detector

    def _require_fitted(self):
        if self.model is None or self.scaler is None:
            raise RuntimeError(
                "Detector is not fitted. Call .fit(df) or AnomalyDetector.load(dir)."
            )