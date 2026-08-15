

import pandas as pd
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "num_connections",
    "unique_dst_ports",
    "bytes_sent",
    "bytes_recv",
    "failed_logins",
    "syn_ratio",
    "avg_conn_duration",
]


LABEL_COLUMN = "label"
NORMAL_LABEL = "normal"


def load_flows(csv_path):
    """Load flow records from CSV and validate the schema."""
    df = pd.read_csv(csv_path)

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"{csv_path} is missing required feature columns: {missing}. "
            f"Regenerate it with: python data/generate_data.py"
        )
    return df


def extract_features(df):
    """Select just the model input columns, in the canonical order."""
    return df[FEATURE_COLUMNS]


def split_baseline(df):
    """
    Return only the rows considered normal.

    The detector is trained on a clean baseline, not on the full mixed
    dataset. This mirrors how you'd deploy it in reality: record a quiet
    period, learn what normal looks like, then flag deviations. It also
    keeps the attack rows completely unseen, so evaluating on them is
    meaningful rather than circular.
    """
    if LABEL_COLUMN not in df.columns:
        # No labels available -- assume the whole capture is baseline.
        return df
    return df[df[LABEL_COLUMN] == NORMAL_LABEL]


class FeatureScaler:
    """
    Thin wrapper around StandardScaler.

    Scaling matters here because the raw features live on wildly different
    scales -- bytes_sent runs into the hundreds of thousands while syn_ratio
    is between 0 and 1. Without standardising, distance-based splits would be
    dominated by the byte counts alone.
    """

    def __init__(self):
        self._scaler = StandardScaler()
        self.fitted = False

    def fit(self, df):
        self._scaler.fit(extract_features(df))
        self.fitted = True
        return self

    def transform(self, df):
        if not self.fitted:
            raise RuntimeError("FeatureScaler.transform() called before fit()")
        return self._scaler.transform(extract_features(df))

    def fit_transform(self, df):
        return self.fit(df).transform(df)