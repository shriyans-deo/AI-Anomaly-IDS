# AI-Anomaly-IDS
AI-powered anomaly-based Intrusion Detection System using Isolation Forest
# AI-ANOMALY-IDS

Anomaly-based intrusion detection. Learns what normal network traffic looks
like and flags deviations, rather than matching against a list of known
attack signatures — so it can catch attacks it has never seen before.

## Layout

```
data/
  generate_data.py     synthetic traffic generator (normal + labelled attacks)
  traffic.csv          generated dataset — not committed, regenerate locally
detection/
  __init__.py          public API
  preprocessing.py     feature schema, loading, scaling
  detector.py          Isolation Forest + rule engine
  train.py             training, evaluation, model export
  model/               saved model artifact
tests/
  test_detection.py    contract + detection quality tests
```

## Quick start

```bash
pip install -r detection/requirements.txt
python data/generate_data.py --summary     # build the dataset
python -m detection.train                  # train, evaluate, save
python tests/test_detection.py             # verify
```

## Current results

```
attack          caught   recall    rules    ml
brute_force     4/4      100.0%        4     4
ddos            4/4      100.0%        4     4
port_scan       3/3      100.0%        3     2

False positives: 24 of 2369 normal flows (1.01%)
```

Accuracy is deliberately not reported: the dataset is 99.5% normal, so a
detector that flags nothing scores 99.5% accuracy while being useless.
Per-class recall and false-positive rate are the numbers that mean something.

## How detection works

Two layers, combined:

**Isolation Forest (unsupervised ML)** — trained on the normal-traffic
baseline only. It isolates points by random partitioning; outliers separate
in fewer splits than clustered normal points, so they score as anomalous. It
never sees the attack rows during training, which is what makes the
evaluation honest. Its strength is catching things nobody wrote a rule for;
its weakness is that it outputs a score, not an explanation.

**Rule checks (deterministic)** — three signatures for well-understood
attacks (excessive failed logins, port-scan pattern, traffic flood). Fast,
explainable, and they fire regardless of the ML score.

Real IDS/SIEM products layer these the same way and for the same reason: the
rules give precision and a human-readable reason on known attacks, the ML
gives coverage on unknown ones.

**A known limitation, worth being upfront about:** attack scores (min 54)
and normal scores (max 67) overlap, so no single ML threshold cleanly
separates them — the rule layer is carrying precision. Tightening
`contamination` reduces false positives but costs ML-alone recall
(0.02 → 11/11 attacks at 2.03% FP; 0.01 → 10/11 at 1.01%; 0.005 → 8/11 at
0.51%). 0.01 is the current default as the best balance.

## Features the model uses

Per source IP, per 10-second window:

| feature | why it matters |
|---|---|
| `num_connections` | floods and scans spike this |
| `unique_dst_ports` | high = scanning; 1 = targeting one service |
| `bytes_sent` / `bytes_recv` | asymmetry signals a flood or refused scan |
| `failed_logins` | brute force |
| `syn_ratio` | near 1.0 = connections opened, never completed |
| `avg_conn_duration` | near zero = not real sessions |

`src_ip` is deliberately excluded — training on it would teach the model
"10.0.0.66 is bad" rather than "scanning is bad".

## Integration contract

This is what the backend depends on. **Changing these four keys or their
types is a breaking change — coordinate before touching them.**

```python
from detection import AnomalyDetector

detector = AnomalyDetector.load("detection/model")   # load once at startup
result = detector.score_one(flow_dict)               # per event
```

`score_one()` returns the input record plus:

| key | type | meaning |
|---|---|---|
| `anomaly_score` | `int` | 0–100, higher = more anomalous |
| `ml_flagged` | `bool` | whether Isolation Forest flagged it |
| `rules_triggered` | `list[str]` | names of rules that fired |
| `severity` | `str` | `"high"` \| `"medium"` \| `"none"` |

All original fields (`timestamp`, `src_ip`, …) pass through untouched.

For bulk scoring, `score_dataframe(df)` returns a list of the same dicts and
is far faster than looping `score_one` — sklearn has fixed per-call overhead.

The saved artifact bundles the scaler with the model on purpose: a model
loaded without its matching scaler produces silently wrong scores.

## Adding an attack type

1. Write a profile function in `data/generate_data.py`
2. Register it in `ATTACK_PROFILES`, add windows to `ATTACK_SCHEDULE`
3. Optionally add a rule to `RULES` in `detection/detector.py`
4. Regenerate, retrain, rerun tests

Rules need no retraining, which makes them the fast path during a hackathon.

## Notes

- `traffic.csv` is gitignored — it is deterministic for a given `--seed`, so
  commit the generator, not the output. Run `generate_data.py` after cloning.
- `--seed` makes runs reproducible; use it when comparing results with a
  teammate so you are both looking at the same data.