"""Train ShieldNet's anomaly detector: Isolation Forest on benign traffic only.

The model learns what normal requests look like; unusual requests get a high
anomaly score. Calibration: the bundle stores two points of the benign
decision-function distribution (median = score 0 end, 1st percentile = score
100 end) so the backend can map raw decision values to a 0–100 score.

Usage: python ml/train_anomaly.py --data ml/data/dataset.csv
Writes ml/models/anomaly_model.joblib + ml/models/anomaly_metrics.json
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from features import FEATURE_NAMES, extract_features

MODEL_VERSION = "anomaly-v1"


def to_score(df_value: float, lo: float, hi: float) -> float:
    """Map an IsolationForest decision value to 0–100 (higher = more anomalous)."""
    if hi == lo:
        return 0.0
    return float(np.clip(100.0 * (hi - df_value) / (hi - lo), 0, 100))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data/dataset.csv")
    ap.add_argument("--out-dir", default="ml/models")
    args = ap.parse_args()

    df = pd.read_csv(args.data).fillna("")
    feats = pd.DataFrame(
        [extract_features(r.method, r.uri, r.body) for r in df.itertuples()]
    )[FEATURE_NAMES]
    benign = feats[df["label"].astype(int) == 0]
    attacks = feats[df["label"].astype(int) == 1]

    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    model.fit(benign)

    benign_df = model.decision_function(benign)
    lo = float(np.percentile(benign_df, 1))    # ~most anomalous benign point
    hi = float(np.percentile(benign_df, 50))   # typical benign point
    benign_scores = [to_score(v, lo, hi) for v in benign_df]
    attack_scores = [to_score(v, lo, hi) for v in model.decision_function(attacks)]

    metrics = {
        "version": MODEL_VERSION,
        "trained_on_benign_rows": int(len(benign)),
        "benign_score_mean": round(float(np.mean(benign_scores)), 2),
        "attack_score_mean": round(float(np.mean(attack_scores)), 2),
        "attacks_scoring_over_40": round(float(np.mean([s > 40 for s in attack_scores])), 4),
        "benign_scoring_over_40": round(float(np.mean([s > 40 for s in benign_scores])), 4),
        "note": "Synthetic starter data — same caveat as ml/README.md.",
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "feature_names": FEATURE_NAMES,
         "version": MODEL_VERSION, "calibration": {"lo": lo, "hi": hi}},
        out_dir / "anomaly_model.joblib",
    )
    (out_dir / "anomaly_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
