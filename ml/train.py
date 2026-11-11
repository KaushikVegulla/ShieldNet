"""Train ShieldNet's ML detectors (Random Forest + XGBoost) and keep the best.

Reads a labelled CSV (see generate_dataset.py), extracts features, trains both
models, evaluates on a held-out split, saves the better one (by F1) to
ml/models/shieldnet_model.joblib and writes ml/models/metrics.json.

Usage: python ml/train.py --data ml/data/dataset.csv
"""
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from features import FEATURE_NAMES, extract_features

MODEL_VERSION = "ml-v1"


def evaluate(name: str, model, X_test, y_test) -> dict:
    pred = model.predict(X_test)
    return {
        "model": name,
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, pred, zero_division=0), 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data/dataset.csv")
    ap.add_argument("--out-dir", default="ml/models")
    args = ap.parse_args()

    df = pd.read_csv(args.data).fillna("")
    X = pd.DataFrame([extract_features(r.method, r.uri, r.body) for r in df.itertuples()])[FEATURE_NAMES]
    y = df["label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    candidates = {
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
        "xgboost": XGBClassifier(n_estimators=200, max_depth=5, learning_rate=0.1,
                                 subsample=0.9, colsample_bytree=0.9, random_state=42,
                                 eval_metric="logloss", n_jobs=-1),
    }
    results, fitted = {}, {}
    for name, model in candidates.items():
        model.fit(X_train, y_train)
        results[name] = evaluate(name, model, X_test, y_test)
        fitted[name] = model
        print(f"{name}: {results[name]}")

    best_name = max(results, key=lambda n: results[n]["f1"])
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": fitted[best_name], "model_name": best_name,
         "feature_names": FEATURE_NAMES, "version": MODEL_VERSION},
        out_dir / "shieldnet_model.joblib",
    )
    metrics = {"dataset_rows": int(len(df)), "best_model": best_name,
               "version": MODEL_VERSION, "results": results}
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"best: {best_name} -> {out_dir / 'shieldnet_model.joblib'}")


if __name__ == "__main__":
    main()
