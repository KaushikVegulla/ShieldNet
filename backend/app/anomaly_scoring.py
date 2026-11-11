"""Anomaly scoring for /analyze (Phase 4).

Loads the Isolation Forest bundle from ANOMALY_MODEL_PATH when present and
returns a 0–100 anomaly score (higher = more unusual vs. benign traffic).
Returns None when no model is available — never invents a score.

Train with ml/train_anomaly.py; the artefact is not committed to git.
"""
import os

from . import features

_MODEL = None
_MODEL_TRIED = False


def _load():
    global _MODEL, _MODEL_TRIED
    if _MODEL_TRIED:
        return _MODEL
    _MODEL_TRIED = True
    path = os.environ.get("ANOMALY_MODEL_PATH", "")
    if not path or not os.path.exists(path):
        return None
    try:
        import joblib

        _MODEL = joblib.load(path)
    except Exception:
        _MODEL = None
    return _MODEL


def score(method: str, uri: str, body: str | None, headers: dict) -> float | None:
    bundle = _load()
    if bundle is None:
        return None
    try:
        import pandas as pd

        feats = features.extract_features(method, uri, body, headers)
        X = pd.DataFrame([[feats[n] for n in bundle["feature_names"]]],
                         columns=bundle["feature_names"])
        raw = float(bundle["model"].decision_function(X)[0])
        cal = bundle["calibration"]
        lo, hi = cal["lo"], cal["hi"]
        if hi == lo:
            return 0.0
        return round(min(max(100.0 * (hi - raw) / (hi - lo), 0.0), 100.0), 2)
    except Exception:
        return None
