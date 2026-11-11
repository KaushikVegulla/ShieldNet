"""ML scoring for /analyze (Phase 3).

Loads the trained model artefact (joblib) from MODEL_PATH when present and
returns a malicious-probability score 0–100. Returns None when no model is
available — the backend must never invent an ML score.

Train with ml/train.py; the artefact is not committed to git. In Docker,
mount ml/models into the backend container and set
MODEL_PATH=/app/models/shieldnet_model.joblib.
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
    path = os.environ.get("MODEL_PATH", "")
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
        proba = bundle["model"].predict_proba(X)[0]
        classes = list(bundle["model"].classes_)
        malicious = proba[classes.index(1)] if 1 in classes else float(proba[-1])
        return round(float(malicious) * 100, 2)
    except Exception:
        return None


def model_version() -> str:
    bundle = _load()
    return bundle.get("version", "ml-v1") if bundle else "baseline-rules-v1"
