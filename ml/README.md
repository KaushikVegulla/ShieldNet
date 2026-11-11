# ML — detection models

## Pipeline

```bash
pip install -r ml/requirements.txt
python ml/generate_dataset.py --rows 2400     # -> ml/data/dataset.csv (not committed)
python ml/train.py                            # -> ml/models/shieldnet_model.joblib
                                              #    + ml/models/metrics.json
pytest ml/tests                               # feature-extraction tests
```

- `features.py` — the one feature implementation (20 numeric features:
  lengths, entropy, special-char ratios, SQLi/XSS/traversal/shell keyword
  hits, header signals). `backend/app/features.py` is an identical runtime
  copy — keep them in sync (`cp ml/features.py backend/app/features.py`).
- `train.py` — trains Random Forest and XGBoost, keeps the better F1,
  saves it as a versioned joblib bundle.
- The backend serves the model when `MODEL_PATH` points at the artefact
  (plus `backend/requirements-ml.txt` installed). Without a model,
  `/analyze` honestly returns `ml_score: null`.

## Current status — read this before quoting any number

Training data is **synthetic** (generated payloads + templated benign
traffic). Both models score F1 = 1.0 on the held-out split of that data —
that only proves the pipeline works end to end; synthetic attacks are far
cleaner than real traffic. The next data iteration is:

1. CSIC-2010 HTTP dataset for realistic labelled traffic
2. ShieldNet's own WAF-logged requests from PostgreSQL (`request_logs`),
   labelled via CRS rule hits + manual review

Model artefacts (`*.joblib`) and datasets (`*.csv`) are git-ignored;
`metrics.json` is committed so results are visible without retraining.
