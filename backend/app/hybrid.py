"""Hybrid scoring engine (Phase 4).

Combines the three detection signals into one 0–100 risk score:

    signal      weight
    rule        0.50   ModSecurity CRS / baseline pattern score
    ml          0.35   XGBoost / Random Forest probability
    anomaly     0.15   Isolation Forest unusualness

Rules:
- Weights renormalise over the signals that are actually present, so a
  missing model never silently drags the score down.
- A very strong rule hit (rule_score >= 90 — e.g. a CRS critical or an
  explicit custom rule) floors the risk at 85: known-bad patterns are not
  diluted by calm ML/anomaly signals.
- Decision thresholds come from settings (monitor 40, block 75 by default).
"""
from .config import settings

WEIGHTS = {"rule": 0.50, "ml": 0.35, "anomaly": 0.15}
RULE_FLOOR_TRIGGER = 90.0
RULE_FLOOR_VALUE = 85.0


def combine(rule_score: float, ml_score: float | None,
            anomaly_score: float | None) -> float:
    signals = {"rule": rule_score}
    if ml_score is not None:
        signals["ml"] = ml_score
    if anomaly_score is not None:
        signals["anomaly"] = anomaly_score
    total_weight = sum(WEIGHTS[name] for name in signals)
    risk = sum(WEIGHTS[name] * value for name, value in signals.items()) / total_weight
    if rule_score >= RULE_FLOOR_TRIGGER:
        risk = max(risk, RULE_FLOOR_VALUE)
    return round(min(max(risk, 0.0), 100.0), 2)


def decide(risk_score: float) -> str:
    if risk_score >= settings.risk_block_threshold:
        return "block"
    if risk_score >= settings.risk_monitor_threshold:
        return "monitor"
    return "allow"
