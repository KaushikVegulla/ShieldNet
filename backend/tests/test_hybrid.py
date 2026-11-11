from app import hybrid


def test_rule_only_passes_through():
    assert hybrid.combine(30.0, None, None) == 30.0
    assert hybrid.combine(80.0, None, None) == 80.0


def test_weights_renormalise_when_ml_missing():
    # rule 0.5 + anomaly 0.15 -> risk is the renormalised weighted mean
    risk = hybrid.combine(0.0, None, 100.0)
    assert risk == round(100.0 * 0.15 / 0.65, 2)


def test_full_combination():
    risk = hybrid.combine(100.0, 100.0, 100.0)
    assert risk == 100.0
    risk = hybrid.combine(0.0, 0.0, 0.0)
    assert risk == 0.0


def test_strong_rule_hit_floors_risk():
    # ML and anomaly are calm, but a 95 rule score must not be diluted.
    risk = hybrid.combine(95.0, 0.0, 0.0)
    assert risk >= 85.0
    assert hybrid.decide(risk) == "block"


def test_strong_ml_floors_at_monitor():
    # SLEEP()-style probe: rules miss it, ML is near-certain.
    risk = hybrid.combine(0.0, 93.5, 16.0)
    assert risk >= 55.0
    assert hybrid.decide(risk) == "monitor"


def test_decide_thresholds():
    assert hybrid.decide(10) == "allow"
    assert hybrid.decide(50) == "monitor"
    assert hybrid.decide(90) == "block"
