import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from features import FEATURE_NAMES, extract_features, feature_vector  # noqa: E402


def test_benign_request_has_no_keyword_hits():
    f = extract_features("GET", "/search?q=coffee+mug", headers={"User-Agent": "Mozilla/5.0"})
    assert f["sqli_keyword_hits"] == 0
    assert f["xss_keyword_hits"] == 0
    assert f["has_user_agent"] == 1.0


def test_sqli_request_lights_up():
    f = extract_features("GET", "/search?q=' UNION SELECT username FROM users --")
    assert f["sqli_keyword_hits"] >= 3
    assert f["quote_count"] >= 1


def test_vector_shape_matches_feature_names():
    v = feature_vector("POST", "/login", "username=a&password=b", {})
    assert len(v) == len(FEATURE_NAMES)
