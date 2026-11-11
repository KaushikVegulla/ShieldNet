"""Request feature extraction — the single source of truth for ML features.

backend/app/features.py is a byte-identical runtime copy (the backend is a
separate Docker image and cannot import from ml/). Keep them in sync:
    cp ml/features.py backend/app/features.py
"""
import math
import re
from urllib.parse import unquote_plus, urlparse, parse_qs

SQLI_WORDS = ["union", "select", "insert", "update", "delete", "drop", "from", "where",
              "sleep", "benchmark", "information_schema", "or 1=1", "' or '"]
XSS_WORDS = ["<script", "javascript:", "onerror", "onload", "alert(", "<svg", "<iframe",
             "document.cookie", "eval("]
TRAVERSAL_TOKENS = ["../", "..\\", "/etc/passwd", ".env", ".git", "boot.ini", "%2e%2e"]
SHELL_TOKENS = [";", "|", "&&", "`", "$(", "cat ", "whoami", "wget", "curl", "/bin/"]

FEATURE_NAMES = [
    "method_post", "uri_length", "path_depth", "num_params", "param_value_max_len",
    "param_value_mean_len", "body_length", "entropy", "special_char_ratio",
    "digit_ratio", "quote_count", "angle_bracket_count", "equals_count",
    "sqli_keyword_hits", "xss_keyword_hits", "traversal_hits", "shell_hits",
    "has_user_agent", "header_count", "encoded_char_ratio",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(method: str, uri: str, body: str | None = None,
                     headers: dict | None = None) -> dict[str, float]:
    headers = headers or {}
    decoded = unquote_plus(uri)
    parsed = urlparse(decoded)
    params = parse_qs(parsed.query)
    values = [v for vs in params.values() for v in vs]
    text = f"{decoded} {body or ''}"
    lower = text.lower()
    alnum = sum(ch.isalnum() for ch in text)
    return {
        "method_post": 1.0 if method.upper() == "POST" else 0.0,
        "uri_length": float(len(uri)),
        "path_depth": float(parsed.path.count("/")),
        "num_params": float(len(params)),
        "param_value_max_len": float(max((len(v) for v in values), default=0)),
        "param_value_mean_len": float(sum(len(v) for v in values) / len(values)) if values else 0.0,
        "body_length": float(len(body or "")),
        "entropy": round(_entropy(text), 4),
        "special_char_ratio": float(1 - (alnum / len(text))) if text.strip() else 0.0,
        "digit_ratio": float(sum(ch.isdigit() for ch in text) / len(text)) if text else 0.0,
        "quote_count": float(text.count("'") + text.count('"')),
        "angle_bracket_count": float(text.count("<") + text.count(">")),
        "equals_count": float(text.count("=")),
        "sqli_keyword_hits": float(sum(lower.count(w) for w in SQLI_WORDS)),
        "xss_keyword_hits": float(sum(lower.count(w) for w in XSS_WORDS)),
        "traversal_hits": float(sum(lower.count(w) for w in TRAVERSAL_TOKENS)),
        "shell_hits": float(sum(lower.count(w) for w in SHELL_TOKENS)),
        "has_user_agent": 1.0 if any(k.lower() == "user-agent" for k in headers) else 0.0,
        "header_count": float(len(headers)),
        "encoded_char_ratio": float(len(re.findall(r"%[0-9a-fA-F]{2}", uri)) / len(uri)) if uri else 0.0,
    }


def feature_vector(method: str, uri: str, body: str | None = None,
                   headers: dict | None = None) -> list[float]:
    feats = extract_features(method, uri, body, headers)
    return [feats[name] for name in FEATURE_NAMES]
