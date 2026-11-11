"""Phase 1 baseline scorer.

A transparent pattern-based stand-in so /analyze works end-to-end today.
Phase 3 adds the ML score (XGBoost / Random Forest) and Phase 4 replaces
this module's risk combination with the full hybrid engine — the function
signature (scores in, decision out) stays the same.
"""
import re
from dataclasses import dataclass, field

from .config import settings

PATTERNS: list[tuple[str, str, int]] = [
    # (regex, attack_type, weight)
    (r"(\bunion\b\s+\bselect\b|\bselect\b.+\bfrom\b|'\s*or\s+'?1'?\s*=\s*'?1)", "sqli", 45),
    (r"(--|#|/\*|\bdrop\b\s+\btable\b|\binsert\b\s+\binto\b|\bupdate\b.+\bset\b)", "sqli", 30),
    (r"(\b(sleep|benchmark)\s*\()", "sqli", 30),
    (r"(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+on\w+\s*=)", "xss", 45),
    (r"(<svg|<iframe|document\.cookie|alert\s*\()", "xss", 30),
    (r"(\.\./|\.\.\\|%2e%2e%2f)", "traversal", 25),
    (r"(/etc/passwd|boot\.ini)", "traversal", 30),
    (r"(\.\.;|%c0%ae)", "traversal", 25),
    (r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|bash|sh)\b", "rce", 55),
    (r"(admin|wp-admin|phpmyadmin|\.env|\.git/)", "probing", 15),
]


@dataclass
class ScoreResult:
    rule_score: float
    attack_type: str | None
    matched_patterns: list[str] = field(default_factory=list)


def rule_score_for(uri: str, body: str | None, modsec_score: float | None) -> ScoreResult:
    haystack = f"{uri} {body or ''}".lower()
    total = 0
    matched: list[str] = []
    by_type: dict[str, int] = {}
    for pattern, attack_type, weight in PATTERNS:
        if re.search(pattern, haystack):
            total += weight
            matched.append(pattern)
            by_type[attack_type] = by_type.get(attack_type, 0) + weight
    if modsec_score:
        # ModSecurity CRS anomaly score: each point is worth 6, capped at 40.
        total += min(int(modsec_score) * 6, 40)
    attack_type = max(by_type, key=by_type.get) if by_type else None
    return ScoreResult(rule_score=float(min(total, 100)), attack_type=attack_type, matched_patterns=matched)


def decide(risk_score: float) -> str:
    if risk_score >= settings.risk_block_threshold:
        return "block"
    if risk_score >= settings.risk_monitor_threshold:
        return "monitor"
    return "allow"
