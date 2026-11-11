import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "parse_audit_log",
    os.path.join(os.path.dirname(__file__), "..", "scripts", "parse_audit_log.py"),
)
parse_audit_log = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parse_audit_log)

SAMPLE_TX = {
    "transaction": {
        "client_ip": "203.0.113.7",
        "request": {
            "method": "GET",
            "uri": "/search?q=%27+UNION+SELECT+1--",
            "headers": {"Host": "localhost", "User-Agent": "curl/8.0"},
            "body": "",
        },
        "messages": [
            {"message": "SQL Injection Attack Detected via libinjection",
             "details": {"ruleId": "942100", "file": "REQUEST-942.conf"}},
            {"message": "SQL Tautology",
             "details": {"ruleId": "942140", "file": "REQUEST-942.conf"}},
        ],
    }
}


def test_transaction_to_payload_extracts_fields():
    p = parse_audit_log.transaction_to_payload(SAMPLE_TX)
    assert p["ip"] == "203.0.113.7"
    assert p["method"] == "GET"
    assert p["uri"].startswith("/search")
    assert p["modsec_rule_ids"] == ["942100", "942140"]
    assert p["modsec_score"] is None


def test_transaction_to_payload_handles_missing_messages():
    p = parse_audit_log.transaction_to_payload(
        {"transaction": {"request": {"method": "GET", "uri": "/"}}}
    )
    assert p["modsec_rule_ids"] == []
    assert p["uri"] == "/"
