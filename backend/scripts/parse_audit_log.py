"""Ship ModSecurity audit-log transactions to the ShieldNet backend.

Reads a ModSecurity audit log in JSON format (MODSEC_AUDIT_LOG_FORMAT=JSON)
— either one JSON object per line or a file of concatenated objects — and
POSTs each transaction to the backend's /ingest endpoint, where it lands in
the request_logs table as logging / ML training data.

Usage:
    python scripts/parse_audit_log.py /var/log/modsec_audit.log \
        --backend http://localhost:8000
"""
import argparse
import json
import os
import urllib.request


def transaction_to_payload(tx: dict) -> dict:
    """Convert one ModSecurity audit transaction to a backend RequestIn payload."""
    transaction = tx.get("transaction", tx)
    request = transaction.get("request", {})
    headers = request.get("headers", {}) or {}
    # ModSecurity JSON headers can be dict or list of {name, value}
    if isinstance(headers, list):
        headers = {h.get("name", ""): h.get("value", "") for h in headers}

    rule_ids: list[str] = []
    for message in transaction.get("messages", []) or []:
        details = message.get("details", {}) or {}
        rule_id = details.get("ruleId")
        if rule_id:
            rule_ids.append(str(rule_id))

    body = (request.get("body") or "")[:2000]
    return {
        "ip": transaction.get("client_ip"),
        "method": request.get("method", "GET"),
        "uri": request.get("uri", "/"),
        "headers": headers,
        "body": body or None,
        "modsec_rule_ids": rule_ids,
        # Per-message CRS scores aren't in the audit log; the backend's
        # /analyze can re-score. Leave None rather than inventing a number.
        "modsec_score": None,
    }


def load_transactions(path: str) -> list[dict]:
    transactions = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                transactions.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip partial / non-JSON lines (e.g. native format)
    return transactions


def post_payload(backend: str, payload: dict, api_key: str = "") -> int:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(
        f"{backend.rstrip('/')}/ingest",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (own backend URL)
        return resp.status


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_log", help="Path to the ModSecurity JSON audit log")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--api-key", default=os.environ.get("SHIELDNET_API_KEY", ""),
                        help="X-API-Key for backends with INGEST_API_KEY set (or env SHIELDNET_API_KEY)")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads, don't POST")
    args = parser.parse_args()

    transactions = load_transactions(args.audit_log)
    sent = 0
    for tx in transactions:
        payload = transaction_to_payload(tx)
        if args.dry_run:
            print(json.dumps(payload))
        else:
            post_payload(args.backend, payload, args.api_key)
        sent += 1
    print(f"{sent} transaction(s) processed")


if __name__ == "__main__":
    main()
