#!/usr/bin/env bash
# ShieldNet WAF-level end-to-end checks — run against the live Docker stack.
#
#   docker compose up -d --build
#   bash tests/run_e2e.sh
#
# Expects: benign traffic reaches the target app through the WAF (200),
# attack payloads are blocked by ModSecurity CRS (403), and the ShieldNet
# custom simulation rule blocks its header case (403).
# NOTE: this script needs Docker and has not been run in CI — the analyzer
# battery (tests/test_attack_battery.py) is the automated suite.
set -u
WAF="${WAF_URL:-http://localhost:8080}"
pass=0; fail=0

check() { # name expected_status url [extra curl args...]
  local name="$1" expected="$2" url="$3"; shift 3
  local got
  got=$(curl -s -o /dev/null -w "%{http_code}" "$@" "$url")
  if [ "$got" = "$expected" ]; then
    echo "PASS  $name -> $got"; pass=$((pass+1))
  else
    echo "FAIL  $name -> got $got, expected $expected"; fail=$((fail+1))
  fi
}

check "benign home"            200 "$WAF/"
check "benign search"          200 "$WAF/search?q=coffee+mug"
check "sqli union select"      403 "$WAF/search?q=%27%20UNION%20SELECT%20username%2C%20password%20FROM%20users%20--"
check "xss script tag"         403 "$WAF/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
check "traversal etc passwd"   403 "$WAF/static/..%2f..%2fetc%2fpasswd"
check "custom simulation rule" 403 "$WAF/search" -H "X-Attack-Simulation: sqli"

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
