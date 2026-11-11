# Target app — demo shop (deliberately vulnerable)

A tiny Flask app that ShieldNet protects. It exists so the WAF has realistic
traffic and attack surface:

- `/` — home
- `/search?q=` — reflects the query **unescaped** (reflected-XSS demo)
- `/product?id=` — product page
- `/login` — simulated SQL-injectable login (no real database or users;
  `' OR '1'='1` "succeeds" by design, to prove the point when the WAF is off)

⚠️ **Never deploy this app on its own.** Its vulnerabilities are intentional
teaching aids and are only safe behind the ShieldNet WAF on a local/demo setup.

Run the tests: `pip install flask pytest && pytest` (5 tests).
In the stack it serves on port 5000, reachable only through the WAF on 8080.
