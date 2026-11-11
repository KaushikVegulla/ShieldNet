"""ShieldNet demo target application.

DELIBERATELY VULNERABLE — for WAF demonstration only.
- /search reflects the query unescaped (reflected XSS if reached directly)
- /login simulates a SQL-injectable login (no real database, no real users)

Never deploy this app publicly without the ShieldNet WAF in front of it,
and never reuse this code in a real product.
"""
from flask import Flask, request

app = Flask(__name__)

HOME = """
<h1>ShieldNet Demo Shop</h1>
<p>This deliberately simple app sits behind the ShieldNet WAF.</p>
<ul>
  <li><a href="/search">Search products</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/product?id=1">A product</a></li>
</ul>
"""

PRODUCTS = {1: "Cotton T-Shirt", 2: "Running Shoes", 3: "Coffee Mug"}


@app.get("/")
def home():
    return HOME


@app.get("/search")
def search():
    q = request.args.get("q", "")
    results = [name for name in PRODUCTS.values() if q.lower() in name.lower()] if q else []
    items = "".join(f"<li>{r}</li>" for r in results) or "<li>No results</li>"
    # NOTE: q is reflected unescaped on purpose (XSS demo behind the WAF).
    return f"<h2>Results for: {q}</h2><ul>{items}</ul>"


@app.get("/product")
def product():
    pid = request.args.get("id", "")
    name = PRODUCTS.get(int(pid)) if pid.isdigit() else None
    if name is None:
        return "<h2>Product not found</h2>", 404
    return f"<h2>{name}</h2><p>Product #{pid}</p>"


@app.get("/login")
def login_form():
    return """
    <h2>Login</h2>
    <form method="post">
      <input name="username" placeholder="username">
      <input name="password" type="password" placeholder="password">
      <button type="submit">Login</button>
    </form>
    """


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Simulated injectable query — string-built on purpose, no real DB behind it:
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    if "' or '1'='1" in password.lower() or "' or 1=1" in password.lower():
        return f"<h2>Welcome, admin (simulated SQL injection success)</h2><pre>{query}</pre>"
    if username == "demo" and password == "demo":
        return "<h2>Welcome, demo</h2>"
    return f"<h2>Login failed</h2><pre>{query}</pre>", 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
