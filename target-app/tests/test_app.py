import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app  # noqa: E402

client = app.test_client()


def test_home_ok():
    assert client.get("/").status_code == 200


def test_search_reflects_query():
    r = client.get("/search?q=mug")
    assert r.status_code == 200
    assert b"Coffee Mug" in r.data


def test_product_found_and_missing():
    assert client.get("/product?id=1").status_code == 200
    assert client.get("/product?id=99").status_code == 404


def test_login_demo_user():
    r = client.post("/login", data={"username": "demo", "password": "demo"})
    assert r.status_code == 200


def test_login_simulated_sqli():
    r = client.post("/login", data={"username": "admin", "password": "' OR '1'='1"})
    assert r.status_code == 200
    assert b"simulated SQL injection success" in r.data
