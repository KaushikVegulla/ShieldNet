from app.config import normalize_database_url


def test_postgres_scheme_is_normalized():
    assert normalize_database_url("postgres://u:p@host:5432/db") == "postgresql+psycopg2://u:p@host:5432/db"


def test_postgresql_scheme_gets_psycopg2_driver():
    # Regression test for the Render deploy failure: bare postgresql:// let
    # SQLAlchemy default to the psycopg (v3) driver, which is not installed.
    assert normalize_database_url("postgresql://u:p@host/db") == "postgresql+psycopg2://u:p@host/db"


def test_other_urls_untouched():
    assert normalize_database_url("postgresql+psycopg2://u:p@host/db") == "postgresql+psycopg2://u:p@host/db"
    assert normalize_database_url("sqlite:///./x.db") == "sqlite:///./x.db"
