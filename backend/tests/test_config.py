from app.config import normalize_database_url


def test_postgres_scheme_is_normalized():
    assert normalize_database_url("postgres://u:p@host:5432/db") == "postgresql://u:p@host:5432/db"


def test_other_urls_untouched():
    assert normalize_database_url("postgresql://u:p@host/db") == "postgresql://u:p@host/db"
    assert normalize_database_url("sqlite:///./x.db") == "sqlite:///./x.db"
