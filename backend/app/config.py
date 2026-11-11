from pydantic_settings import BaseSettings


def normalize_database_url(url: str) -> str:
    """Make hosted Postgres URLs work with the installed driver.

    Providers hand out postgres:// or postgresql:// URLs. Bare schemes let
    SQLAlchemy pick its default DBAPI — which changed to psycopg (v3) in
    newer SQLAlchemy, while this project installs psycopg2-binary. Pin the
    driver explicitly: postgresql+psycopg2://.
    """
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg2://" + url[len(prefix):]
    return url


class Settings(BaseSettings):
    # Overridden by DATABASE_URL env var (see .env.example / docker-compose).
    database_url: str = "postgresql://shieldnet:change-me-in-env@db:5432/shieldnet"
    risk_monitor_threshold: int = 40
    risk_block_threshold: int = 75


settings = Settings()
settings.database_url = normalize_database_url(settings.database_url)
