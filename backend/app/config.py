from pydantic_settings import BaseSettings


def normalize_database_url(url: str) -> str:
    """Hosted Postgres providers often hand out postgres:// URLs, but
    SQLAlchemy 2 requires the postgresql:// scheme."""
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


class Settings(BaseSettings):
    # Overridden by DATABASE_URL env var (see .env.example / docker-compose).
    database_url: str = "postgresql://shieldnet:change-me-in-env@db:5432/shieldnet"
    risk_monitor_threshold: int = 40
    risk_block_threshold: int = 75


settings = Settings()
settings.database_url = normalize_database_url(settings.database_url)
