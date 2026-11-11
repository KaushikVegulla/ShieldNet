from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Overridden by DATABASE_URL env var (see .env.example / docker-compose).
    database_url: str = "postgresql://shieldnet:change-me-in-env@db:5432/shieldnet"
    risk_monitor_threshold: int = 40
    risk_block_threshold: int = 75


settings = Settings()
