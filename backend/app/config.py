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

    # --- Auth (JWT console login) ---
    # JWT_SECRET must be a long random value in production (Render env var).
    jwt_secret: str = "dev-only-secret-change-me-in-production"
    jwt_expire_minutes: int = 15
    refresh_token_days: int = 7
    # Seeded on first startup when no user exists; override via env.
    admin_email: str = "admin@shieldnet.io"
    admin_password: str = "shieldnet"
    # Refresh-cookie flags. Cross-site hosting (Vercel -> Render) needs
    # AUTH_COOKIE_SECURE=true and AUTH_COOKIE_SAMESITE=none; local http
    # development uses the defaults (lax / not secure).
    auth_cookie_secure: bool = False
    auth_cookie_samesite: str = "lax"
    # Shared key for machine clients (WAF audit pipeline) on /ingest and
    # /analyze, sent as the X-API-Key header. Empty = those endpoints are
    # open (local development default); set it in production.
    ingest_api_key: str = ""
    # Comma-separated browser origins allowed to call the API with
    # credentials (cookies). Credentialed CORS cannot use "*".
    cors_origins: str = "https://shieldnet-web.vercel.app,http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
settings.database_url = normalize_database_url(settings.database_url)
