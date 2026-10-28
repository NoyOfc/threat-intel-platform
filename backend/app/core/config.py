from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Backend configuration, read from environment variables (and `.env` if present).

    Provider API keys are SecretStr so they never appear in reprs, logs, or tracebacks.
    They are backend-only and must never be sent to the frontend.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ThreatScope API"
    environment: str = "development"
    demo_mode: bool = True
    database_url: str = "sqlite:///./data/threatscope.db"

    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
