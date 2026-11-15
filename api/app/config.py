from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CHATGUARD_",
        env_file=".env",
        extra="ignore",
    )

    db_path: str = "chatguard.db"
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    trust_proxy_headers: bool = False


settings = Settings()


@lru_cache
def get_settings() -> Settings:
    return settings
