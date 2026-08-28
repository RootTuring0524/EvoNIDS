from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="EVONIDS_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "EvoNIDS API"
    environment: str = "development"
    database_url: str = "sqlite:///./evonids.db"
    auto_create_db: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    admin_api_token: SecretStr | None = None
    sensor_ingest_token: SecretStr | None = None
    dataset_root: str = "./datasets"
    model_artifact_root: str = "./model-artifacts"
    training_cpu_threads: int = 0


@lru_cache
def get_settings() -> Settings:
    return Settings()
