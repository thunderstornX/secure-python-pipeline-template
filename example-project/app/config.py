from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "SecurePipelineExample"
    debug: bool = False
    database_url: str = "sqlite:///./example.db"
    # HMAC key used by the demo bearer-token signer; sourced from the
    # SECRET_KEY environment variable in production. The placeholder default
    # is intentionally non-secret -- never deploy with this value.
    secret_key: str = "change-me-via-SECRET_KEY-env-var"
    bcrypt_rounds: int = 12


settings = Settings()
