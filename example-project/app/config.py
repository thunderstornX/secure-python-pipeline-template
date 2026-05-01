from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "SecurePipelineExample"
    debug: bool = False
    database_url: str = "sqlite:///./example.db"
    # Secret used to seed PBKDF2; loaded from environment, never hardcoded.
    secret_key: str = "change-me-via-SECRET_KEY-env-var"
    bcrypt_rounds: int = 12


settings = Settings()
