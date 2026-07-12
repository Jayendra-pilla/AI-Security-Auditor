from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from pydantic import model_validator

class Settings(BaseSettings):
    APP_NAME: str = "AI Security Auditor"
    APP_HOST: str = "127.0.0.1"
    APP_PORT: int = 8000
    DEBUG: bool = True

    # PostgreSQL Configuration
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: str = "5432"
    POSTGRES_DB: str = "ai_security_auditor"

    # DATABASE_URL can be provided directly or constructed dynamically
    DATABASE_URL: Optional[str] = None

    # Security
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10
    ALLOW_PRIVATE_SCANS: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Gemini API
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # Observability
    LOG_LEVEL: str = "INFO"
    APP_VERSION: str = "1.0.0"
    ENABLE_REQUEST_LOGGING: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore"
    )

    @model_validator(mode="after")
    def assemble_db_connection(self) -> 'Settings':
        if not self.DATABASE_URL:
            from urllib.parse import quote_plus
            encoded_password = quote_plus(self.POSTGRES_PASSWORD)
            self.DATABASE_URL = f"postgresql+psycopg://{self.POSTGRES_USER}:{encoded_password}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        return self

settings = Settings()
