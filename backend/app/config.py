"""
Backend Configuration Settings
Supports SQLite for lightweight zero-dependency local dev/tests, and PostgreSQL for staging/prod.
"""
import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    PROJECT_NAME: str = "SIH26148 JOCKY Forensic Framework"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./jocky_forensics.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev_secret_key_change_in_production_jocky_2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    AGENT_REGISTRATION_TOKEN: str = os.getenv("AGENT_REGISTRATION_TOKEN", "jocky-agent-enrollment-secret-2026")
    EVIDENCE_STORAGE_DIR: str = "./evidence_storage"
    REPORTS_STORAGE_DIR: str = "./reports_output"

settings = Settings()
