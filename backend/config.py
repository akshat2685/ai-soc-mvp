from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    """
    Centralized 12-Factor App Configuration.
    Validates all critical environment variables on startup.
    """
    
    # Core Application
    APP_ENV: str = "development"
    DEBUG: bool = APP_ENV == "development"
    
    # AI Engine
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    
    # Databases
    POSTGRES_URL: str = "sqlite:///soc.db" # Defaulting to local sqlite for dev
    REDIS_URL: str = "redis://localhost:6379"
    
    # Security & JWT
    JWT_SECRET: str = "change_me_in_production"
    JWT_EXPIRE_MINUTES: int = 480 # 8 hours
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_CAPACITY: int = 100
    RATE_LIMIT_REFILL_RATE: float = 10.0
    
    # Observability
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# Post-load validation for strict environments
if settings.APP_ENV == "production":
    if not settings.GEMINI_API_KEY:
        raise ValueError("[CONFIG] GEMINI_API_KEY is required in production!")
    if settings.JWT_SECRET == "change_me_in_production":
        raise ValueError("[CONFIG] JWT_SECRET must be securely set in production!")
    if settings.POSTGRES_URL.startswith("sqlite"):
        raise ValueError("[CONFIG] Production cannot use SQLite databases!")
