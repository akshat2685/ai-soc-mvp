"""Centralized configuration for the memory platform. All values are env-driven."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache

try:
    # Optional: load a .env from project root if python-dotenv is installed.
    from dotenv import load_dotenv

    _PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))
    load_dotenv()  # also allow CWD .env
except Exception:
    pass


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class PostgresConfig:
    host: str = field(default_factory=lambda: _env("POSTGRES_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("POSTGRES_PORT", 5432))
    user: str = field(default_factory=lambda: _env("POSTGRES_USER", "soc"))
    password: str = field(default_factory=lambda: _env("POSTGRES_PASSWORD", "soc_secret"))
    db: str = field(default_factory=lambda: _env("POSTGRES_DB", "soc_memory"))

    @property
    def dsn(self) -> str:
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.db}"
        )


@dataclass(frozen=True)
class QdrantConfig:
    host: str = field(default_factory=lambda: _env("QDRANT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("QDRANT_PORT", 6333))
    prefix: str = field(default_factory=lambda: _env("QDRANT_COLLECTION_PREFIX", "soc"))

    def collection(self, name: str) -> str:
        return f"{self.prefix}_{name}"


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str = field(default_factory=lambda: _env("NEO4J_URI", "bolt://127.0.0.1:7687"))
    user: str = field(default_factory=lambda: _env("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: _env("NEO4J_PASSWORD", "soc_secret"))


@dataclass(frozen=True)
class EmbeddingsConfig:
    model_name: str = field(
        default_factory=lambda: _env(
            "EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
        )
    )
    dim: int = field(default_factory=lambda: _env_int("EMBEDDING_DIM", 384))
    # Cache the model locally so re-runs don't re-download.
    cache_dir: str = field(
        default_factory=lambda: os.path.join(
            os.path.dirname(__file__), "models_cache"
        )
    )


@dataclass(frozen=True)
class ScoringWeights:
    """importance = w_conf*confidence + w_trust*trust + w_recency*recency + w_usage*usage + w_impact*impact"""

    confidence: float = field(default_factory=lambda: _env_float("WEIGHT_CONFIDENCE", 0.30))
    trust: float = field(default_factory=lambda: _env_float("WEIGHT_TRUST", 0.20))
    recency: float = field(default_factory=lambda: _env_float("WEIGHT_RECENCY", 0.20))
    usage: float = field(default_factory=lambda: _env_float("WEIGHT_USAGE", 0.15))
    impact: float = field(default_factory=lambda: _env_float("WEIGHT_IMPACT", 0.15))

    @property
    def as_list(self) -> list[tuple[str, float]]:
        return [
            ("confidence", self.confidence),
            ("trust", self.trust),
            ("recency", self.recency),
            ("usage", self.usage),
            ("impact", self.impact),
        ]


@dataclass(frozen=True)
class Settings:
    postgres: PostgresConfig = field(default_factory=PostgresConfig)
    qdrant: QdrantConfig = field(default_factory=QdrantConfig)
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
    embeddings: EmbeddingsConfig = field(default_factory=EmbeddingsConfig)
    scoring: ScoringWeights = field(default_factory=ScoringWeights)

    soc_api_url: str = field(default_factory=lambda: _env("SOC_API_URL", "http://127.0.0.1:8000"))
    api_host: str = field(default_factory=lambda: _env("MEMORY_API_HOST", "127.0.0.1"))
    api_port: int = field(default_factory=lambda: _env_int("MEMORY_API_PORT", 8001))

    decay_half_life_days: int = field(default_factory=lambda: _env_int("DECAY_HALF_LIFE_DAYS", 90))
    context_token_budget: int = field(default_factory=lambda: _env_int("CONTEXT_TOKEN_BUDGET", 4000))

    @property
    def project_root(self) -> str:
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
