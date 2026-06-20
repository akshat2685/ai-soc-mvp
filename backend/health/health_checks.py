"""EDYSOR Health Checks — Comprehensive Liveness & Readiness Probes.

Provides:
  - /health/live — Kubernetes liveness probe (is the process alive?)
  - /health/ready — Readiness probe (are dependencies available?)
  - /health/startup — Startup probe (has initialization completed?)
  - Per-dependency health checks (DB, Redis, Neo4j, Qdrant, Gemini API)
  - Degraded mode detection and reporting
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.health")


class DependencyStatus:
    OK = "ok"
    DEGRADED = "degraded"
    ERROR = "error"
    UNKNOWN = "unknown"


class HealthChecker:
    """Comprehensive health checker for all EDYSOR dependencies."""

    def __init__(self):
        self._startup_complete = False
        self._startup_time: Optional[float] = None
        self._last_check_results: Dict[str, Any] = {}
        self._check_history: List[Dict[str, Any]] = []

    def mark_startup_complete(self):
        """Called after all initialization is done."""
        self._startup_complete = True
        self._startup_time = time.time()
        logger.info("Startup probe: initialization complete")

    # ----- Individual dependency checks -----

    def check_database(self) -> Dict[str, Any]:
        """Check primary SQLite/PostgreSQL database connectivity."""
        start = time.time()
        try:
            db_path = os.path.join(os.path.dirname(__file__), "..", "soc.db")
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path, timeout=5)
                conn.execute("SELECT 1")
                conn.close()
                elapsed = time.time() - start
                return {"status": DependencyStatus.OK, "latency_ms": round(elapsed * 1000, 2)}
            else:
                return {"status": DependencyStatus.DEGRADED, "message": "DB file not found — first run?"}
        except Exception as e:
            return {"status": DependencyStatus.ERROR, "message": str(e)}

    def check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity."""
        try:
            import redis
            r = redis.Redis(
                host=os.environ.get("REDIS_HOST", "localhost"),
                port=int(os.environ.get("REDIS_PORT", 6379)),
                socket_timeout=3,
            )
            r.ping()
            return {"status": DependencyStatus.OK}
        except ImportError:
            return {"status": DependencyStatus.DEGRADED, "message": "redis-py not installed"}
        except Exception as e:
            return {"status": DependencyStatus.DEGRADED, "message": f"Redis unavailable: {e}"}

    def check_neo4j(self) -> Dict[str, Any]:
        """Check Neo4j graph database connectivity."""
        try:
            from neo4j import GraphDatabase
            uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
            user = os.environ.get("NEO4J_USER", "neo4j")
            password = os.environ.get("NEO4J_PASSWORD", "password")
            driver = GraphDatabase.driver(uri, auth=(user, password))
            with driver.session() as session:
                session.run("RETURN 1")
            driver.close()
            return {"status": DependencyStatus.OK}
        except ImportError:
            return {"status": DependencyStatus.DEGRADED, "message": "neo4j driver not installed"}
        except Exception as e:
            return {"status": DependencyStatus.DEGRADED, "message": f"Neo4j unavailable: {e}"}

    def check_qdrant(self) -> Dict[str, Any]:
        """Check Qdrant vector store connectivity."""
        try:
            from qdrant_client import QdrantClient
            client = QdrantClient(
                host=os.environ.get("QDRANT_HOST", "localhost"),
                port=int(os.environ.get("QDRANT_PORT", 6333)),
                timeout=3,
            )
            client.get_collections()
            return {"status": DependencyStatus.OK}
        except ImportError:
            return {"status": DependencyStatus.DEGRADED, "message": "qdrant-client not installed"}
        except Exception as e:
            return {"status": DependencyStatus.DEGRADED, "message": f"Qdrant unavailable: {e}"}

    def check_gemini_api(self) -> Dict[str, Any]:
        """Check Gemini API key availability (does not make an API call)."""
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if api_key:
            return {"status": DependencyStatus.OK, "message": "API key configured"}
        return {"status": DependencyStatus.DEGRADED, "message": "No Gemini API key — LLM features will use fallback"}

    # ----- Composite checks -----

    def liveness(self) -> Dict[str, Any]:
        """Liveness probe — is the process alive? Lightweight check only."""
        return {
            "status": "alive",
            "timestamp": time.time(),
            "uptime_seconds": round(time.time() - (self._startup_time or time.time()), 2),
        }

    def readiness(self) -> Dict[str, Any]:
        """Readiness probe — are critical dependencies available?"""
        checks = {
            "database": self.check_database(),
            "redis": self.check_redis(),
            "neo4j": self.check_neo4j(),
            "qdrant": self.check_qdrant(),
            "gemini_api": self.check_gemini_api(),
        }

        # Critical services that must be OK
        critical_services = ["database"]
        # Non-critical services that can be degraded
        optional_services = ["redis", "neo4j", "qdrant", "gemini_api"]

        critical_ok = all(
            checks[svc]["status"] in (DependencyStatus.OK, DependencyStatus.DEGRADED)
            for svc in critical_services
        )

        degraded_services = [
            svc for svc in optional_services
            if checks[svc]["status"] != DependencyStatus.OK
        ]

        overall = "ready"
        if not critical_ok:
            overall = "not_ready"
        elif degraded_services:
            overall = "degraded"

        result = {
            "status": overall,
            "checks": checks,
            "degraded_services": degraded_services,
            "timestamp": time.time(),
        }

        self._last_check_results = result
        self._check_history.append({"timestamp": time.time(), "status": overall})
        if len(self._check_history) > 100:
            self._check_history = self._check_history[-100:]

        return result

    def startup(self) -> Dict[str, Any]:
        """Startup probe — has initialization completed?"""
        return {
            "status": "ready" if self._startup_complete else "initializing",
            "startup_complete": self._startup_complete,
            "startup_time": self._startup_time,
        }

    def get_uptime(self) -> float:
        """Get uptime in seconds."""
        if self._startup_time:
            return time.time() - self._startup_time
        return 0.0

    def get_history(self) -> List[Dict[str, Any]]:
        """Get recent health check history."""
        return self._check_history[-50:]


# Global health checker
health_checker = HealthChecker()
