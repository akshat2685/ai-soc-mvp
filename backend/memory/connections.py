"""Lazy singleton connections to the three backing stores + unified health check.

Each backend is created on first use, so importing this module never fails even
if the databases are offline. The memory platform degrades gracefully: a downed
store simply reports unhealthy and queries that need it return empty results
rather than crashing the whole service.
"""
from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Any

from .config import get_settings

log = logging.getLogger(__name__)
_settings = get_settings()

# ---------------------------------------------------------------------------
# PostgreSQL (Layer 1)
# ---------------------------------------------------------------------------
_pg_lock = threading.Lock()
_pg_pool: Any = None


def get_postgres():
    """Return a shared psycopg connection pool (created lazily)."""
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    with _pg_lock:
        if _pg_pool is not None:
            return _pg_pool
        try:
            from psycopg_pool import ConnectionPool

            _pg_pool = ConnectionPool(
                conninfo=_settings.postgres.dsn,
                min_size=1,
                max_size=8,
                open=True,
                timeout=10,
            )
            log.info("PostgreSQL pool opened -> %s:%s", _settings.postgres.host, _settings.postgres.port)
        except Exception as e:
            log.error("PostgreSQL unavailable: %s", e)
            _pg_pool = None
            raise
    return _pg_pool


@contextmanager
def pg_conn():
    """Context manager yielding a psycopg connection from the pool."""
    pool = get_postgres()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


# ---------------------------------------------------------------------------
# Qdrant (Layer 2)
# ---------------------------------------------------------------------------
_qdrant_lock = threading.Lock()
_qdrant: Any = None


def get_qdrant():
    global _qdrant
    if _qdrant is not None:
        return _qdrant
    with _qdrant_lock:
        if _qdrant is not None:
            return _qdrant
        try:
            from qdrant_client import QdrantClient

            _qdrant = QdrantClient(
                host=_settings.qdrant.host,
                port=_settings.qdrant.port,
                timeout=10,
            )
            log.info("Qdrant client opened -> %s:%s", _settings.qdrant.host, _settings.qdrant.port)
        except Exception as e:
            log.error("Qdrant unavailable: %s", e)
            _qdrant = None
            raise
    return _qdrant


# ---------------------------------------------------------------------------
# Neo4j (Layer 3)
# ---------------------------------------------------------------------------
_neo4j_lock = threading.Lock()
_neo4j: Any = None


def get_neo4j():
    global _neo4j
    if _neo4j is not None:
        return _neo4j
    with _neo4j_lock:
        if _neo4j is not None:
            return _neo4j
        try:
            from neo4j import GraphDatabase

            driver = GraphDatabase.driver(
                _settings.neo4j.uri,
                auth=(_settings.neo4j.user, _settings.neo4j.password),
            )
            driver.verify_connectivity()
            _neo4j = driver
            log.info("Neo4j driver opened -> %s", _settings.neo4j.uri)
        except Exception as e:
            log.error("Neo4j unavailable: %s", e)
            _neo4j = None
            raise
    return _neo4j


# ---------------------------------------------------------------------------
# Unified health check
# ---------------------------------------------------------------------------
def _check_pg() -> tuple[bool, str]:
    try:
        with pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def _check_qdrant() -> tuple[bool, str]:
    try:
        get_qdrant().get_collections()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def _check_neo4j() -> tuple[bool, str]:
    try:
        with get_neo4j().session() as s:
            s.run("RETURN 1").consume()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def health() -> dict[str, Any]:
    """Probe every backend. Never raises — used by the /memory/health endpoint."""
    checks = {"postgres": _check_pg, "qdrant": _check_qdrant, "neo4j": _check_neo4j}
    result: dict[str, Any] = {}
    all_ok = True
    for name, fn in checks.items():
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, str(e)
        result[name] = {"healthy": ok, "detail": detail}
        if not ok:
            all_ok = False
    result["overall"] = "healthy" if all_ok else "degraded"
    return result


def close_all() -> None:
    """Tear down all connections (used on shutdown / tests)."""
    global _pg_pool, _qdrant, _neo4j
    if _pg_pool is not None:
        try:
            _pg_pool.close()
        except Exception:
            pass
        _pg_pool = None
    if _qdrant is not None:
        try:
            _qdrant.close()
        except Exception:
            pass
        _qdrant = None
    if _neo4j is not None:
        try:
            _neo4j.close()
        except Exception:
            pass
        _neo4j = None
