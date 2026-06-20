"""Apply schema migrations to PostgreSQL and Neo4j.

Usage (CLI):
    python -m backend.memory.migrations.apply
    python -m backend.memory.migrations.apply --reset   # DANGEROUS: drops & recreates

Safe to re-run: both SQL and Cypher files are written to be idempotent.
"""
from __future__ import annotations

import logging
import pathlib

from .. import connections

log = logging.getLogger(__name__)
HERE = pathlib.Path(__file__).parent
PG_SQL = HERE / "001_postgres.sql"
NEO4J_CYP = HERE / "002_neo4j.cyp"


def apply_postgres(reset: bool = False) -> dict:
    """Run the Postgres migration. Returns a small status dict."""
    if reset:
        log.warning("RESET requested — dropping all memory tables.")
        with connections.pg_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
            )
    sql = PG_SQL.read_text(encoding="utf-8")
    with connections.pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    log.info("Postgres migration applied (%d bytes).", len(sql))
    return {"applied": True, "reset": reset, "sql_path": str(PG_SQL)}


def apply_neo4j(reset: bool = False) -> dict:
    """Run the Neo4j Cypher migration. Returns a small status dict."""
    if reset:
        log.warning("RESET requested — wiping Neo4j graph.")
        with connections.get_neo4j().session() as s:
            s.run("MATCH (n) DETACH DELETE n").consume()
    cypher = NEO4J_CYP.read_text(encoding="utf-8")
    # Split on semicolons; Neo4j doesn't support multi-statement in one run().
    statements = [s.strip() for s in cypher.split(";") if s.strip() and not s.strip().startswith("//")]
    applied = 0
    with connections.get_neo4j().session() as s:
        for stmt in statements:
            # Strip trailing line comments inside the statement
            clean = "\n".join(
                line for line in stmt.splitlines() if not line.strip().startswith("//")
            ).strip()
            if not clean:
                continue
            try:
                s.run(clean).consume()
                applied += 1
            except Exception as e:
                log.error("Cypher failed: %s\n%s", e, clean[:200])
                raise
    log.info("Neo4j migration applied (%d statements).", applied)
    return {"applied": True, "reset": reset, "statements": applied}


def ensure_qdrant_collections() -> dict:
    """Create Qdrant collections (Layer 2) if they don't exist."""
    from ..config import get_settings
    from qdrant_client.http import models as qm

    cfg = get_settings()
    client = connections.get_qdrant()
    collections = [
        "incident_reports",
        "investigation_notes",
        "threat_reports",
        "lessons_learned",
        "playbooks",
        "analyst_notes",
    ]
    created = []
    for name in collections:
        cname = cfg.qdrant.collection(name)
        try:
            client.get_collection(cname)
        except Exception:
            client.recreate_collection(
                collection_name=cname,
                vectors_config=qm.VectorParams(
                    size=cfg.embeddings.dim, distance=qm.Distance.COSINE
                ),
            )
            created.append(cname)
    log.info("Qdrant collections ensured (%d newly created).", len(created))
    return {"ensured": collections, "created": created}


def apply_all(reset: bool = False) -> dict:
    """Run every migration step. Best-effort per backend; never aborts all."""
    results: dict = {}
    for name, fn in [
        ("postgres", lambda: apply_postgres(reset)),
        ("neo4j", lambda: apply_neo4j(reset)),
        ("qdrant", lambda: ensure_qdrant_collections()),
    ]:
        try:
            results[name] = fn()
        except Exception as e:
            log.error("Migration '%s' failed: %s", name, e)
            results[name] = {"applied": False, "error": str(e)}
    return results


if __name__ == "__main__":
    import argparse
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Apply memory-platform migrations")
    p.add_argument("--reset", action="store_true", help="Drop & recreate (destructive)")
    args = p.parse_args()
    out = apply_all(reset=args.reset)
    print(json.dumps(out, indent=2, default=str))
    sys.exit(0 if all(isinstance(v, dict) and v.get("applied") or v.get("ensured") for v in out.values()) else 1)
