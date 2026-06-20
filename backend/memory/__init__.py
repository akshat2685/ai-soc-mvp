"""
AI SOC Memory Platform
======================
The long-term brain of the Security Operations Center.

A multi-layer memory subsystem that turns incidents, investigations, threat
intelligence, and analyst decisions into reusable, searchable, evolving
organizational knowledge.

Layers
------
Layer 1 — Structured Memory  (PostgreSQL) : incidents, assets, IOCs, playbooks...
Layer 2 — Semantic Memory    (Qdrant)     : reports, notes, lessons (vector search)
Layer 3 — Relationship Memory(Neo4j)      : users↔assets↔threats (blast radius)
Layer 4 — Temporal Memory    (versioning) : nothing is ever deleted
Layer 5 — Unified metadata   (scoring)    : confidence, trust, recency, usage, impact

This package is self-contained and additive: it talks to the existing SOC over
its HTTP API and never touches the SOC's own SQLite store.
"""

__version__ = "1.0.0"
