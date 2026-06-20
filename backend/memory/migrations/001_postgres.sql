-- =============================================================================
-- AI SOC Memory Platform — Layer 1 (Structured Memory)
-- PostgreSQL schema. Idempotent: safe to re-run.
--
-- Design principles:
--   * Nothing is ever deleted — temporal memory comes from append-only
--     *_versions tables plus soft-delete / supersede semantics.
--   * Every domain table mirrors one of the 16 memory modules.
--   * `memory_objects` is the unified metadata table: scoring, decay, reference
--     counts and importance for ANY memory type live here (GraphRAG / retrieval
--     join through it).
--   * JSONB columns hold the flexible payload; columns hold the fields we query.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- fuzzy text search
CREATE EXTENSION IF NOT EXISTS "vector";     -- cosine similarity on vectors (optional mirror of Qdrant)

-- -----------------------------------------------------------------------------
-- Unified memory metadata (Layer 5)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_objects (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,                 -- MemoryType enum value
    ref_table       TEXT,                          -- domain table name (e.g. 'incidents')
    ref_id          TEXT,                          -- domain row id
    source          TEXT NOT NULL DEFAULT 'system',
    confidence      REAL NOT NULL DEFAULT 0.5,
    trust           REAL NOT NULL DEFAULT 0.5,
    recency         REAL NOT NULL DEFAULT 1.0,
    usage           REAL NOT NULL DEFAULT 0.0,
    impact          REAL NOT NULL DEFAULT 0.5,
    importance      REAL NOT NULL DEFAULT 0.5,     -- composite score
    reference_count INTEGER NOT NULL DEFAULT 0,
    is_persistent   BOOLEAN NOT NULL DEFAULT FALSE,-- bypass decay
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_accessed   TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags            TEXT[] NOT NULL DEFAULT '{}',
    search_text     TEXT,                          -- denormalized text for trigram + vector
    embedding       vector(384)                    -- optional mirror of Qdrant vector
);
CREATE INDEX IF NOT EXISTS idx_memory_type        ON memory_objects (type);
CREATE INDEX IF NOT EXISTS idx_memory_importance  ON memory_objects (importance DESC);
CREATE INDEX IF NOT EXISTS idx_memory_tags        ON memory_objects USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_memory_search_text ON memory_objects USING gin (search_text gin_trgm_ops);

-- -----------------------------------------------------------------------------
-- Layer 4: temporal versioning (every change to a memory object)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_versions (
    id            BIGSERIAL PRIMARY KEY,
    object_id     TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    changed_by    TEXT,
    change_reason TEXT,
    snapshot      JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (object_id, version)
);
CREATE INDEX IF NOT EXISTS idx_versions_object ON memory_versions (object_id, version DESC);

-- -----------------------------------------------------------------------------
-- Incidents (full history; nothing deleted)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                   TEXT PRIMARY KEY,
    severity             TEXT,
    confidence           REAL DEFAULT 0.5,
    alert_source         TEXT,
    attack_type          TEXT,
    mitre_mapping        TEXT,
    affected_assets      TEXT[] DEFAULT '{}',
    affected_users       TEXT[] DEFAULT '{}',
    investigation_summary TEXT,
    root_cause           TEXT,
    response_actions     JSONB DEFAULT '[]',
    resolution           TEXT,
    analyst_feedback     TEXT,
    verdict              TEXT DEFAULT 'PENDING',
    status               TEXT DEFAULT 'ACTIVE',
    correlation_key      TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inc_attack_type  ON incidents (attack_type);
CREATE INDEX IF NOT EXISTS idx_inc_severity     ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_inc_corr         ON incidents (correlation_key);
CREATE INDEX IF NOT EXISTS idx_inc_assets       ON incidents USING gin (affected_assets);
CREATE INDEX IF NOT EXISTS idx_inc_users        ON incidents USING gin (affected_users);

-- -----------------------------------------------------------------------------
-- Investigations
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigations (
    id                  TEXT PRIMARY KEY,
    incident_id         TEXT REFERENCES incidents(id) ON DELETE CASCADE,
    evidence            JSONB DEFAULT '[]',
    artifacts           JSONB DEFAULT '[]',
    logs                JSONB DEFAULT '[]',
    queries             JSONB DEFAULT '[]',
    reasoning_steps     JSONB DEFAULT '[]',
    conclusions         JSONB DEFAULT '[]',
    recommended_actions JSONB DEFAULT '[]',
    summary_text        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_incident ON investigations (incident_id);

-- -----------------------------------------------------------------------------
-- Threat intelligence (actors / campaigns / malware)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_actors (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    aliases       TEXT[] DEFAULT '{}',
    ttps          JSONB DEFAULT '[]',  -- MITRE ATT&CK techniques
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    frequency     INTEGER DEFAULT 1,
    confidence    REAL DEFAULT 0.5,
    source_reliability REAL DEFAULT 0.5,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS campaigns (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    threat_actor  TEXT,
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS malware_families (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    aliases       TEXT[] DEFAULT '{}',
    threat_actor  TEXT,
    techniques    JSONB DEFAULT '[]',
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- IOCs (with computed risk score)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id                   TEXT PRIMARY KEY,
    ioc_type             TEXT NOT NULL,   -- ip/domain/url/hash/email/registry_key/process
    value                TEXT NOT NULL,
    times_seen           INTEGER DEFAULT 1,
    incidents_linked     TEXT[] DEFAULT '{}',
    threat_actors_linked TEXT[] DEFAULT '{}',
    severity_history     JSONB DEFAULT '[]',
    resolution_history   JSONB DEFAULT '[]',
    risk_score           REAL DEFAULT 0.0,
    first_seen           TIMESTAMPTZ,
    last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_ioc_type_val ON iocs (ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_value     ON iocs (value);
CREATE INDEX IF NOT EXISTS idx_ioc_risk      ON iocs (risk_score DESC);

-- -----------------------------------------------------------------------------
-- Users (behavior baselines + drift)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_behavior (
    user_id                TEXT PRIMARY KEY,
    typical_login_hour_utc INTEGER,
    typical_location       TEXT,
    typical_devices        TEXT[] DEFAULT '{}',
    typical_apps           TEXT[] DEFAULT '{}',
    typical_activity_level REAL DEFAULT 0.5,   -- events/day baseline
    baseline               JSONB DEFAULT '{}',
    drift_score            REAL DEFAULT 0.0,
    last_seen              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Assets
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,  -- server/endpoint/db/app/container/cloud
    criticality     TEXT DEFAULT 'MEDIUM',
    owner           TEXT,
    vulnerabilities JSONB DEFAULT '[]',
    patch_history   JSONB DEFAULT '[]',
    incident_history TEXT[] DEFAULT '{}',
    risk_score      REAL DEFAULT 0.0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets (kind);

-- -----------------------------------------------------------------------------
-- Detections (rule quality: TP/FP/FN/coverage)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    id              TEXT PRIMARY KEY,
    rule_type       TEXT NOT NULL,  -- sigma/yara/custom/ml
    logic           TEXT,
    true_positives  INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    coverage        REAL DEFAULT 0.0,
    precision       REAL DEFAULT 0.0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Playbooks (SOAR)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS playbooks (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    steps             JSONB DEFAULT '[]',
    triggers          TEXT[] DEFAULT '{}',
    success_rate      REAL DEFAULT 0.0,
    failure_rate      REAL DEFAULT 0.0,
    avg_execution_sec REAL DEFAULT 0.0,
    executions        INTEGER DEFAULT 0,
    analyst_feedback  JSONB DEFAULT '[]',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pb_triggers ON playbooks USING gin (triggers);

-- -----------------------------------------------------------------------------
-- False positives + lessons learned
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS false_positives (
    id                   TEXT PRIMARY KEY,
    detection_trigger    TEXT,
    investigation_outcome TEXT,
    reason               TEXT,
    suppression_key      TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fp_suppkey ON false_positives (suppression_key);

CREATE TABLE IF NOT EXISTS lessons_learned (
    id              TEXT PRIMARY KEY,
    incident_id     TEXT,
    what_happened   TEXT,
    why_it_happened TEXT,
    what_worked     TEXT,
    what_failed     TEXT,
    recommendations JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ll_incident ON lessons_learned (incident_id);

-- -----------------------------------------------------------------------------
-- Attack graphs
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_graphs (
    id           TEXT PRIMARY KEY,
    incident_id  TEXT,
    nodes        JSONB DEFAULT '[]',
    edges        JSONB DEFAULT '[]',
    mermaid_code TEXT,
    summary      TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Agent decisions (AI agent self-improvement loop)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_decisions (
    id         TEXT PRIMARY KEY,
    agent_role TEXT NOT NULL,
    decision   TEXT NOT NULL,
    reasoning  TEXT,
    tool_calls JSONB DEFAULT '[]',
    outcome    TEXT,
    confidence REAL DEFAULT 0.5,
    success    BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_role ON agent_decisions (agent_role);

-- -----------------------------------------------------------------------------
-- Response actions (autonomous responses taken)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS response_actions (
    id          TEXT PRIMARY KEY,
    incident_id TEXT,
    action_type TEXT NOT NULL,
    target      TEXT,
    details     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_resp_incident ON response_actions (incident_id);

-- -----------------------------------------------------------------------------
-- updated_at auto-touch trigger helper (kept lightweight)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incidents_touch ON incidents;
CREATE TRIGGER trg_incidents_touch BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
