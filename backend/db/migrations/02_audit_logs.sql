-- EDYSOR Audit Logs Schema Migration
-- Creates the immutable audit_logs table for compliance-grade event logging.

-- Enable pgcrypto if not already enabled
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create audit_logs table (IMMUTABLE — no updates or deletes allowed)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,  -- 'success' or 'failure'
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    tenant_id VARCHAR(50) NOT NULL DEFAULT 'default',
    chain_hash VARCHAR(64) NOT NULL,  -- SHA-256 tamper-evident chain hash
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) WITH (fillfactor=90);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);

-- Immutability enforcement: No updates or deletes allowed on audit_logs
REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;

-- Create a dedicated app_user role if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user;
    END IF;
END
$$;

GRANT INSERT, SELECT ON audit_logs TO app_user;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO app_user;

-- Comment for documentation
COMMENT ON TABLE audit_logs IS 'Immutable audit trail for all EDYSOR operations — compliance grade (SOC2, ISO27001, GDPR)';
COMMENT ON COLUMN audit_logs.chain_hash IS 'SHA-256 hash linking to previous entry for tamper detection';
