-- Enable the pgcrypto extension in PostgreSQL for built-in symmetric encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Example of creating a table supporting database-level column encryption
-- (Symmetric PGP encryption using a secret key fetched from Vault or config)
CREATE TABLE IF NOT EXISTS soar_integration_configs_encrypted (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) DEFAULT 'default',
    integration_name VARCHAR(100) NOT NULL,
    
    -- config_data is stored as bytea (binary data) to hold the encrypted output
    config_data BYTEA NOT NULL,
    
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, integration_name)
);

-- Example trigger and encryption function
CREATE OR REPLACE FUNCTION encrypt_soar_config()
RETURNS TRIGGER AS $$
DECLARE
    encryption_key TEXT;
BEGIN
    -- Retrieve encryption key set in the database session configuration (e.g. SET app.encryption_key = '...')
    encryption_key := current_setting('app.encryption_key', true);
    
    IF encryption_key IS NULL OR encryption_key = '' THEN
        RAISE EXCEPTION 'Database encryption key is not set in session. Cannot encrypt configuration.';
    END IF;
    
    -- Encrypt value using pgp_sym_encrypt and convert text data
    NEW.config_data := pgp_sym_encrypt(NEW.config_data::text, encryption_key);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger before INSERT or UPDATE
-- CREATE TRIGGER encrypt_soar_config_trigger
-- BEFORE INSERT OR UPDATE ON soar_integration_configs_encrypted
-- FOR EACH ROW EXECUTE FUNCTION encrypt_soar_config();
