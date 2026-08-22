DO $migration$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ipesign_runtime') THEN
        CREATE ROLE ipesign_runtime NOLOGIN NOINHERIT;
    END IF;
    EXECUTE format('GRANT ipesign_runtime TO %I', current_user);
END
$migration$;

DO $migration$
BEGIN
    IF to_regclass('ipesign.ipesign_state') IS NULL
       AND to_regclass('public.ipesign_state') IS NOT NULL THEN
        ALTER TABLE public.ipesign_state SET SCHEMA ipesign;
    END IF;
    IF to_regclass('ipesign.ipesign_ledger_blocks') IS NULL
       AND to_regclass('public.ipesign_ledger_blocks') IS NOT NULL THEN
        ALTER TABLE public.ipesign_ledger_blocks SET SCHEMA ipesign;
    END IF;
END
$migration$;

CREATE TABLE IF NOT EXISTS ipesign.ipesign_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    root_ca_cert_pem_b64 TEXT,
    root_ca_key_blob_b64 TEXT,
    ca_cert_pem_b64 TEXT NOT NULL,
    ca_key_pem_b64 TEXT,
    ca_key_blob_b64 TEXT NOT NULL,
    ledger_key_pem_b64 TEXT,
    ledger_key_blob_b64 TEXT NOT NULL,
    chain_snapshot_b64 TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS root_ca_cert_pem_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS root_ca_key_blob_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS ca_key_pem_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS ca_key_blob_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS ledger_key_pem_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS ledger_key_blob_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ADD COLUMN IF NOT EXISTS chain_snapshot_b64 TEXT;
ALTER TABLE ipesign.ipesign_state ALTER COLUMN chain_snapshot_b64 DROP NOT NULL;

CREATE TABLE IF NOT EXISTS ipesign.ipesign_ledger_blocks (
    block_index BIGINT PRIMARY KEY CHECK (block_index >= 0),
    prev_hash TEXT NOT NULL,
    block_hash TEXT NOT NULL UNIQUE CHECK (block_hash <> ''),
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type <> ''),
    payload BYTEA NOT NULL,
    cert_hash TEXT,
    record_id TEXT,
    payload_hash TEXT NOT NULL CHECK (payload_hash <> ''),
    ledger_signature TEXT NOT NULL CHECK (ledger_signature <> '')
);

DO $migration$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ipesign_ledger_event_type_check' AND conrelid = 'ipesign.ipesign_ledger_blocks'::regclass) THEN
        ALTER TABLE ipesign.ipesign_ledger_blocks
            ADD CONSTRAINT ipesign_ledger_event_type_check
            CHECK (event_type IN ('GENESIS', 'ISSUER_REGISTERED', 'CERTIFICATE_ISSUED', 'SIGNATURE_REGISTERED', 'CERTIFICATE_REVOKED', 'SIGNATURE_REVOKED'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ipesign_ledger_block_hash_check' AND conrelid = 'ipesign.ipesign_ledger_blocks'::regclass) THEN
        ALTER TABLE ipesign.ipesign_ledger_blocks
            ADD CONSTRAINT ipesign_ledger_block_hash_check CHECK (block_hash <> '');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ipesign_ledger_payload_hash_check' AND conrelid = 'ipesign.ipesign_ledger_blocks'::regclass) THEN
        ALTER TABLE ipesign.ipesign_ledger_blocks
            ADD CONSTRAINT ipesign_ledger_payload_hash_check CHECK (payload_hash <> '');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ipesign_ledger_signature_check' AND conrelid = 'ipesign.ipesign_ledger_blocks'::regclass) THEN
        ALTER TABLE ipesign.ipesign_ledger_blocks
            ADD CONSTRAINT ipesign_ledger_signature_check CHECK (ledger_signature <> '');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ipesign_ledger_event_fields_check' AND conrelid = 'ipesign.ipesign_ledger_blocks'::regclass) THEN
        ALTER TABLE ipesign.ipesign_ledger_blocks
            ADD CONSTRAINT ipesign_ledger_event_fields_check CHECK (
                (event_type <> 'CERTIFICATE_ISSUED' OR NULLIF(cert_hash, '') IS NOT NULL)
                AND
                (event_type <> 'SIGNATURE_REGISTERED' OR (NULLIF(cert_hash, '') IS NOT NULL AND NULLIF(record_id, '') IS NOT NULL))
            );
    END IF;
END
$migration$;

CREATE UNIQUE INDEX IF NOT EXISTS ipesign_ledger_certificate_hash_uidx
    ON ipesign.ipesign_ledger_blocks (cert_hash)
    WHERE event_type = 'CERTIFICATE_ISSUED';
CREATE UNIQUE INDEX IF NOT EXISTS ipesign_ledger_single_use_uidx
    ON ipesign.ipesign_ledger_blocks (cert_hash)
    WHERE event_type = 'SIGNATURE_REGISTERED';
CREATE UNIQUE INDEX IF NOT EXISTS ipesign_ledger_record_id_uidx
    ON ipesign.ipesign_ledger_blocks (record_id)
    WHERE event_type = 'SIGNATURE_REGISTERED';
CREATE INDEX IF NOT EXISTS ipesign_ledger_event_type_idx
    ON ipesign.ipesign_ledger_blocks (event_type, block_index);

CREATE OR REPLACE FUNCTION ipesign.reject_ledger_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION 'IpeSign ledger rows are append-only';
END
$function$;

DROP TRIGGER IF EXISTS ipesign_ledger_append_only ON ipesign.ipesign_ledger_blocks;
CREATE TRIGGER ipesign_ledger_append_only
    BEFORE UPDATE OR DELETE ON ipesign.ipesign_ledger_blocks
    FOR EACH STATEMENT
    EXECUTE FUNCTION ipesign.reject_ledger_mutation();

REVOKE ALL ON FUNCTION ipesign.reject_ledger_mutation() FROM PUBLIC;

ALTER TABLE ipesign.ipesign_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipesign.ipesign_state FORCE ROW LEVEL SECURITY;
ALTER TABLE ipesign.ipesign_ledger_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipesign.ipesign_ledger_blocks FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ipesign_state_runtime_policy ON ipesign.ipesign_state;
CREATE POLICY ipesign_state_runtime_policy ON ipesign.ipesign_state
    FOR ALL TO ipesign_runtime
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS ipesign_ledger_runtime_select ON ipesign.ipesign_ledger_blocks;
CREATE POLICY ipesign_ledger_runtime_select ON ipesign.ipesign_ledger_blocks
    FOR SELECT TO ipesign_runtime
    USING (true);

DROP POLICY IF EXISTS ipesign_ledger_runtime_insert ON ipesign.ipesign_ledger_blocks;
CREATE POLICY ipesign_ledger_runtime_insert ON ipesign.ipesign_ledger_blocks
    FOR INSERT TO ipesign_runtime
    WITH CHECK (true);

REVOKE ALL ON SCHEMA ipesign FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ipesign FROM PUBLIC;
GRANT USAGE ON SCHEMA ipesign TO ipesign_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE ipesign.ipesign_state TO ipesign_runtime;
GRANT SELECT, INSERT ON TABLE ipesign.ipesign_ledger_blocks TO ipesign_runtime;

DO $migration$
DECLARE
    exposed_role TEXT;
BEGIN
    FOREACH exposed_role IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = exposed_role) THEN
            EXECUTE format('REVOKE ALL ON SCHEMA ipesign FROM %I', exposed_role);
            EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA ipesign FROM %I', exposed_role);
        END IF;
    END LOOP;
END
$migration$;

ALTER DEFAULT PRIVILEGES IN SCHEMA ipesign REVOKE ALL ON TABLES FROM PUBLIC;
