ALTER TABLE ipesign.ipesign_ledger_blocks
    ADD COLUMN IF NOT EXISTS occurred_at_canonical TEXT;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ipesign_ledger_canonical_timestamp_check'
          AND conrelid = 'ipesign.ipesign_ledger_blocks'::regclass
    ) THEN
        ALTER TABLE ipesign.ipesign_ledger_blocks
            ADD CONSTRAINT ipesign_ledger_canonical_timestamp_check
            CHECK (occurred_at_canonical IS NULL OR occurred_at_canonical <> '');
    END IF;
END
$migration$;

CREATE OR REPLACE FUNCTION ipesign.reject_ledger_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.occurred_at_canonical IS NULL
       AND NEW.occurred_at_canonical IS NOT NULL
       AND NEW.occurred_at_canonical <> ''
       AND ROW(
           NEW.block_index, NEW.prev_hash, NEW.block_hash, NEW.occurred_at,
           NEW.event_type, NEW.payload, NEW.cert_hash, NEW.record_id,
           NEW.payload_hash, NEW.ledger_signature
       ) IS NOT DISTINCT FROM ROW(
           OLD.block_index, OLD.prev_hash, OLD.block_hash, OLD.occurred_at,
           OLD.event_type, OLD.payload, OLD.cert_hash, OLD.record_id,
           OLD.payload_hash, OLD.ledger_signature
       ) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'IpeSign ledger rows are append-only';
END
$function$;

DROP TRIGGER IF EXISTS ipesign_ledger_append_only ON ipesign.ipesign_ledger_blocks;
CREATE TRIGGER ipesign_ledger_append_only
    BEFORE UPDATE OR DELETE ON ipesign.ipesign_ledger_blocks
    FOR EACH ROW
    EXECUTE FUNCTION ipesign.reject_ledger_mutation();

REVOKE ALL ON FUNCTION ipesign.reject_ledger_mutation() FROM PUBLIC;
