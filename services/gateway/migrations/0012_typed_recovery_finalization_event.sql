-- Make the existing recovery-finalization authorization row explicit and
-- protect the compatibility event table against ordinary mutation.
-- This is an incremental compatibility step; it is not the signed lifecycle
-- event journal/outbox described in docs/phase-c/02-lifecycle-to-ratchet-trust-boundary-v1.md.
BEGIN;

ALTER TABLE authorization_events
    RENAME COLUMN cert_cbor TO payload_cbor;

ALTER TABLE authorization_events
    DROP CONSTRAINT authorization_events_kind_check,
    ADD CONSTRAINT authorization_events_kind_check
        CHECK (kind IN ('ENROLL', 'TRANSITION', 'RECOVERY_FINALIZED'));

-- Backfill only legacy rows that exactly match a durable, finalized recovery
-- request. This preserves retry semantics for recoveries finalized before
-- migration 0012. Do not classify a generic TRANSITION by shape alone.
UPDATE authorization_events AS e
SET kind = 'RECOVERY_FINALIZED'
FROM account_recovery_requests AS r
WHERE e.kind = 'TRANSITION'
  AND r.status = 'FINALIZED'
  AND e.auth_digest = r.request_digest
  AND e.account_id = r.account_id
  AND e.old_epoch = r.old_epoch
  AND e.new_epoch = r.new_epoch
  AND e.target_device_id = r.target_device_id
  AND e.payload_cbor = r.request_cbor;

-- A finalized recovery must have exactly matching durable event evidence.
-- Fail the whole migration instead of silently leaving an inconsistent row
-- that would make an exact FinalizeRecovery retry fail after deployment.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM account_recovery_requests AS r
        WHERE r.status = 'FINALIZED'
          AND NOT EXISTS (
              SELECT 1
              FROM authorization_events AS e
              WHERE e.kind = 'RECOVERY_FINALIZED'
                AND e.auth_digest = r.request_digest
                AND e.account_id = r.account_id
                AND e.old_epoch = r.old_epoch
                AND e.new_epoch = r.new_epoch
                AND e.target_device_id = r.target_device_id
                AND e.payload_cbor = r.request_cbor
          )
    ) THEN
        RAISE EXCEPTION
            'migration 0012 refused: finalized recovery request lacks an exact matching authorization event';
    END IF;
END;
$$;

CREATE FUNCTION authorization_events_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authorization_events is append-only; % is prohibited', TG_OP
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER authorization_events_block_mutation_trg
BEFORE UPDATE OR DELETE ON authorization_events
FOR EACH ROW
EXECUTE FUNCTION authorization_events_reject_mutation();

CREATE TRIGGER authorization_events_block_truncate_trg
BEFORE TRUNCATE ON authorization_events
FOR EACH STATEMENT
EXECUTE FUNCTION authorization_events_reject_mutation();

COMMIT;
