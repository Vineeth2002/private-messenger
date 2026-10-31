-- Durable 48-hour recovery request lifecycle for PM-V1.
-- Stores signed public protocol bytes and terminal outcome metadata only.
-- No private keys, recovery secrets, or message plaintext are stored here.
BEGIN;

CREATE TABLE account_recovery_requests (
    request_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(account_id),

    -- SHA-256 and exact bytes of the signed RecoveryRequestV1.
    request_digest bytea NOT NULL UNIQUE
        CHECK (octet_length(request_digest) = 32),
    request_cbor bytea NOT NULL
        CHECK (octet_length(request_cbor) > 0),

    old_epoch bigint NOT NULL
        CHECK (old_epoch BETWEEN 1 AND 4294967294),
    new_epoch bigint NOT NULL
        CHECK (new_epoch BETWEEN 2 AND 4294967295),
    target_device_id uuid NOT NULL,
    enrollment_certificate_digest bytea NOT NULL
        CHECK (octet_length(enrollment_certificate_digest) = 32),

    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ABORTED', 'FINALIZED')),

    -- Set by the database trigger. The deadline is exactly 48 elapsed hours
    -- after accepted_at; clients cannot choose or shorten this interval.
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finalize_after timestamptz NOT NULL
        DEFAULT (clock_timestamp() + INTERVAL '172800 seconds'),

    -- Populated only for the ABORTED terminal outcome.
    aborted_at timestamptz,
    aborting_device_id uuid,
    abort_digest bytea UNIQUE,
    abort_cbor bytea,

    -- Populated only for the FINALIZED terminal outcome.
    finalized_at timestamptz,

    CONSTRAINT account_recovery_requests_epoch_step_ck
        CHECK (new_epoch = old_epoch + 1),

    CONSTRAINT account_recovery_requests_deadline_ck
        CHECK (finalize_after > accepted_at),

    CONSTRAINT account_recovery_requests_abort_time_ck
        CHECK (
            aborted_at IS NULL
            OR (aborted_at >= accepted_at AND aborted_at < finalize_after)
        ),

    CONSTRAINT account_recovery_requests_finalize_time_ck
        CHECK (
            finalized_at IS NULL
            OR finalized_at >= finalize_after
        ),

    CONSTRAINT account_recovery_requests_outcome_shape_ck
        CHECK (
            (
                status = 'PENDING'
                AND aborted_at IS NULL
                AND aborting_device_id IS NULL
                AND abort_digest IS NULL
                AND abort_cbor IS NULL
                AND finalized_at IS NULL
            )
            OR
            (
                status = 'ABORTED'
                AND aborted_at IS NOT NULL
                AND aborting_device_id IS NOT NULL
                AND abort_digest IS NOT NULL
                AND octet_length(abort_digest) = 32
                AND abort_cbor IS NOT NULL
                AND octet_length(abort_cbor) > 0
                AND finalized_at IS NULL
            )
            OR
            (
                status = 'FINALIZED'
                AND aborted_at IS NULL
                AND aborting_device_id IS NULL
                AND abort_digest IS NULL
                AND abort_cbor IS NULL
                AND finalized_at IS NOT NULL
            )
        ),

    -- The challenge table references this exact account/request/digest tuple.
    CONSTRAINT account_recovery_requests_account_request_digest_uq
        UNIQUE (account_id, request_id, request_digest),

    CONSTRAINT account_recovery_requests_request_id_nonzero_ck
        CHECK (request_id <> '00000000-0000-0000-0000-000000000000'::uuid),

    CONSTRAINT account_recovery_requests_target_device_nonzero_ck
        CHECK (target_device_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

-- Only one recovery request may be pending for an account at a time.
CREATE UNIQUE INDEX account_recovery_requests_one_pending_per_account_idx
    ON account_recovery_requests (account_id)
    WHERE status = 'PENDING';

-- Worker discovery. This index contains pending requests only.
CREATE INDEX account_recovery_requests_due_idx
    ON account_recovery_requests (finalize_after, account_id, request_id)
    WHERE status = 'PENDING';

-- The database, not an API caller, decides when the 48-hour clock starts.
CREATE FUNCTION account_recovery_requests_set_deadline()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM 'PENDING'
       OR NEW.aborted_at IS NOT NULL
       OR NEW.aborting_device_id IS NOT NULL
       OR NEW.abort_digest IS NOT NULL
       OR NEW.abort_cbor IS NOT NULL
       OR NEW.finalized_at IS NOT NULL
    THEN
        RAISE EXCEPTION 'recovery requests must be inserted as PENDING'
            USING ERRCODE = '23514';
    END IF;

    NEW.accepted_at := clock_timestamp();
    NEW.finalize_after := NEW.accepted_at + INTERVAL '172800 seconds';
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_requests_set_deadline_trg
BEFORE INSERT ON account_recovery_requests
FOR EACH ROW
EXECUTE FUNCTION account_recovery_requests_set_deadline();

-- Request identity and signed payload are immutable. A PENDING request may
-- transition once to ABORTED or FINALIZED; terminal rows cannot be updated.
CREATE FUNCTION account_recovery_requests_guard_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now timestamptz;
BEGIN
    IF OLD.status <> 'PENDING' THEN
        RAISE EXCEPTION 'terminal recovery request outcomes are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.account_id IS DISTINCT FROM OLD.account_id
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.request_cbor IS DISTINCT FROM OLD.request_cbor
       OR NEW.old_epoch IS DISTINCT FROM OLD.old_epoch
       OR NEW.new_epoch IS DISTINCT FROM OLD.new_epoch
       OR NEW.target_device_id IS DISTINCT FROM OLD.target_device_id
       OR NEW.enrollment_certificate_digest IS DISTINCT FROM OLD.enrollment_certificate_digest
       OR NEW.accepted_at IS DISTINCT FROM OLD.accepted_at
       OR NEW.finalize_after IS DISTINCT FROM OLD.finalize_after
    THEN
        RAISE EXCEPTION 'recovery request identity and signed payload are immutable'
            USING ERRCODE = '55000';
    END IF;

    -- The database clock, not caller-supplied timestamps, decides which
    -- terminal outcome is permitted. The UPDATE already holds this row lock.
    database_now := clock_timestamp();

    IF NEW.status = 'ABORTED' THEN
        IF database_now >= OLD.finalize_after THEN
            RAISE EXCEPTION 'recovery abort window has closed'
                USING ERRCODE = '55000';
        END IF;
        NEW.aborted_at := database_now;
        NEW.finalized_at := NULL;
    ELSIF NEW.status = 'FINALIZED' THEN
        IF database_now < OLD.finalize_after THEN
            RAISE EXCEPTION 'recovery request is not yet eligible for finalization'
                USING ERRCODE = '55000';
        END IF;
        NEW.finalized_at := database_now;
        NEW.aborted_at := NULL;
        NEW.aborting_device_id := NULL;
        NEW.abort_digest := NULL;
        NEW.abort_cbor := NULL;
    ELSE
        RAISE EXCEPTION 'pending recovery request may only become ABORTED or FINALIZED'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_requests_guard_update_trg
BEFORE UPDATE ON account_recovery_requests
FOR EACH ROW
EXECUTE FUNCTION account_recovery_requests_guard_update();

-- Recovery audit records must not be deleted or truncated. Terminal outcomes
-- remain durable even when no enrollment challenge has yet referenced them.
CREATE FUNCTION account_recovery_requests_block_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'recovery request records cannot be deleted or truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER account_recovery_requests_block_delete_trg
BEFORE DELETE ON account_recovery_requests
FOR EACH ROW
EXECUTE FUNCTION account_recovery_requests_block_delete();

CREATE TRIGGER account_recovery_requests_block_truncate_trg
BEFORE TRUNCATE ON account_recovery_requests
FOR EACH STATEMENT
EXECUTE FUNCTION account_recovery_requests_block_delete();

-- A recovery challenge must reference the exact finalized request, target
-- device, epoch, and enrollment-certificate digest. Ordinary enrollment keeps
-- both recovery_request_id and recovery_request_digest NULL.
ALTER TABLE device_enrollment_challenges
    ADD CONSTRAINT device_enrollment_challenges_recovery_request_fk
    FOREIGN KEY (account_id, recovery_request_id, recovery_request_digest)
    REFERENCES account_recovery_requests (account_id, request_id, request_digest);

CREATE FUNCTION device_enrollment_challenges_require_finalized_recovery()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request_status text;
    request_target_device_id uuid;
    request_new_epoch bigint;
    request_enrollment_digest bytea;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.challenge_id IS DISTINCT FROM OLD.challenge_id
           OR NEW.account_id IS DISTINCT FROM OLD.account_id
           OR NEW.device_id IS DISTINCT FROM OLD.device_id
           OR NEW.account_epoch IS DISTINCT FROM OLD.account_epoch
           OR NEW.enrollment_certificate_digest IS DISTINCT FROM OLD.enrollment_certificate_digest
           OR NEW.challenge_nonce IS DISTINCT FROM OLD.challenge_nonce
           OR NEW.recovery_request_id IS DISTINCT FROM OLD.recovery_request_id
           OR NEW.recovery_request_digest IS DISTINCT FROM OLD.recovery_request_digest
        THEN
            RAISE EXCEPTION 'enrollment challenge identity and recovery binding are immutable'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    IF NEW.recovery_request_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT r.status, r.target_device_id, r.new_epoch,
           r.enrollment_certificate_digest
      INTO request_status, request_target_device_id, request_new_epoch,
           request_enrollment_digest
      FROM account_recovery_requests r
     WHERE r.account_id = NEW.account_id
       AND r.request_id = NEW.recovery_request_id
       AND r.request_digest = NEW.recovery_request_digest;

    IF NOT FOUND
       OR request_status <> 'FINALIZED'
       OR request_target_device_id <> NEW.device_id
       OR request_new_epoch <> NEW.account_epoch
       OR request_enrollment_digest <> NEW.enrollment_certificate_digest
    THEN
        RAISE EXCEPTION 'recovery enrollment challenge is not bound to a finalized request'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER device_enrollment_challenges_require_finalized_recovery_trg
BEFORE INSERT OR UPDATE ON device_enrollment_challenges
FOR EACH ROW
EXECUTE FUNCTION device_enrollment_challenges_require_finalized_recovery();

COMMIT;
