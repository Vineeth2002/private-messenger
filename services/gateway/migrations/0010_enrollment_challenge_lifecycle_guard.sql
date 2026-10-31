-- Enforce immutable enrollment challenge timestamps and one-way consumption.
-- Expiry and creation time are fixed at insertion. Consumption may transition
-- exactly once from NULL to a database-generated timestamp.
BEGIN;

CREATE FUNCTION device_enrollment_challenges_guard_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'enrollment challenge creation time is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'enrollment challenge expiry is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.consumed_at IS NOT NULL THEN
        IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
            RAISE EXCEPTION 'enrollment challenge consumption is irreversible'
                USING ERRCODE = '55000';
        END IF;
    ELSIF NEW.consumed_at IS NOT NULL THEN
        -- Callers cannot backdate consumption or choose its timestamp.
        NEW.consumed_at := clock_timestamp();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER device_enrollment_challenges_guard_lifecycle_trg
BEFORE UPDATE OF created_at, expires_at, consumed_at
ON device_enrollment_challenges
FOR EACH ROW
EXECUTE FUNCTION device_enrollment_challenges_guard_lifecycle();

COMMIT;