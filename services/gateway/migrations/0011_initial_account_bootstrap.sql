-- First-account bootstrap challenges are deliberately independent of accounts:
-- the account row is created only after a valid device proof is accepted.
BEGIN;
CREATE TABLE initial_account_bootstrap_challenges (
    challenge_id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    device_id uuid NOT NULL,
    account_epoch bigint NOT NULL CHECK (account_epoch = 1),
    enrollment_certificate_digest bytea NOT NULL CHECK (octet_length(enrollment_certificate_digest)=32),
    recovery_commitment bytea NOT NULL CHECK (octet_length(recovery_commitment)=32),
    recovery_pub bytea NOT NULL CHECK (octet_length(recovery_pub)=32),
    challenge_nonce bytea NOT NULL CHECK (octet_length(challenge_nonce)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX initial_account_bootstrap_lookup_idx
 ON initial_account_bootstrap_challenges(account_id, device_id, expires_at);
CREATE INDEX initial_account_bootstrap_expiry_idx
 ON initial_account_bootstrap_challenges(expires_at);
CREATE INDEX initial_account_bootstrap_consumed_idx
 ON initial_account_bootstrap_challenges(consumed_at) WHERE consumed_at IS NOT NULL;
CREATE FUNCTION initial_account_bootstrap_guard_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.device_id IS DISTINCT FROM OLD.device_id OR
    NEW.account_epoch IS DISTINCT FROM OLD.account_epoch OR
    NEW.enrollment_certificate_digest IS DISTINCT FROM OLD.enrollment_certificate_digest OR
    NEW.recovery_commitment IS DISTINCT FROM OLD.recovery_commitment OR
    NEW.recovery_pub IS DISTINCT FROM OLD.recovery_pub OR NEW.challenge_nonce IS DISTINCT FROM OLD.challenge_nonce OR
    NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
   RAISE EXCEPTION 'initial account bootstrap challenge fields are immutable' USING ERRCODE='55000';
 END IF;
 IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
   RAISE EXCEPTION 'initial account bootstrap challenge consumption is irreversible' USING ERRCODE='55000';
 ELSIF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL THEN
   NEW.consumed_at := clock_timestamp();
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER initial_account_bootstrap_guard_lifecycle_trg
 BEFORE UPDATE ON initial_account_bootstrap_challenges
 FOR EACH ROW EXECUTE FUNCTION initial_account_bootstrap_guard_lifecycle();
COMMIT;
