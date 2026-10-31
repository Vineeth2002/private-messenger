-- V1 lifecycle epoch domain: 1..=2^32-1 across every persisted account/device record.
-- This migration deliberately aborts if existing rows are outside the candidate V1 range.
-- Resolve those rows explicitly before applying; never truncate or cast them.
BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM accounts WHERE account_epoch < 1 OR account_epoch > 4294967295)
       OR EXISTS (SELECT 1 FROM devices WHERE account_epoch < 1 OR account_epoch > 4294967295)
       OR EXISTS (SELECT 1 FROM authorization_accounts WHERE epoch < 1 OR epoch > 4294967295)
       OR EXISTS (SELECT 1 FROM authorization_devices
                  WHERE authorized_epoch < 1 OR authorized_epoch > 4294967295
                     OR revoked_epoch < 0 OR revoked_epoch > 4294967295)
       OR EXISTS (SELECT 1 FROM authorization_events
                  WHERE old_epoch < 1 OR old_epoch > 4294967295
                     OR new_epoch < 1 OR new_epoch > 4294967295)
       OR EXISTS (SELECT 1 FROM device_enrollment_challenges
                  WHERE account_epoch < 1 OR account_epoch > 4294967295)
    THEN
        RAISE EXCEPTION 'V1 lifecycle epoch bound migration refused: out-of-range persisted epoch exists';
    END IF;
END
$$;

ALTER TABLE accounts
    ADD CONSTRAINT accounts_account_epoch_u32 CHECK (account_epoch BETWEEN 1 AND 4294967295);

ALTER TABLE devices
    ADD CONSTRAINT devices_account_epoch_u32 CHECK (account_epoch BETWEEN 1 AND 4294967295);

ALTER TABLE authorization_accounts
    ADD CONSTRAINT authorization_accounts_epoch_u32 CHECK (epoch BETWEEN 1 AND 4294967295);

ALTER TABLE authorization_devices
    ADD CONSTRAINT authorization_devices_authorized_epoch_u32
        CHECK (authorized_epoch BETWEEN 1 AND 4294967295),
    ADD CONSTRAINT authorization_devices_revoked_epoch_u32
        CHECK (revoked_epoch BETWEEN 0 AND 4294967295);

ALTER TABLE authorization_events
    ADD CONSTRAINT authorization_events_old_epoch_u32 CHECK (old_epoch BETWEEN 1 AND 4294967295),
    ADD CONSTRAINT authorization_events_new_epoch_u32 CHECK (new_epoch BETWEEN 1 AND 4294967295);

ALTER TABLE device_enrollment_challenges
    ADD CONSTRAINT device_enrollment_challenges_account_epoch_u32
        CHECK (account_epoch BETWEEN 1 AND 4294967295);

COMMIT;
