-- Persistent, single-use challenges for additional-device enrollment.
-- Only public protocol data and challenge lifecycle state are stored.
BEGIN;

CREATE TABLE device_enrollment_challenges (
    challenge_id    uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts(account_id),
    device_id       uuid NOT NULL,
    account_epoch   bigint NOT NULL CHECK (account_epoch >= 1),

    -- SHA-256 of the exact complete signed enrollment certificate bytes.
    enrollment_certificate_digest bytea NOT NULL
        CHECK (octet_length(enrollment_certificate_digest) = 32),

    -- Both fields are NULL for ordinary enrollment.
    -- Recovery enrollment binds to a finalized recovery request.
    recovery_request_id     uuid,
    recovery_request_digest bytea,

    challenge_nonce bytea NOT NULL
        CHECK (octet_length(challenge_nonce) = 32),

    created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,

    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),

    CHECK (
        (recovery_request_id IS NULL AND recovery_request_digest IS NULL)
        OR
        (
            recovery_request_id IS NOT NULL
            AND recovery_request_digest IS NOT NULL
            AND octet_length(recovery_request_digest) = 32
        )
    )
);

-- Challenge lookup by account, device, and expiry.
CREATE INDEX device_enrollment_challenges_lookup_idx
    ON device_enrollment_challenges
       (account_id, device_id, expires_at);

-- Find expired challenges, whether consumed or not.
CREATE INDEX device_enrollment_challenges_expiry_idx
    ON device_enrollment_challenges (expires_at);

-- Support cleanup of consumed challenges.
CREATE INDEX device_enrollment_challenges_consumed_cleanup_idx
    ON device_enrollment_challenges (consumed_at)
    WHERE consumed_at IS NOT NULL;

COMMIT;