-- Persistent one-time request nonces for PM-V1 per-device HTTP authentication.
-- A nonce remains reserved until its signed timestamp can no longer pass the
-- request-auth clock-skew check. No private key or message plaintext is stored.
BEGIN;

CREATE TABLE device_request_nonces (
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    device_id  uuid NOT NULL REFERENCES devices(device_id),
    nonce      bytea NOT NULL CHECK (octet_length(nonce) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (account_id, device_id, nonce),
    CHECK (expires_at > created_at)
);

CREATE INDEX device_request_nonces_expiry_idx
    ON device_request_nonces (expires_at);

COMMIT;
