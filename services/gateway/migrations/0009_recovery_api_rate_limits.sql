-- Shared, privacy-preserving fixed-window rate limits for recovery API peers.
-- Client addresses are HMACed by the gateway; raw IP addresses are not stored.
BEGIN;

CREATE TABLE recovery_api_rate_limits (
    client_key_hash bytea PRIMARY KEY
        CHECK (octet_length(client_key_hash) = 32),
    window_started_at timestamptz NOT NULL,
    request_count integer NOT NULL
        CHECK (request_count > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX recovery_api_rate_limits_updated_at_idx
    ON recovery_api_rate_limits (updated_at);

COMMIT;
