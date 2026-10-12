-- PostgreSQL 16. Account/device authorization state is separate from KT history.
-- It binds to the existing accounts/devices tables and never stores private keys.
BEGIN;

CREATE TABLE authorization_accounts (
    account_id          uuid PRIMARY KEY REFERENCES accounts(account_id),
    epoch               bigint NOT NULL CHECK (epoch >= 1),
    recovery_commitment bytea NOT NULL CHECK (octet_length(recovery_commitment) = 32),
    recovery_pub        bytea NOT NULL CHECK (octet_length(recovery_pub) = 32),
    status              smallint NOT NULL CHECK (status IN (1,2)),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE authorization_devices (
    device_id              uuid PRIMARY KEY REFERENCES devices(device_id),
    account_id             uuid NOT NULL REFERENCES accounts(account_id),
    dsk_pub                bytea NOT NULL CHECK (octet_length(dsk_pub) = 32),
    ddhk_pub               bytea NOT NULL CHECK (octet_length(ddhk_pub) = 32),
    status                 smallint NOT NULL CHECK (status IN (1,2)),
    authorized_epoch       bigint NOT NULL CHECK (authorized_epoch >= 1),
    enrollment_auth_digest bytea NOT NULL CHECK (octet_length(enrollment_auth_digest) = 32),
    revoked_epoch          bigint NOT NULL DEFAULT 0 CHECK (revoked_epoch >= 0),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX authorization_devices_account_status_idx
    ON authorization_devices(account_id, status);

CREATE TABLE authorization_events (
    auth_digest       bytea PRIMARY KEY CHECK (octet_length(auth_digest) = 32),
    kind              text NOT NULL CHECK (kind IN ('ENROLL','TRANSITION')),
    account_id        uuid NOT NULL REFERENCES accounts(account_id),
    old_epoch         bigint NOT NULL CHECK (old_epoch >= 1),
    new_epoch         bigint NOT NULL CHECK (new_epoch >= 1),
    target_device_id  uuid NOT NULL,
    cert_cbor         bytea NOT NULL,
    applied_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE(kind, account_id, old_epoch, new_epoch, target_device_id)
);

COMMIT;
