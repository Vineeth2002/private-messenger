-- PostgreSQL 16. Persistent application data; target hosting: India.
-- INVARIANT: no private identity keys, ratchet state, message keys, media keys, push
-- private keys or recovery private keys are ever stored here (public material,
-- commitments and ciphertext only). Redis is ephemeral and never holds crypto state.
BEGIN;

CREATE TABLE accounts (
    account_id        uuid PRIMARY KEY,
    username          text NOT NULL UNIQUE,
    account_epoch     bigint NOT NULL DEFAULT 1 CHECK (account_epoch >= 1),
    irc               bytea NOT NULL CHECK (octet_length(irc) = 32),  -- Identity Recovery Commitment (SHA-256)
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    device_id         uuid PRIMARY KEY,
    account_id        uuid NOT NULL REFERENCES accounts(account_id),
    account_epoch     bigint NOT NULL,
    dsk_pub           bytea NOT NULL CHECK (octet_length(dsk_pub) = 32),   -- Ed25519 public
    ddhk_pub          bytea NOT NULL CHECK (octet_length(ddhk_pub) = 32),  -- X25519 public (separate key pair)
    push_pub          bytea,                                                -- HPKE recipient PUBLIC key only
    revoked_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_certificates (
    device_id         uuid NOT NULL REFERENCES devices(device_id),
    cert_cbor         bytea NOT NULL,        -- PM-CBOR-2026 binding structure (signed)
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, created_at)
);

CREATE TABLE signed_prekeys (
    device_id         uuid NOT NULL REFERENCES devices(device_id),
    spk_id            bigint NOT NULL,
    spk_pub           bytea NOT NULL CHECK (octet_length(spk_pub) = 32),
    signature         bytea NOT NULL CHECK (octet_length(signature) = 64),
    PRIMARY KEY (device_id, spk_id)
);

CREATE TABLE one_time_prekeys (
    device_id         uuid NOT NULL REFERENCES devices(device_id),
    opk_id            bigint NOT NULL,
    opk_pub           bytea NOT NULL CHECK (octet_length(opk_pub) = 32),
    consumed_at       timestamptz,
    PRIMARY KEY (device_id, opk_id)
);

CREATE TABLE message_envelopes (
    envelope_id       uuid PRIMARY KEY,
    recipient_device  uuid NOT NULL REFERENCES devices(device_id),
    envelope_cbor     bytea NOT NULL,        -- opaque ciphertext envelope; server never decrypts
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL
);
CREATE INDEX message_envelopes_recipient_idx ON message_envelopes (recipient_device, created_at);

CREATE TABLE delivery_acks (
    envelope_id       uuid PRIMARY KEY,
    acked_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE media_upload_sessions (
    media_id          uuid PRIMARY KEY,      -- allocated BEFORE encryption (bound into chunk AAD)
    owner_device      uuid NOT NULL REFERENCES devices(device_id),
    size_bucket_bytes bigint NOT NULL,
    state             text NOT NULL CHECK (state IN ('open','complete','expired')),
    expires_at        timestamptz NOT NULL
);

CREATE TABLE notification_state (
    device_id         uuid PRIMARY KEY REFERENCES devices(device_id),
    last_notification uuid,                  -- push is a wake-up hint only; no authorization weight
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE transparency_state (
    tree_size         bigint PRIMARY KEY,
    signed_tree_head  bytea NOT NULL,
    published_at      timestamptz NOT NULL DEFAULT now()
);

COMMIT;
