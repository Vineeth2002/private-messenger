-- PostgreSQL 16. KT V1 node state used to derive the frozen SMT and
-- append-only history proofs. This migration introduces storage only; it does
-- not change any PM-CBOR wire object or cryptographic rule.
BEGIN;

CREATE TABLE transparency_current_state (
    smt_key      bytea PRIMARY KEY,
    leaf_hash    bytea NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(smt_key) = 32),
    CHECK (octet_length(leaf_hash) = 32)
);

CREATE TABLE transparency_history_entries (
    sequence     bigint PRIMARY KEY,
    smt_key      bytea NOT NULL,
    leaf_hash    bytea NOT NULL,
    entry_cbor   bytea NOT NULL,
    published_at timestamptz NOT NULL DEFAULT now(),
    CHECK (sequence >= 1),
    CHECK (octet_length(smt_key) = 32),
    CHECK (octet_length(leaf_hash) = 32),
    CHECK (octet_length(entry_cbor) > 0)
);

CREATE INDEX transparency_history_entries_smt_key_idx
    ON transparency_history_entries (smt_key, sequence);

COMMIT;
