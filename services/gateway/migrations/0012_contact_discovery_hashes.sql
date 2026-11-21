-- Migration 0012: Privacy-preserving SHA-256 contact discovery table.
-- Stores only 64-char hex SHA-256 contact hashes and optional pairing codes; never plaintext contacts.

CREATE TABLE IF NOT EXISTS contact_discovery_entries (
    discovery_hash_hex CHAR(64) PRIMARY KEY,
    account_id UUID NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    pairing_code TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contact_discovery_account_id
    ON contact_discovery_entries (account_id);
