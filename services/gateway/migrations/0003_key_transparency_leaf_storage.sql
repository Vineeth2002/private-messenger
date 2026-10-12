-- PostgreSQL 16. Retain exact signed TransparencyLeafV1 bytes alongside hash-only KT state.
-- Leaf bytes are storage data; the frozen PM-CBOR history entry remains unchanged.
BEGIN;

ALTER TABLE transparency_current_state
    ADD COLUMN leaf_cbor bytea NOT NULL,
    ADD CONSTRAINT transparency_current_state_leaf_cbor_length CHECK (octet_length(leaf_cbor) > 0);

ALTER TABLE transparency_history_entries
    ADD COLUMN leaf_cbor bytea NOT NULL,
    ADD CONSTRAINT transparency_history_entries_leaf_cbor_length CHECK (octet_length(leaf_cbor) > 0);

COMMIT;