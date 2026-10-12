package kt

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

// TransparencyStateStore persists the mutable current-state SMT leaves and the
// immutable append-only history entries used to generate KT V1 proofs.
type TransparencyStateStore interface {
	UpsertCurrentState(ctx context.Context, leaf SMTLeaf, leafRaw []byte) error
	AppendHistoryEntry(ctx context.Context, raw []byte, leafRaw []byte) error
	CurrentState(ctx context.Context) ([]SMTLeaf, error)
	HistoryEntries(ctx context.Context) ([][]byte, error)
}

// TransparencyStatePublisher is the write boundary for an atomic KT V1
// publication. Callers publishing new state should use PublishState rather
// than issuing the current-state and history writes separately.
type TransparencyStatePublisher interface {
	PublishState(ctx context.Context, leaf SMTLeaf, leafRaw []byte, raw []byte) error
}

// PostgresTransparencyStateStore is the PostgreSQL persistence boundary for
// KT V1 tree state. The exact PM-CBOR history entry bytes are retained.
type PostgresTransparencyStateStore struct {
	db SQLExecutor
}

var (
	ErrTransparencyHistoryConflict     = errors.New("conflicting history entry already published at sequence")
	ErrTransparencyHistoryRollback     = errors.New("history sequence is below persisted high water")
	ErrTransparencyHistoryGap          = errors.New("history sequence skips a persisted publication sequence")
	ErrTransparencyStateNotFound       = errors.New("current transparency state not found")
	ErrTransparencyPublicationMismatch = errors.New("history entry does not match current-state leaf")
	ErrTransparencyLeafMismatch        = errors.New("signed transparency leaf does not match current-state leaf")
)

func NewPostgresTransparencyStateStore(db SQLExecutor) *PostgresTransparencyStateStore {
	return &PostgresTransparencyStateStore{db: db}
}

const upsertCurrentTransparencyStateSQL = `
INSERT INTO transparency_current_state (smt_key, leaf_hash, leaf_cbor)
VALUES ($1, $2, $3)
ON CONFLICT (smt_key) DO UPDATE
SET leaf_hash = EXCLUDED.leaf_hash,
    leaf_cbor = EXCLUDED.leaf_cbor,
    updated_at = now()`

const selectCurrentTransparencyStateSQL = `
SELECT smt_key, leaf_hash
FROM transparency_current_state
ORDER BY smt_key ASC`

const selectCurrentTransparencyStateAtKeySQL = `
SELECT leaf_hash
FROM transparency_current_state
WHERE smt_key = $1`

const selectHistoryEntriesSQL = `
SELECT sequence, smt_key, leaf_hash, entry_cbor
FROM transparency_history_entries
ORDER BY sequence ASC`

// This transaction-scoped advisory lock serializes publication-sequence
// allocation without changing the frozen KT wire protocol.
const lockTransparencyHistoryPublicationSQL = `SELECT pg_advisory_xact_lock($1)`
const maxTransparencyHistorySequenceSQL = `SELECT COALESCE(MAX(sequence), 0) FROM transparency_history_entries`
const selectTransparencyHistoryAtSequenceSQL = `
SELECT smt_key, leaf_hash, entry_cbor, leaf_cbor
FROM transparency_history_entries
WHERE sequence = $1`
const insertTransparencyHistoryEntrySQL = `
INSERT INTO transparency_history_entries (sequence, smt_key, leaf_hash, entry_cbor, leaf_cbor)
VALUES ($1, $2, $3, $4, $5)`

const transparencyHistoryLockKey int64 = 7143534259781

func (s *PostgresTransparencyStateStore) UpsertCurrentState(ctx context.Context, leaf SMTLeaf, leafRaw []byte) error {
	if s == nil || s.db == nil {
		return errors.New("nil transparency state store")
	}
	if err := validatePublishedTransparencyLeaf(leaf, leafRaw); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, upsertCurrentTransparencyStateSQL, leaf.Key[:], leaf.LeafHash[:], leafRaw)
	return err
}

func validatePublishedTransparencyLeaf(leaf SMTLeaf, leafRaw []byte) error {
	if len(leafRaw) == 0 {
		return errors.New("empty signed transparency leaf")
	}
	parsed, leafHash, err := VerifyTransparencyLeafV1(leafRaw)
	if err != nil {
		return fmt.Errorf("invalid signed transparency leaf: %w", err)
	}
	if SMTKey(parsed.AccountID, parsed.DeviceID) != leaf.Key || leafHash != leaf.LeafHash {
		return ErrTransparencyLeafMismatch
	}
	return nil
}

// PublishState atomically publishes one new immutable history entry and the
// corresponding current-state SMT leaf. Both writes occur in the same
// PostgreSQL transaction, so a partial publication cannot leave the two trees
// describing different states.
//
// Retries of an already-published sequence are idempotent only when the exact
// history bytes and their parsed fields match. Retries never rewrite the
// current-state leaf, which prevents an older history publication from
// rolling the SMT backwards.
func (s *PostgresTransparencyStateStore) PublishState(ctx context.Context, leaf SMTLeaf, leafRaw []byte, raw []byte) error {
	if s == nil || s.db == nil {
		return errors.New("nil transparency state store")
	}
	entry, err := ParseHistoryEntryV1(raw)
	if err != nil {
		return fmt.Errorf("invalid history entry: %w", err)
	}
	if entry.Sequence == 0 || entry.Sequence > math.MaxInt64 {
		return errors.New("history sequence outside PostgreSQL bigint")
	}
	if entry.SMTKey != leaf.Key || entry.LeafHash != leaf.LeafHash {
		return ErrTransparencyPublicationMismatch
	}
	if err := validatePublishedTransparencyLeaf(leaf, leafRaw); err != nil {
		return err
	}

	beginner, ok := s.db.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return errors.New("transparency store requires transactional PostgreSQL handle for publication")
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, lockTransparencyHistoryPublicationSQL, transparencyHistoryLockKey); err != nil {
		return err
	}

	var maxSeq int64
	if err := tx.QueryRowContext(ctx, maxTransparencyHistorySequenceSQL).Scan(&maxSeq); err != nil {
		return err
	}
	if maxSeq < 0 {
		return errors.New("negative persisted history sequence")
	}

	wanted := int64(entry.Sequence)
	if wanted <= maxSeq {
		var storedKey, storedLeaf, storedRaw, storedLeafCbor []byte
		err := tx.QueryRowContext(ctx, selectTransparencyHistoryAtSequenceSQL, wanted).Scan(
			&storedKey,
			&storedLeaf,
			&storedRaw,
			&storedLeafCbor,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTransparencyHistoryRollback
		}
		if err != nil {
			return err
		}
		if !transparencyBytesEqual(storedRaw, raw) ||
			!transparencyBytesEqual(storedKey, entry.SMTKey[:]) ||
			!transparencyBytesEqual(storedLeaf, entry.LeafHash[:]) ||
			!transparencyBytesEqual(storedLeafCbor, leafRaw) {
			return ErrTransparencyHistoryConflict
		}

		var currentLeaf []byte
		err = tx.QueryRowContext(ctx, selectCurrentTransparencyStateAtKeySQL, leaf.Key[:]).Scan(&currentLeaf)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTransparencyStateNotFound
		}
		if err != nil {
			return err
		}
		if len(currentLeaf) != 32 {
			return errors.New("invalid persisted current-state hash length")
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	}

	if wanted != maxSeq+1 {
		return ErrTransparencyHistoryGap
	}

	if _, err := tx.ExecContext(ctx, upsertCurrentTransparencyStateSQL, leaf.Key[:], leaf.LeafHash[:], leafRaw); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		insertTransparencyHistoryEntrySQL,
		wanted,
		entry.SMTKey[:],
		entry.LeafHash[:],
		raw,
		leafRaw,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *PostgresTransparencyStateStore) AppendHistoryEntry(ctx context.Context, raw []byte, leafRaw []byte) error {
	if s == nil || s.db == nil {
		return errors.New("nil transparency state store")
	}
	entry, err := ParseHistoryEntryV1(raw)
	if err != nil {
		return fmt.Errorf("invalid history entry: %w", err)
	}
	if entry.Sequence == 0 || entry.Sequence > math.MaxInt64 {
		return errors.New("history sequence outside PostgreSQL bigint")
	}
	historyLeaf := SMTLeaf{Key: entry.SMTKey, LeafHash: entry.LeafHash}
	if err := validatePublishedTransparencyLeaf(historyLeaf, leafRaw); err != nil {
		return err
	}

	beginner, ok := s.db.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return errors.New("transparency store requires transactional PostgreSQL handle for history publication")
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, lockTransparencyHistoryPublicationSQL, transparencyHistoryLockKey); err != nil {
		return err
	}

	var maxSeq int64
	if err := tx.QueryRowContext(ctx, maxTransparencyHistorySequenceSQL).Scan(&maxSeq); err != nil {
		return err
	}
	if maxSeq < 0 {
		return errors.New("negative persisted history sequence")
	}

	wanted := int64(entry.Sequence)
	if wanted <= maxSeq {
		var storedKey, storedLeaf, storedRaw, storedLeafCbor []byte
		err := tx.QueryRowContext(ctx, selectTransparencyHistoryAtSequenceSQL, wanted).Scan(
			&storedKey,
			&storedLeaf,
			&storedRaw,
			&storedLeafCbor,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTransparencyHistoryRollback
		}
		if err != nil {
			return err
		}
		if !transparencyBytesEqual(storedRaw, raw) ||
			!transparencyBytesEqual(storedKey, entry.SMTKey[:]) ||
			!transparencyBytesEqual(storedLeaf, entry.LeafHash[:]) ||
			!transparencyBytesEqual(storedLeafCbor, leafRaw) {
			return ErrTransparencyHistoryConflict
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	}

	if wanted != maxSeq+1 {
		return ErrTransparencyHistoryGap
	}
	if _, err := tx.ExecContext(
		ctx,
		insertTransparencyHistoryEntrySQL,
		wanted,
		entry.SMTKey[:],
		entry.LeafHash[:],
		raw,
		leafRaw,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *PostgresTransparencyStateStore) CurrentState(ctx context.Context) ([]SMTLeaf, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("nil transparency state store")
	}
	queryer, ok := s.db.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	})
	if !ok {
		return nil, errors.New("transparency store requires query-capable PostgreSQL handle")
	}
	rows, err := queryer.QueryContext(ctx, selectCurrentTransparencyStateSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SMTLeaf
	for rows.Next() {
		var key, leaf []byte
		if err := rows.Scan(&key, &leaf); err != nil {
			return nil, err
		}
		if len(key) != 32 || len(leaf) != 32 {
			return nil, errors.New("invalid persisted current-state hash length")
		}
		var item SMTLeaf
		copy(item.Key[:], key)
		copy(item.LeafHash[:], leaf)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresTransparencyStateStore) HistoryEntries(ctx context.Context) ([][]byte, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("nil transparency state store")
	}
	queryer, ok := s.db.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	})
	if !ok {
		return nil, errors.New("transparency store requires query-capable PostgreSQL handle")
	}
	rows, err := queryer.QueryContext(ctx, selectHistoryEntriesSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out [][]byte
	var expected int64 = 1
	for rows.Next() {
		var sequence int64
		var key, leaf, raw []byte
		if err := rows.Scan(&sequence, &key, &leaf, &raw); err != nil {
			return nil, err
		}
		if sequence != expected || sequence <= 0 {
			return nil, errors.New("persisted history sequence is not contiguous")
		}
		if len(key) != 32 || len(leaf) != 32 || len(raw) == 0 {
			return nil, errors.New("invalid persisted history row")
		}
		entry, err := ParseHistoryEntryV1(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid persisted history entry: %w", err)
		}
		if entry.Sequence != uint64(sequence) || !transparencyBytesEqual(entry.SMTKey[:], key) || !transparencyBytesEqual(entry.LeafHash[:], leaf) {
			return nil, errors.New("persisted history columns do not match entry bytes")
		}
		out = append(out, append([]byte(nil), raw...))
		expected++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func transparencyBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
