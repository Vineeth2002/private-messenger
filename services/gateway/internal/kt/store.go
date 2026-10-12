package kt

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

var (
	ErrSTHConflict = errors.New("conflicting STH already published at tree size")
	ErrSTHRollback = errors.New("STH tree size is below the persisted high water")
	ErrSTHNotFound = errors.New("no STH has been published")
)

// STHRecord is the persisted representation of one exact signed tree head.
// SignedTreeHead is retained as the original PM-CBOR byte string; no JSON or
// Go-specific protocol representation is introduced at the persistence boundary.
type STHRecord struct {
	TreeSize       uint64
	SignedTreeHead []byte
	PublishedAt    time.Time
}

type rowScanner interface {
	Scan(dest ...any) error
}

// SQLExecutor is implemented by *sql.DB and *sql.Tx. Keeping the database
// dependency this small makes the KT store independently testable without a
// second SQL mocking dependency.
type SQLExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// PostgresSTHStore persists signed tree heads in the existing
// transparency_state table from migrations/0001_init.sql.
//
// Publication is monotonic with respect to the currently persisted maximum:
// a lower unseen tree size is rejected, the same tree size is idempotent only
// when the exact STH bytes match, and a different STH at the same tree size is
// retained as a security-relevant conflict rather than overwritten.
type PostgresSTHStore struct {
	db SQLExecutor
}

func NewPostgresSTHStore(db SQLExecutor) *PostgresSTHStore {
	return &PostgresSTHStore{db: db}
}

const insertSTHIfCurrentHighWaterAllows = `
INSERT INTO transparency_state (tree_size, signed_tree_head, published_at)
SELECT $1, $2, $3
WHERE NOT EXISTS (
    SELECT 1
    FROM transparency_state
    WHERE tree_size > $1
)
ON CONFLICT (tree_size) DO NOTHING`

const selectSTHAtSize = `
SELECT tree_size, signed_tree_head, published_at
FROM transparency_state
WHERE tree_size = $1`

const selectLatestSTH = `
SELECT tree_size, signed_tree_head, published_at
FROM transparency_state
ORDER BY tree_size DESC
LIMIT 1`

func (s *PostgresSTHStore) Publish(ctx context.Context, record STHRecord) error {
	if s == nil || s.db == nil {
		return errors.New("nil STH store")
	}
	if record.TreeSize > math.MaxInt64 {
		return fmt.Errorf("tree size %d exceeds PostgreSQL bigint", record.TreeSize)
	}
	if len(record.SignedTreeHead) == 0 {
		return errors.New("empty signed tree head")
	}

	publishedAt := record.PublishedAt
	if publishedAt.IsZero() {
		publishedAt = time.Now().UTC()
	}

	result, err := s.db.ExecContext(
		ctx,
		insertSTHIfCurrentHighWaterAllows,
		int64(record.TreeSize),
		record.SignedTreeHead,
		publishedAt,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 0 {
		return nil
	}

	var storedSize int64
	var storedSTH []byte
	var storedAt time.Time
	err = s.db.QueryRowContext(ctx, selectSTHAtSize, int64(record.TreeSize)).Scan(
		&storedSize,
		&storedSTH,
		&storedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSTHRollback
	}
	if err != nil {
		return err
	}
	if storedSize < 0 {
		return errors.New("negative persisted STH tree size")
	}
	if string(storedSTH) != string(record.SignedTreeHead) {
		return ErrSTHConflict
	}
	return nil
}

func (s *PostgresSTHStore) Latest(ctx context.Context) (STHRecord, error) {
	if s == nil || s.db == nil {
		return STHRecord{}, errors.New("nil STH store")
	}

	var storedSize int64
	var storedSTH []byte
	var storedAt time.Time
	if err := s.db.QueryRowContext(ctx, selectLatestSTH).Scan(
		&storedSize,
		&storedSTH,
		&storedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return STHRecord{}, ErrSTHNotFound
		}
		return STHRecord{}, err
	}
	if storedSize < 0 {
		return STHRecord{}, errors.New("negative persisted STH tree size")
	}
	return STHRecord{
		TreeSize:       uint64(storedSize),
		SignedTreeHead: append([]byte(nil), storedSTH...),
		PublishedAt:    storedAt,
	}, nil
}
