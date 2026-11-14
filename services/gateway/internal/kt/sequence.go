package kt

import (
	"context"
	"errors"
	"math"
)

// HistorySequenceReader reports the next append-only KT history sequence.
// A caller must treat this as a hint: concurrent publishers may claim it first.
type HistorySequenceReader interface {
	NextHistorySequence(context.Context) (uint64, error)
}

// NextHistorySequence returns MAX(sequence)+1 from the persisted history.
// The publication transaction remains the authority and rejects stale values.
func (s *PostgresTransparencyStateStore) NextHistorySequence(ctx context.Context) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("nil transparency state store")
	}
	var maxSeq int64
	if err := s.db.QueryRowContext(ctx, maxTransparencyHistorySequenceSQL).Scan(&maxSeq); err != nil {
		return 0, err
	}
	if maxSeq < 0 || maxSeq == math.MaxInt64 {
		return 0, errors.New("transparency history sequence is outside PostgreSQL bigint range")
	}
	return uint64(maxSeq + 1), nil
}
