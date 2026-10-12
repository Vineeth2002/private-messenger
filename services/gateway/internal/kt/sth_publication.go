package kt

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

// PublishedTransparencySnapshot is the exact STH produced by one committed
// KT V1 publication. The signed STH bytes are returned verbatim.
type PublishedTransparencySnapshot struct {
	STH         SignedTreeHeadV1
	SignedBytes []byte
}

// TransparencyPublicationService creates the STH from the database snapshot
// produced by one atomic publication transaction. The log private key is only
// held in process memory; it is never persisted in PostgreSQL.
type TransparencyPublicationService struct {
	state      *PostgresTransparencyStateStore
	logPrivate ed25519.PrivateKey
	logPublic  [32]byte
	logID      [32]byte
	now        func() time.Time
}

func NewTransparencyPublicationService(
	state *PostgresTransparencyStateStore,
	logPrivate ed25519.PrivateKey,
	logID [32]byte,
) (*TransparencyPublicationService, error) {
	if state == nil || state.db == nil {
		return nil, errors.New("nil transparency state store")
	}
	if len(logPrivate) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid transparency log private key")
	}
	public, ok := logPrivate.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("invalid transparency log public key")
	}
	var logPublic [32]byte
	copy(logPublic[:], public)
	return &TransparencyPublicationService{
		state:      state,
		logPrivate: append(ed25519.PrivateKey(nil), logPrivate...),
		logPublic:  logPublic,
		logID:      logID,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

// PublishStateAndSTH atomically commits the supplied current-state leaf,
// history entry, and the STH derived from the resulting database snapshot.
// A retry of an already-completed publication returns the exact persisted STH
// rather than rebuilding a second object.
func (p *TransparencyPublicationService) PublishStateAndSTH(ctx context.Context, leaf SMTLeaf, leafRaw []byte, historyRaw []byte) (PublishedTransparencySnapshot, error) {
	if p == nil || p.state == nil || p.state.db == nil {
		return PublishedTransparencySnapshot{}, errors.New("nil transparency publication service")
	}
	entry, err := ParseHistoryEntryV1(historyRaw)
	if err != nil {
		return PublishedTransparencySnapshot{}, fmt.Errorf("invalid history entry: %w", err)
	}
	if entry.Sequence == 0 || entry.SMTKey != leaf.Key || entry.LeafHash != leaf.LeafHash {
		return PublishedTransparencySnapshot{}, ErrTransparencyPublicationMismatch
	}
	if err := validatePublishedTransparencyLeaf(leaf, leafRaw); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if entry.Sequence > uint64(^uint64(0)>>1) {
		return PublishedTransparencySnapshot{}, errors.New("history sequence outside PostgreSQL bigint")
	}

	beginner, ok := p.state.db.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return PublishedTransparencySnapshot{}, errors.New("transparency publication requires transactional PostgreSQL handle")
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, lockTransparencyHistoryPublicationSQL, transparencyHistoryLockKey); err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	maxSeq, err := queryHistoryMaxInTx(ctx, tx)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	wanted := int64(entry.Sequence)
	if wanted <= maxSeq {
		return p.retryPublishedState(ctx, tx, entry, leafRaw, historyRaw, wanted)
	}
	if wanted != maxSeq+1 {
		return PublishedTransparencySnapshot{}, ErrTransparencyHistoryGap
	}

	if err := p.verifyPrePublicationSnapshot(ctx, tx, uint64(maxSeq)); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, upsertCurrentTransparencyStateSQL, leaf.Key[:], leaf.LeafHash[:], leafRaw); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, insertTransparencyHistoryEntrySQL, wanted, entry.SMTKey[:], entry.LeafHash[:], historyRaw, leafRaw); err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	current, err := currentStateInTx(ctx, tx)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	history, err := historyEntriesInTx(ctx, tx)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	smtRoot, err := SMTRootV1(current)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	historyRoot := HistoryRootV1(history)

	issuedAtTime := p.now()
	if issuedAtTime.Unix() < 0 {
		return PublishedTransparencySnapshot{}, errors.New("transparency STH issuance time before Unix epoch")
	}
	sthRaw, sth, err := p.buildSTH(uint64(wanted), smtRoot, historyRoot, uint64(issuedAtTime.Unix()))
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if err := publishSTHInExecutor(ctx, tx, STHRecord{TreeSize: uint64(wanted), SignedTreeHead: sthRaw}); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	committed = true
	return PublishedTransparencySnapshot{STH: sth, SignedBytes: append([]byte(nil), sthRaw...)}, nil
}

func (p *TransparencyPublicationService) retryPublishedState(ctx context.Context, tx *sql.Tx, entry HistoryEntryV1, leafRaw []byte, historyRaw []byte, wanted int64) (PublishedTransparencySnapshot, error) {
	var storedKey, storedLeaf, storedRaw, storedLeafCbor []byte
	if err := tx.QueryRowContext(ctx, selectTransparencyHistoryAtSequenceSQL, wanted).Scan(&storedKey, &storedLeaf, &storedRaw, &storedLeafCbor); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PublishedTransparencySnapshot{}, ErrTransparencyHistoryRollback
		}
		return PublishedTransparencySnapshot{}, err
	}
	if !transparencyBytesEqual(storedKey, entry.SMTKey[:]) || !transparencyBytesEqual(storedLeaf, entry.LeafHash[:]) || !transparencyBytesEqual(storedRaw, historyRaw) || !transparencyBytesEqual(storedLeafCbor, leafRaw) {
		return PublishedTransparencySnapshot{}, ErrTransparencyHistoryConflict
	}

	var storedSTH []byte
	var storedSize int64
	var storedAt time.Time
	if err := tx.QueryRowContext(ctx, selectSTHAtSize, wanted).Scan(&storedSize, &storedSTH, &storedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PublishedTransparencySnapshot{}, errors.New("published history entry has no matching STH")
		}
		return PublishedTransparencySnapshot{}, err
	}
	if storedSize < 0 {
		return PublishedTransparencySnapshot{}, errors.New("negative persisted STH tree size")
	}
	sth, err := VerifySignedTreeHeadV1(storedSTH, p.logPublic)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if sth.TreeSize != uint64(storedSize) || sth.TreeSize != uint64(wanted) {
		return PublishedTransparencySnapshot{}, errors.New("persisted STH tree size mismatch")
	}
	if err := tx.Commit(); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	return PublishedTransparencySnapshot{STH: sth, SignedBytes: append([]byte(nil), storedSTH...)}, nil
}

func (p *TransparencyPublicationService) buildSTH(treeSize uint64, smtRoot, historyRoot [32]byte, issuedAt uint64) ([]byte, SignedTreeHeadV1, error) {
	sth := SignedTreeHeadV1{TreeSize: treeSize, SMTRoot: smtRoot, HistoryRoot: historyRoot, IssuedAt: issuedAt, LogID: p.logID}
	body, err := cbor.EncodeCanonical(sthBodyValue(sth))
	if err != nil {
		return nil, SignedTreeHeadV1{}, err
	}
	message := append(append([]byte(nil), []byte(sthSignDomain)...), body...)
	signature := ed25519.Sign(p.logPrivate, message)
	copy(sth.Signature[:], signature)
	full := cbor.Value{Kind: cbor.KindMap, Map: append(sthBodyValue(sth).Map, bytesPair(7, signature))}
	raw, err := cbor.EncodeCanonical(full)
	if err != nil {
		return nil, SignedTreeHeadV1{}, err
	}
	verified, err := VerifySignedTreeHeadV1(raw, p.logPublic)
	if err != nil {
		return nil, SignedTreeHeadV1{}, err
	}
	if verified.TreeSize != treeSize || verified.SMTRoot != smtRoot || verified.HistoryRoot != historyRoot || verified.LogID != p.logID {
		return nil, SignedTreeHeadV1{}, errors.New("generated STH does not match publication snapshot")
	}
	return raw, verified, nil
}

func queryHistoryMaxInTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var maxSeq int64
	if err := tx.QueryRowContext(ctx, maxTransparencyHistorySequenceSQL).Scan(&maxSeq); err != nil {
		return 0, err
	}
	if maxSeq < 0 {
		return 0, errors.New("negative persisted history sequence")
	}
	return maxSeq, nil
}

func (p *TransparencyPublicationService) verifyPrePublicationSnapshot(ctx context.Context, tx *sql.Tx, historySize uint64) error {
	if historySize == 0 {
		var size int64
		var raw []byte
		var publishedAt time.Time
		err := tx.QueryRowContext(ctx, selectLatestSTH).Scan(&size, &raw, &publishedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("empty history has a persisted STH")
	}
	var size int64
	var raw []byte
	var publishedAt time.Time
	if err := tx.QueryRowContext(ctx, selectLatestSTH).Scan(&size, &raw, &publishedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("persisted history has no matching latest STH")
		}
		return err
	}
	if size < 0 || uint64(size) != historySize {
		return errors.New("persisted STH tree size does not match history high water")
	}
	sth, err := VerifySignedTreeHeadV1(raw, p.logPublic)
	if err != nil {
		return err
	}
	current, err := currentStateInTx(ctx, tx)
	if err != nil {
		return err
	}
	history, err := historyEntriesInTx(ctx, tx)
	if err != nil {
		return err
	}
	smtRoot, err := SMTRootV1(current)
	if err != nil {
		return err
	}
	if historyRoot := HistoryRootV1(history); sth.TreeSize != historySize || sth.SMTRoot != smtRoot || sth.HistoryRoot != historyRoot {
		return errors.New("persisted STH does not match committed transparency snapshot")
	}
	return nil
}

func currentStateInTx(ctx context.Context, tx *sql.Tx) ([]SMTLeaf, error) {
	rows, err := tx.QueryContext(ctx, selectCurrentTransparencyStateSQL)
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

func historyEntriesInTx(ctx context.Context, tx *sql.Tx) ([][]byte, error) {
	rows, err := tx.QueryContext(ctx, selectHistoryEntriesSQL)
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
		if sequence != expected || sequence <= 0 || len(key) != 32 || len(leaf) != 32 || len(raw) == 0 {
			return nil, errors.New("invalid persisted history snapshot")
		}
		entry, err := ParseHistoryEntryV1(raw)
		if err != nil {
			return nil, err
		}
		if entry.Sequence != uint64(sequence) || entry.SMTKey != bytesTo32(key) || entry.LeafHash != bytesTo32(leaf) {
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

func bytesTo32(raw []byte) [32]byte {
	var out [32]byte
	copy(out[:], raw)
	return out
}

type sthSQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// publishSTHInExecutor shares the frozen monotonic STH persistence rule with
// the atomic publication transaction without changing the existing SQLExecutor
// abstraction used by the general store.
func publishSTHInExecutor(ctx context.Context, db sthSQLExecutor, record STHRecord) error {
	if db == nil {
		return errors.New("nil STH executor")
	}
	if record.TreeSize > uint64(^uint64(0)>>1) {
		return fmt.Errorf("tree size %d exceeds PostgreSQL bigint", record.TreeSize)
	}
	if len(record.SignedTreeHead) == 0 {
		return errors.New("empty signed tree head")
	}
	publishedAt := record.PublishedAt
	if publishedAt.IsZero() {
		publishedAt = time.Now().UTC()
	}
	result, err := db.ExecContext(ctx, insertSTHIfCurrentHighWaterAllows, int64(record.TreeSize), record.SignedTreeHead, publishedAt)
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
	if err := db.QueryRowContext(ctx, selectSTHAtSize, int64(record.TreeSize)).Scan(&storedSize, &storedSTH, &storedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSTHRollback
		}
		return err
	}
	if storedSize < 0 {
		return errors.New("negative persisted STH tree size")
	}
	if !transparencyBytesEqual(storedSTH, record.SignedTreeHead) {
		return ErrSTHConflict
	}
	return nil
}
