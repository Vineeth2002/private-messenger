package kt

import (
	"context"
	"database/sql"
	"errors"
)

// DeviceLeafPrincipal is the minimal authenticated device identity required by
// the KT domain. It deliberately avoids importing the deviceauth or
// authorization packages, which depend on kt for wire verification.
type DeviceLeafPrincipal struct {
	AccountID [16]byte
	DeviceID  [16]byte
	Epoch     uint64
}

// DeviceLeafTransactionAuthorizer validates a leaf using row locks held by tx.
type DeviceLeafTransactionAuthorizer interface {
	ValidateLeafTx(context.Context, *sql.Tx, TransparencyLeafV1) error
}

type DeviceLeafPublicationTxBeginner interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// PostgresDeviceLeafPublicationService atomically validates the authenticated
// device principal, locks current authorization state, and publishes the leaf,
// append-only history entry, and STH in one PostgreSQL transaction.
type PostgresDeviceLeafPublicationService struct {
	db         DeviceLeafPublicationTxBeginner
	authorizer DeviceLeafTransactionAuthorizer
	publisher  *TransparencyPublicationService
}

func NewPostgresDeviceLeafPublicationService(
	db DeviceLeafPublicationTxBeginner,
	authorizer DeviceLeafTransactionAuthorizer,
	publisher *TransparencyPublicationService,
) (*PostgresDeviceLeafPublicationService, error) {
	if db == nil {
		return nil, errors.New("nil device leaf publication database")
	}
	if authorizer == nil {
		return nil, errors.New("nil device leaf transaction authorizer")
	}
	if publisher == nil {
		return nil, errors.New("nil transparency publication service")
	}
	return &PostgresDeviceLeafPublicationService{db: db, authorizer: authorizer, publisher: publisher}, nil
}

func (s *PostgresDeviceLeafPublicationService) PublishDeviceLeaf(
	ctx context.Context,
	principal DeviceLeafPrincipal,
	expectedSequence uint64,
	leafRaw []byte,
) (PublishedTransparencySnapshot, error) {
	if s == nil || s.db == nil || s.authorizer == nil || s.publisher == nil {
		return PublishedTransparencySnapshot{}, errors.New("nil device leaf publication service")
	}
	if expectedSequence == 0 || expectedSequence > uint64(^uint64(0)>>1) {
		return PublishedTransparencySnapshot{}, errors.New("invalid expected KT history sequence")
	}

	leaf, leafHash, err := VerifyTransparencyLeafV1(leafRaw)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if leaf.AccountID != principal.AccountID || leaf.DeviceID != principal.DeviceID || leaf.Epoch != principal.Epoch {
		return PublishedTransparencySnapshot{}, errors.New("authenticated principal does not match transparency leaf")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Authorization locks are acquired before the KT history advisory lock,
	// matching the gateway's account/device lifecycle lock ordering.
	if err := s.authorizer.ValidateLeafTx(ctx, tx, leaf); err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	smtKey := SMTKey(leaf.AccountID, leaf.DeviceID)
	historyRaw, err := encodeDeviceLeafHistoryEntry(expectedSequence, smtKey, leafHash)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	snapshot, err := s.publisher.PublishStateAndSTHInTx(
		ctx, tx, SMTLeaf{Key: smtKey, LeafHash: leafHash}, leafRaw, historyRaw,
	)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return PublishedTransparencySnapshot{}, err
	}
	committed = true
	return snapshot, nil
}

// encodeDeviceLeafHistoryEntry encodes the frozen three-field KT history entry.
func encodeDeviceLeafHistoryEntry(sequence uint64, key, leafHash [32]byte) ([]byte, error) {
	return encodeHistoryEntryV1(sequence, key, leafHash)
}
