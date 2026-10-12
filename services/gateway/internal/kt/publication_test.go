package kt

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

type publicationTestDB struct{}

func (publicationTestDB) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, errors.New("unexpected database write")
}

func (publicationTestDB) QueryRowContext(context.Context, string, ...any) *sql.Row {
	return nil
}

type publicationTestRow struct{}

func (publicationTestRow) Scan(...any) error { return errors.New("unexpected database read") }

func publicationTestEntry(sequence byte, key, leaf [32]byte) []byte {
	raw := make([]byte, 0, 71)
	raw = append(raw, 0xa3, 0x01, sequence, 0x02, 0x58, 0x20)
	raw = append(raw, key[:]...)
	raw = append(raw, 0x03, 0x58, 0x20)
	raw = append(raw, leaf[:]...)
	return raw
}

func TestPublishStateRejectsHistoryLeafMismatchBeforeTransaction(t *testing.T) {
	var key, leaf, other [32]byte
	leaf[0] = 1
	other[0] = 2
	raw := publicationTestEntry(1, key, other)
	store := NewPostgresTransparencyStateStore(publicationTestDB{})
	if err := store.PublishState(context.Background(), SMTLeaf{Key: key, LeafHash: leaf}, nil, raw); !errors.Is(err, ErrTransparencyPublicationMismatch) {
		t.Fatalf("err = %v, want ErrTransparencyPublicationMismatch", err)
	}
}

func TestPublishStateRequiresTransactionCapableDatabase(t *testing.T) {
	const leafHex = "a9015000112233445566778899aabbccddeeff02010350010101010101010101010101010101010458207776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b055820b39af3676aac20db81c831af4b077b61240ac157b872108b46acb1c19c6f6265065840ea15fdcea10d6c22a057c1d7b6a5860f6eb4594af62e6cd695ffa9118a53a38b9d78358808c79ca2fccee0c05443737fe8e9007371b85597ddf8a05fc71f22090758207d6698f2aa51b0812025628dcaa91913f5a387b6a368bafe0fef456715056bba085820818f3cbb2ac8a4d924a8fbb0e7777f0ec7a53e27e8903ae283cd51d6a0888e54095840b73b192f111d853c72137c4bcc784c237b616aa84b5baf025612ffac444e022f19b3d903344a7b2a10661fb6ecefd8934a2241918b7105af32dd4423f1c7b002"
	leafRaw := mustVerifyHex(t, leafHex)
	verified, leafHash, err := VerifyTransparencyLeafV1(leafRaw)
	if err != nil {
		t.Fatal(err)
	}
	key := SMTKey(verified.AccountID, verified.DeviceID)
	raw := publicationTestEntry(1, key, leafHash)
	store := NewPostgresTransparencyStateStore(publicationTestDB{})
	if err := store.PublishState(context.Background(), SMTLeaf{Key: key, LeafHash: leafHash}, leafRaw, raw); err == nil {
		t.Fatal("expected transactional database requirement")
	}
}
