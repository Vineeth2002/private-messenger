package kt

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"testing"
)

type sthPublicationNoTxDB struct{}

func (sthPublicationNoTxDB) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, errors.New("unexpected database write")
}

func (sthPublicationNoTxDB) QueryRowContext(context.Context, string, ...any) *sql.Row {
	return nil
}

func TestTransparencyPublicationBuildSTHIsSelfVerified(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	var logID [32]byte
	for i := range logID {
		logID[i] = byte(0xa0 + i)
	}
	var rootA, rootB [32]byte
	rootA[0], rootB[0] = 0x11, 0x22
	store := NewPostgresTransparencyStateStore(sthPublicationNoTxDB{})
	service, err := NewTransparencyPublicationService(store, private, logID)
	if err != nil {
		t.Fatal(err)
	}
	raw, sth, err := service.buildSTH(32, rootA, rootB, 1700100000)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || sth.TreeSize != 32 || sth.SMTRoot != rootA || sth.HistoryRoot != rootB || sth.IssuedAt != 1700100000 || sth.LogID != logID {
		t.Fatal("generated STH does not preserve the publication fields")
	}
	verified, err := VerifySignedTreeHeadV1(raw, service.logPublic)
	if err != nil {
		t.Fatal(err)
	}
	if verified.STHDigest == ([32]byte{}) {
		t.Fatal("generated STH digest is empty")
	}
}

func TestTransparencyPublicationRejectsMismatchedHistoryBeforeTransaction(t *testing.T) {
	var key, leaf, other [32]byte
	leaf[0] = 1
	other[0] = 2
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store := NewPostgresTransparencyStateStore(sthPublicationNoTxDB{})
	service, err := NewTransparencyPublicationService(store, private, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	entry := publicationTestEntry(1, key, other)
	_, err = service.PublishStateAndSTH(context.Background(), SMTLeaf{Key: key, LeafHash: leaf}, nil, entry)
	if !errors.Is(err, ErrTransparencyPublicationMismatch) {
		t.Fatalf("err = %v, want ErrTransparencyPublicationMismatch", err)
	}
}

func TestTransparencyPublicationConstructorCopiesKeyAndRejectsInvalidKey(t *testing.T) {
	store := NewPostgresTransparencyStateStore(sthPublicationNoTxDB{})
	if _, err := NewTransparencyPublicationService(store, ed25519.PrivateKey{1}, [32]byte{}); err == nil {
		t.Fatal("expected invalid private key rejection")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	service, err := NewTransparencyPublicationService(store, private, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	private[0] ^= 0xff
	if service.logPrivate[0] == private[0] {
		t.Fatal("service retained caller-owned private key slice")
	}
}
