package kt

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memorySTHStore struct {
	record      STHRecord
	publishErr  error
	latestErr   error
	publishCall int
}

func (m *memorySTHStore) Publish(_ context.Context, record STHRecord) error {
	m.publishCall++
	if m.publishErr != nil {
		return m.publishErr
	}
	m.record = STHRecord{
		TreeSize:       record.TreeSize,
		SignedTreeHead: append([]byte(nil), record.SignedTreeHead...),
		PublishedAt:    record.PublishedAt,
	}
	return nil
}

func (m *memorySTHStore) Latest(_ context.Context) (STHRecord, error) {
	if m.latestErr != nil {
		return STHRecord{}, m.latestErr
	}
	return STHRecord{
		TreeSize:       m.record.TreeSize,
		SignedTreeHead: append([]byte(nil), m.record.SignedTreeHead...),
		PublishedAt:    m.record.PublishedAt,
	}, nil
}

func TestSTHPublisherPublishesVerifiedFrozenSTH(t *testing.T) {
	v := loadEquivocationVector(t)
	logPublic := mustFixed32(t, v.Log.PublicKeyHex)
	raw := mustVerifyHex(t, v.STHAHex)

	store := &memorySTHStore{}
	publisher := NewSTHPublisher(store, logPublic)

	sth, err := publisher.Publish(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize == 0 {
		t.Fatal("expected non-zero tree size")
	}
	if store.publishCall != 1 {
		t.Fatalf("publish calls = %d, want 1", store.publishCall)
	}
	if string(store.record.SignedTreeHead) != string(raw) {
		t.Fatal("publisher did not persist exact STH bytes")
	}
}

func TestSTHPublisherRejectsInvalidSTHBeforePersistence(t *testing.T) {
	v := loadEquivocationVector(t)
	logPublic := mustFixed32(t, v.Log.PublicKeyHex)
	raw := mustVerifyHex(t, v.STHAHex)
	raw[len(raw)-1] ^= 0x01

	store := &memorySTHStore{}
	publisher := NewSTHPublisher(store, logPublic)

	if _, err := publisher.Publish(context.Background(), raw); err == nil {
		t.Fatal("tampered STH accepted")
	}
	if store.publishCall != 0 {
		t.Fatalf("publish calls = %d, want 0", store.publishCall)
	}
}

func TestSTHPublisherLatestReverifiesPersistedBytes(t *testing.T) {
	v := loadEquivocationVector(t)
	logPublic := mustFixed32(t, v.Log.PublicKeyHex)
	raw := mustVerifyHex(t, v.STHAHex)
	publishedAt := time.Unix(1700101234, 0).UTC()

	store := &memorySTHStore{record: STHRecord{
		TreeSize:       32,
		SignedTreeHead: append([]byte(nil), raw...),
		PublishedAt:    publishedAt,
	}}
	publisher := NewSTHPublisher(store, logPublic)

	sth, gotRaw, gotAt, err := publisher.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != 32 {
		t.Fatalf("tree size = %d, want 32", sth.TreeSize)
	}
	if string(gotRaw) != string(raw) {
		t.Fatal("latest did not return exact persisted bytes")
	}
	if !gotAt.Equal(publishedAt) {
		t.Fatalf("published_at = %s, want %s", gotAt, publishedAt)
	}
}

func TestSTHPublisherLatestRejectsPersistedCorruption(t *testing.T) {
	v := loadEquivocationVector(t)
	logPublic := mustFixed32(t, v.Log.PublicKeyHex)
	raw := mustVerifyHex(t, v.STHAHex)
	raw[len(raw)-1] ^= 0x01

	store := &memorySTHStore{record: STHRecord{
		TreeSize:       32,
		SignedTreeHead: raw,
	}}
	publisher := NewSTHPublisher(store, logPublic)

	if _, _, _, err := publisher.Latest(context.Background()); err == nil {
		t.Fatal("corrupted persisted STH accepted")
	}
}

func TestSTHPublisherPropagatesStoreError(t *testing.T) {
	v := loadEquivocationVector(t)
	logPublic := mustFixed32(t, v.Log.PublicKeyHex)
	raw := mustVerifyHex(t, v.STHAHex)
	wantErr := errors.New("store failed")

	store := &memorySTHStore{publishErr: wantErr}
	publisher := NewSTHPublisher(store, logPublic)

	_, err := publisher.Publish(context.Background(), raw)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}
