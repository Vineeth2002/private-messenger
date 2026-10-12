package kt

import (
	"context"
	"errors"
	"time"
)

// STHStore is the persistence boundary for exact signed tree heads.
// The store persists the original PM-CBOR byte string and does not define a
// parallel JSON or Go-native protocol representation.
type STHStore interface {
	Publish(ctx context.Context, record STHRecord) error
	Latest(ctx context.Context) (STHRecord, error)
}

// STHPublisher verifies STHs before they cross into persistence and verifies
// persisted STH bytes again when they are retrieved.
type STHPublisher struct {
	store     STHStore
	logPublic [32]byte
}

func NewSTHPublisher(store STHStore, logPublic [32]byte) *STHPublisher {
	return &STHPublisher{store: store, logPublic: logPublic}
}

// Publish verifies a complete frozen STH wire object and then persists its
// exact received bytes. The STH issuance timestamp remains the cryptographic
// field; publication time is storage metadata assigned by the store.
func (p *STHPublisher) Publish(ctx context.Context, raw []byte) (SignedTreeHeadV1, error) {
	if p == nil || p.store == nil {
		return SignedTreeHeadV1{}, errors.New("nil STH publisher")
	}

	sth, err := VerifySignedTreeHeadV1(raw, p.logPublic)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}

	record := STHRecord{
		TreeSize:       sth.TreeSize,
		SignedTreeHead: append([]byte(nil), raw...),
	}
	if err := p.store.Publish(ctx, record); err != nil {
		return SignedTreeHeadV1{}, err
	}
	return sth, nil
}

// Latest retrieves the persisted STH bytes and cryptographically verifies them
// before returning the decoded frozen object and exact received bytes.
func (p *STHPublisher) Latest(ctx context.Context) (SignedTreeHeadV1, []byte, time.Time, error) {
	if p == nil || p.store == nil {
		return SignedTreeHeadV1{}, nil, time.Time{}, errors.New("nil STH publisher")
	}

	record, err := p.store.Latest(ctx)
	if err != nil {
		return SignedTreeHeadV1{}, nil, time.Time{}, err
	}
	sth, err := VerifySignedTreeHeadV1(record.SignedTreeHead, p.logPublic)
	if err != nil {
		return SignedTreeHeadV1{}, nil, time.Time{}, err
	}
	if sth.TreeSize != record.TreeSize {
		return SignedTreeHeadV1{}, nil, time.Time{}, errors.New("persisted STH tree size mismatch")
	}
	return sth, append([]byte(nil), record.SignedTreeHead...), record.PublishedAt, nil
}
