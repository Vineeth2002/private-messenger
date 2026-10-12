package devices

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

type beginTxFunc func(context.Context, *sql.TxOptions) (*sql.Tx, error)

func (f beginTxFunc) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return f(ctx, opts)
}

func TestDeviceProvisionerRejectsInvalidEnrollmentBeforeDatabase(t *testing.T) {
	neverBegin := beginTxFunc(func(context.Context, *sql.TxOptions) (*sql.Tx, error) {
		t.Fatal("database transaction should not have started")
		return nil, nil
	})

	p := NewPostgresDeviceProvisioner(neverBegin)
	device := Device{AccountEpoch: 1}
	if err := p.Enroll(context.Background(), device, []byte{1}, nil); err == nil {
		t.Fatal("expected invalid-id error")
	}

	device.AccountID[0] = 1
	device.DeviceID[0] = 2
	device.Revoked = true
	if err := p.Enroll(context.Background(), device, []byte{1}, nil); err == nil {
		t.Fatal("expected revoked-device error")
	}

	device.Revoked = false
	if err := p.Enroll(context.Background(), device, nil, nil); err == nil {
		t.Fatal("expected missing-certificate error")
	}

	mismatched := SignedPrekey{DeviceID: [16]byte{9}, SPKID: 1}
	if err := p.Enroll(context.Background(), device, []byte{1}, []SignedPrekey{mismatched}); err == nil {
		t.Fatal("expected prekey/device mismatch error")
	}
}

type fakeSQLStateError string

func (e fakeSQLStateError) Error() string    { return string(e) }
func (e fakeSQLStateError) SQLState() string { return string(e) }

func TestIsUniqueViolation(t *testing.T) {
	if !isUniqueViolation(fakeSQLStateError("23505")) {
		t.Fatal("expected unique violation")
	}
	if isUniqueViolation(fakeSQLStateError("23503")) {
		t.Fatal("unexpected unique violation")
	}
	if isUniqueViolation(errors.New("plain error")) {
		t.Fatal("plain error should not be unique violation")
	}
}
