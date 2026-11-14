package devices

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"strings"
	"testing"
)

func validX25519PublicForTest(t *testing.T) [32]byte {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(bytesRepeat(0x42, 32))
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], private.PublicKey().Bytes())
	return out
}

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func TestDecodeSignedPrekeyRejectsOutOfRangeIDsAndLowOrderKey(t *testing.T) {
	deviceID := [16]byte{1}
	validPublic := validX25519PublicForTest(t)
	signature := make([]byte, 64)
	for _, id := range []int64{0, -1, int64(uint64(^uint32(0)) + 1)} {
		if _, err := decodeSignedPrekey(uuidText(deviceID), id, validPublic[:], signature, deviceID); err == nil {
			t.Fatalf("SPK ID %d unexpectedly accepted", id)
		}
	}
	if _, err := decodeSignedPrekey(uuidText(deviceID), 1, make([]byte, 32), signature, deviceID); err == nil {
		t.Fatal("all-zero low-order X25519 key unexpectedly accepted")
	}
	if _, err := decodeSignedPrekey(uuidText(deviceID), 1, validPublic[:], signature, deviceID); err != nil {
		t.Fatalf("valid X25519 key rejected: %v", err)
	}
}

func TestSignedPrekeyDirectoryQueryExcludesRevokedAndStaleEpochDevices(t *testing.T) {
	for _, fragment := range []string{
		"JOIN devices AS d ON d.device_id = sp.device_id",
		"JOIN accounts AS a ON a.account_id = d.account_id",
		"d.revoked_at IS NULL",
		"d.account_epoch = a.account_epoch",
	} {
		if !strings.Contains(selectSignedPrekeysSQL, fragment) {
			t.Fatalf("signed-prekey query missing lifecycle filter %q", fragment)
		}
	}
}

func TestDeviceProvisionerRejectsUnsignedCandidateBeforeDatabase(t *testing.T) {
	neverBegin := beginTxFunc(func(context.Context, *sql.TxOptions) (*sql.Tx, error) {
		t.Fatal("database transaction must not start for an unverified signed prekey")
		return nil, nil
	})
	p := NewPostgresDeviceProvisioner(neverBegin)
	device := Device{
		AccountID:    [16]byte{1},
		DeviceID:     [16]byte{2},
		AccountEpoch: 1,
		DSKPub:       [32]byte{3},
		DDHKPub:      [32]byte{4},
	}
	prekey := SignedPrekey{DeviceID: device.DeviceID, SPKID: 1, SPKPub: validX25519PublicForTest(t), Signature: [64]byte{}}
	if err := p.Enroll(context.Background(), device, []byte{1}, []SignedPrekey{prekey}); err == nil {
		t.Fatal("unsigned candidate prekey unexpectedly accepted")
	}
}
