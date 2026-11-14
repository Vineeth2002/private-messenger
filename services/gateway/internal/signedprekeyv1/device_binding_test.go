package signedprekeyv1

import (
	"bytes"
	"errors"
	"testing"
)

func TestVerifyRecordFieldsBindsCandidateToAuthoritativeDevice(t *testing.T) {
	fixture := loadVector(t)
	accountID := mustFixed(t, fixture.AccountIDHex, 16)
	deviceID := mustFixed(t, fixture.DeviceIDHex, 16)
	spkPublic := decodeHex(t, fixture.SPKPublicHex)
	signature := decodeHex(t, fixture.SignatureHex)
	dskPublic := decodeHex(t, fixture.DSKPublicHex)

	if err := VerifyRecordFields(accountID, uint64(fixture.AccountEpoch), deviceID, int64(fixture.SPKID), spkPublic, signature, dskPublic); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	wrongAccount := accountID
	wrongAccount[0] ^= 1
	wrongDevice := deviceID
	wrongDevice[0] ^= 1
	wrongSPK := append([]byte(nil), spkPublic...)
	wrongSPK[0] ^= 1
	wrongSignature := append([]byte(nil), signature...)
	wrongSignature[0] ^= 1
	wrongDSK := append([]byte(nil), dskPublic...)
	wrongDSK[0] ^= 1

	cases := []struct {
		name      string
		account   [16]byte
		epoch     uint64
		device    [16]byte
		spkID     int64
		spkPublic []byte
		signature []byte
		dsk       []byte
		want      error
	}{
		{"account substitution", wrongAccount, uint64(fixture.AccountEpoch), deviceID, int64(fixture.SPKID), spkPublic, signature, dskPublic, ErrInvalidSignature},
		{"epoch substitution", accountID, uint64(fixture.AccountEpoch) + 1, deviceID, int64(fixture.SPKID), spkPublic, signature, dskPublic, ErrInvalidSignature},
		{"device substitution", accountID, uint64(fixture.AccountEpoch), wrongDevice, int64(fixture.SPKID), spkPublic, signature, dskPublic, ErrInvalidSignature},
		{"SPK ID substitution", accountID, uint64(fixture.AccountEpoch), deviceID, int64(fixture.SPKID) + 1, spkPublic, signature, dskPublic, ErrInvalidSignature},
		{"SPK public substitution", accountID, uint64(fixture.AccountEpoch), deviceID, int64(fixture.SPKID), wrongSPK, signature, dskPublic, ErrInvalidSignature},
		{"signature tampering", accountID, uint64(fixture.AccountEpoch), deviceID, int64(fixture.SPKID), spkPublic, wrongSignature, dskPublic, ErrInvalidSignature},
		{"DSK substitution", accountID, uint64(fixture.AccountEpoch), deviceID, int64(fixture.SPKID), spkPublic, signature, wrongDSK, ErrInvalidSignature},
		{"zero SPK ID", accountID, uint64(fixture.AccountEpoch), deviceID, 0, spkPublic, signature, dskPublic, ErrInvalidField},
		{"negative SPK ID", accountID, uint64(fixture.AccountEpoch), deviceID, -1, spkPublic, signature, dskPublic, ErrInvalidField},
		{"SPK ID above u32", accountID, uint64(fixture.AccountEpoch), deviceID, int64(uint64(MaxID) + 1), spkPublic, signature, dskPublic, ErrInvalidField},
		{"epoch above u32", accountID, MaxEpoch + 1, deviceID, int64(fixture.SPKID), spkPublic, signature, dskPublic, ErrInvalidField},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyRecordFields(tc.account, tc.epoch, tc.device, tc.spkID, tc.spkPublic, tc.signature, tc.dsk)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}

	if bytes.Equal(signature, wrongSignature) {
		t.Fatal("test signature mutation did not change the bytes")
	}
}
