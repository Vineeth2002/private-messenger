package signedprekeyv1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestEncodeRecordReproducesSharedCandidateVector(t *testing.T) {
	rawFixture, err := os.ReadFile("testdata/rust_go_candidate_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AccountIDHex    string `json:"account_id_hex"`
		AccountEpoch    uint32 `json:"account_epoch"`
		DeviceIDHex     string `json:"device_id_hex"`
		SPKID           uint32 `json:"spk_id"`
		SPKPublicHex    string `json:"spk_public_hex"`
		SignatureHex    string `json:"signature_hex"`
		RawSignedPrekey string `json:"raw_signed_prekey_hex"`
	}
	if err := json.Unmarshal(rawFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var accountID, deviceID [16]byte
	copy(accountID[:], decode(fixture.AccountIDHex))
	copy(deviceID[:], decode(fixture.DeviceIDHex))
	encoded, err := EncodeRecord(accountID, uint64(fixture.AccountEpoch), deviceID, uint64(fixture.SPKID), decode(fixture.SPKPublicHex), decode(fixture.SignatureHex))
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	want := decode(fixture.RawSignedPrekey)
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded vector differs\n got %x\nwant %x", encoded, want)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(EncodeRecord): %v", err)
	}
	if parsed.AccountID != accountID || parsed.DeviceID != deviceID || parsed.AccountEpoch != fixture.AccountEpoch || parsed.SPKID != fixture.SPKID {
		t.Fatal("encoded record identity fields changed")
	}
}
