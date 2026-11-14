package signedprekeyv1

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

type vectorFixture struct {
	Contract        string `json:"contract"`
	DSKPublicHex    string `json:"dsk_public_hex"`
	AccountIDHex    string `json:"account_id_hex"`
	AccountEpoch    uint32 `json:"account_epoch"`
	DeviceIDHex     string `json:"device_id_hex"`
	SPKID           uint32 `json:"spk_id"`
	SPKPublicHex    string `json:"spk_public_hex"`
	SignatureHex    string `json:"signature_hex"`
	RawSignedPrekey string `json:"raw_signed_prekey_hex"`
}

func loadVector(t *testing.T) vectorFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/rust_go_candidate_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture vectorFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestRustGoCandidateVectorParsesAndVerifies(t *testing.T) {
	fixture := loadVector(t)
	raw := decodeHex(t, fixture.RawSignedPrekey)
	dsk := decodeHex(t, fixture.DSKPublicHex)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(vector): %v", err)
	}
	if err := parsed.Verify(dsk); err != nil {
		t.Fatalf("Verify(vector): %v", err)
	}
	if parsed.AccountID != [16]byte(mustFixed(t, fixture.AccountIDHex, 16)) {
		t.Fatal("account ID mismatch")
	}
	if parsed.AccountEpoch != fixture.AccountEpoch {
		t.Fatalf("epoch=%d want=%d", parsed.AccountEpoch, fixture.AccountEpoch)
	}
	if parsed.DeviceID != [16]byte(mustFixed(t, fixture.DeviceIDHex, 16)) {
		t.Fatal("device ID mismatch")
	}
	if parsed.SPKID != fixture.SPKID {
		t.Fatalf("SPK ID=%d want=%d", parsed.SPKID, fixture.SPKID)
	}
	if !bytes.Equal(parsed.SPKPub[:], decodeHex(t, fixture.SPKPublicHex)) {
		t.Fatal("SPK public key mismatch")
	}
	if !bytes.Equal(parsed.Signature[:], decodeHex(t, fixture.SignatureHex)) {
		t.Fatal("signature mismatch")
	}
	if !bytes.Equal(parsed.Raw(), raw) {
		t.Fatal("raw candidate object was not preserved byte-for-byte")
	}
}

func TestRejectsWrongDSKAndTamperedSignature(t *testing.T) {
	fixture := loadVector(t)
	raw := decodeHex(t, fixture.RawSignedPrekey)
	dsk := decodeHex(t, fixture.DSKPublicHex)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	wrongDSK := append([]byte(nil), dsk...)
	wrongDSK[0] ^= 0x80
	if err := parsed.Verify(wrongDSK); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong DSK error=%v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 1
	changed, err := Parse(tampered)
	if err != nil {
		t.Fatalf("tampered signature should retain valid shape: %v", err)
	}
	if err := changed.Verify(dsk); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered signature error=%v", err)
	}
}

func TestRejectsNonCanonicalEncoding(t *testing.T) {
	fixture := loadVector(t)
	raw := decodeHex(t, fixture.RawSignedPrekey)
	// The first map key (1) is encoded with an unnecessary one-byte argument.
	nonCanonical := append([]byte{raw[0], 0x18, raw[1]}, raw[2:]...)
	if _, err := Parse(nonCanonical); !errors.Is(err, ErrInvalidCBOR) {
		t.Fatalf("non-canonical encoding error=%v", err)
	}
}

func TestRejectsUnsupportedVersionAndLowOrderSPK(t *testing.T) {
	fixture := loadVector(t)
	raw := decodeHex(t, fixture.RawSignedPrekey)
	unsupported := append([]byte(nil), raw...)
	unsupported[2] = 2 // map key 1's value is the third byte
	if _, err := Parse(unsupported); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("unsupported version error=%v", err)
	}

	lowOrder := candidateWire(t, 1, bytes.Repeat([]byte{0}, 32))
	if _, err := Parse(lowOrder); !errors.Is(err, ErrInvalidX25519Public) {
		t.Fatalf("low-order SPK error=%v", err)
	}
}

func TestRejectsMalformedFields(t *testing.T) {
	fixture := loadVector(t)
	raw := decodeHex(t, fixture.RawSignedPrekey)
	decoded, err := cbor.DecodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Zero account ID is structurally valid CBOR but invalid protocol data.
	decoded.Map[1].Val = bytesValueForTest(make([]byte, 16))
	zeroAccount, err := cbor.EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(zeroAccount); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("zero account ID error=%v", err)
	}

	decoded, err = cbor.DecodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Map = append(decoded.Map, cbor.Pair{Key: uintValueForTest(8), Val: uintValueForTest(0)})
	unknownField, err := cbor.EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(unknownField); !errors.Is(err, ErrInvalidShape) {
		t.Fatalf("unknown field error=%v", err)
	}
}

func candidateWire(t *testing.T, version uint64, spkPublic []byte) []byte {
	t.Helper()
	fixture := loadVector(t)
	account := decodeHex(t, fixture.AccountIDHex)
	device := decodeHex(t, fixture.DeviceIDHex)
	core := cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		{Key: uintValueForTest(1), Val: uintValueForTest(version)},
		{Key: uintValueForTest(2), Val: bytesValueForTest(account)},
		{Key: uintValueForTest(3), Val: uintValueForTest(uint64(fixture.AccountEpoch))},
		{Key: uintValueForTest(4), Val: bytesValueForTest(device)},
		{Key: uintValueForTest(5), Val: uintValueForTest(uint64(fixture.SPKID))},
		{Key: uintValueForTest(6), Val: bytesValueForTest(spkPublic)},
		{Key: uintValueForTest(7), Val: bytesValueForTest(make([]byte, ed25519.SignatureSize))},
	}}
	raw, err := cbor.EncodeCanonical(core)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustFixed(t *testing.T, value string, size int) [16]byte {
	t.Helper()
	var out [16]byte
	decoded := decodeHex(t, value)
	if len(decoded) != size {
		t.Fatalf("fixed value length=%d want=%d", len(decoded), size)
	}
	copy(out[:], decoded)
	return out
}

func bytesValueForTest(value []byte) cbor.Value {
	return cbor.Value{Kind: cbor.KindBytes, Bytes: value}
}

func uintValueForTest(value uint64) cbor.Value {
	return cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}}
}

func TestX25519ValidationRejectsAllZero(t *testing.T) {
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	zeroPublic, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := private.ECDH(zeroPublic); err == nil {
		t.Fatal("Go X25519 unexpectedly accepted the all-zero shared secret")
	}
}
