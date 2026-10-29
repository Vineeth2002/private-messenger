package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

type recoveryAbortCandidateFixture struct {
	Schema   string `json:"schema"`
	Status   string `json:"status"`
	Recovery struct {
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"recovery"`
	RecoveryRequest struct {
		RequestCBORHex string `json:"request_cbor_hex"`
	} `json:"recovery_request"`
	RecoveryAbort struct {
		DomainASCII             string `json:"domain_ascii"`
		AccountIDHex            string `json:"account_id_hex"`
		AbortingDeviceIDHex     string `json:"aborting_device_id_hex"`
		OldEpoch                uint64 `json:"old_epoch"`
		NewEpoch                uint64 `json:"new_epoch"`
		RequestIDHex            string `json:"request_id_hex"`
		RequestDigestHex        string `json:"recovery_request_digest_sha256_hex"`
		AbortingDSKPublicKeyHex string `json:"aborting_dsk_public_key_hex"`
		CoreCBORHex             string `json:"core_cbor_hex"`
		SignedMessageHex        string `json:"signed_message_hex"`
		SignatureHex            string `json:"signature_hex"`
		AbortCBORHex            string `json:"abort_cbor_hex"`
	} `json:"recovery_abort"`
}

func readRecoveryAbortCandidateFixture(t *testing.T) recoveryAbortCandidateFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "test-vectors", "v1", "lifecycle_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lifecycle candidate vector %q: %v", path, err)
	}
	var fixture recoveryAbortCandidateFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode lifecycle candidate vector: %v", err)
	}
	if fixture.Schema != "lifecycle-wire-v1-candidate" || fixture.Status != "candidate_not_frozen" {
		t.Fatalf("unexpected lifecycle fixture metadata: schema=%q status=%q", fixture.Schema, fixture.Status)
	}
	if fixture.RecoveryAbort.AbortCBORHex == "" {
		t.Fatal("recovery_abort vector entry is missing")
	}
	return fixture
}

func TestRecoveryAbortV1CandidateVectorMatchesRustExactly(t *testing.T) {
	fixture := readRecoveryAbortCandidateFixture(t)
	var recoveryPub [32]byte
	copy(recoveryPub[:], lifecycleFixed(t, fixture.Recovery.PublicKeyHex, 32))
	requestRaw := decodeLifecycleHex(t, fixture.RecoveryRequest.RequestCBORHex)
	request, err := ParseRecoveryRequestV1(requestRaw)
	if err != nil {
		t.Fatalf("parse RecoveryRequestV1 fixture: %v", err)
	}
	if err := request.Verify(recoveryPub); err != nil {
		t.Fatalf("verify RecoveryRequestV1 fixture: %v", err)
	}

	abortRaw := decodeLifecycleHex(t, fixture.RecoveryAbort.AbortCBORHex)
	abort, err := ParseRecoveryAbortV1(abortRaw)
	if err != nil {
		t.Fatalf("parse RecoveryAbortV1 fixture: %v", err)
	}
	var devicePub [32]byte
	copy(devicePub[:], lifecycleFixed(t, fixture.RecoveryAbort.AbortingDSKPublicKeyHex, 32))
	if err := abort.VerifyForRequest(recoveryPub, devicePub, requestRaw); err != nil {
		t.Fatalf("verify abort signature/request binding: %v", err)
	}
	if fixture.RecoveryAbort.DomainASCII != RecoveryAbortDomain {
		t.Fatalf("domain mismatch: %q", fixture.RecoveryAbort.DomainASCII)
	}
	if abort.AccountID != *(*[16]byte)(lifecycleFixed(t, fixture.RecoveryAbort.AccountIDHex, 16)) {
		t.Fatal("AccountID mismatch")
	}
	if abort.DeviceID != *(*[16]byte)(lifecycleFixed(t, fixture.RecoveryAbort.AbortingDeviceIDHex, 16)) {
		t.Fatal("aborting DeviceID mismatch")
	}
	if abort.OldEpoch != fixture.RecoveryAbort.OldEpoch || abort.NewEpoch != fixture.RecoveryAbort.NewEpoch {
		t.Fatal("epoch mismatch")
	}
	if abort.RequestID != *(*[16]byte)(lifecycleFixed(t, fixture.RecoveryAbort.RequestIDHex, 16)) {
		t.Fatal("request ID mismatch")
	}
	if abort.RecoveryRequestDigest != *(*[32]byte)(lifecycleFixed(t, fixture.RecoveryAbort.RequestDigestHex, 32)) {
		t.Fatal("request digest mismatch")
	}
	if got := hex.EncodeToString(abort.Signature[:]); got != fixture.RecoveryAbort.SignatureHex {
		t.Fatalf("signature mismatch: %s", got)
	}
	if got := hex.EncodeToString(abort.Raw); got != fixture.RecoveryAbort.AbortCBORHex {
		t.Fatal("abort raw bytes mismatch")
	}

	core, err := abort.canonicalCore()
	if err != nil {
		t.Fatalf("encode canonical abort core: %v", err)
	}
	if got := hex.EncodeToString(core); got != fixture.RecoveryAbort.CoreCBORHex {
		t.Fatalf("core mismatch: %s", got)
	}
	signedMessage := append([]byte(RecoveryAbortDomain), core...)
	if got := hex.EncodeToString(signedMessage); got != fixture.RecoveryAbort.SignedMessageHex {
		t.Fatalf("signed message mismatch: %s", got)
	}
	requestDigest := sha256.Sum256(requestRaw)
	if got := hex.EncodeToString(requestDigest[:]); got != fixture.RecoveryAbort.RequestDigestHex {
		t.Fatalf("exact request digest mismatch: %s", got)
	}
}

func TestRecoveryAbortV1CandidateRejectsMalformedTamperedAndWrongKey(t *testing.T) {
	fixture := readRecoveryAbortCandidateFixture(t)
	raw := decodeLifecycleHex(t, fixture.RecoveryAbort.AbortCBORHex)
	abort, err := ParseRecoveryAbortV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	var devicePub [32]byte
	copy(devicePub[:], lifecycleFixed(t, fixture.RecoveryAbort.AbortingDSKPublicKeyHex, 32))
	if err := abort.Verify(devicePub); err != nil {
		t.Fatalf("fixture DSK signature should verify: %v", err)
	}

	wrongPubBytes, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var wrongPub [32]byte
	copy(wrongPub[:], wrongPubBytes)
	if err := abort.Verify(wrongPub); err == nil {
		t.Fatal("abort accepted wrong DSK public key")
	}

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 1
	tamperedAbort, err := ParseRecoveryAbortV1(tampered)
	if err != nil {
		t.Fatalf("signature mutation should remain structurally parseable: %v", err)
	}
	if err := tamperedAbort.Verify(devicePub); err == nil {
		t.Fatal("tampered abort signature was accepted")
	}
	if _, err := ParseRecoveryAbortV1(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated abort was accepted")
	}
	if _, err := ParseRecoveryAbortV1(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("abort with trailing bytes was accepted")
	}
}

func TestRecoveryAbortV1CandidateBindsOneExactRequest(t *testing.T) {
	recoveryPubBytes, recoveryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryPub [32]byte
	copy(recoveryPub[:], recoveryPubBytes)
	var accountID, targetDevice, requestID1, requestID2 [16]byte
	accountID[0], targetDevice[0], requestID1[0], requestID2[0] = 0x11, 0x22, 0x66, 0x67
	var targetDSK, targetDDHK [32]byte
	targetDSK[0], targetDDHK[0] = 0x33, 0x44
	enrollmentRaw := signTestEnrollmentForRecoveryRequestV1(t, recoveryPrivate, accountID, 4, targetDevice, targetDSK, targetDDHK)
	requestRaw1 := signTestRecoveryRequestV1(t, recoveryPrivate, accountID, 3, 4, requestID1, targetDevice, enrollmentRaw)
	requestRaw2 := signTestRecoveryRequestV1(t, recoveryPrivate, accountID, 3, 4, requestID2, targetDevice, enrollmentRaw)

	devicePubBytes, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var devicePub [32]byte
	copy(devicePub[:], devicePubBytes)
	var aborterID [16]byte
	aborterID[0] = 0x55
	requestDigest := sha256.Sum256(requestRaw1)
	corePairs := []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), bytesPair(3, aborterID[:]),
		uintPair(4, 3), uintPair(5, 4), bytesPair(6, requestID1[:]), bytesPair(7, requestDigest[:]),
	}
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: corePairs})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(devicePrivate, append([]byte(RecoveryAbortDomain), core...))
	wirePairs := append(append([]cbor.Pair(nil), corePairs...), bytesPair(8, signature))
	abortRaw := mustEncodeLifecycleMap(t, wirePairs)
	abort, err := ParseRecoveryAbortV1(abortRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := abort.VerifyForRequest(recoveryPub, devicePub, requestRaw1); err != nil {
		t.Fatalf("matching request should verify: %v", err)
	}
	if err := abort.VerifyForRequest(recoveryPub, devicePub, requestRaw2); err == nil {
		t.Fatal("abort was accepted for another valid request with a different request ID/digest")
	}
}
