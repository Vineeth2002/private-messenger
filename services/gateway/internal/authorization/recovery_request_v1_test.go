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

type lifecycleWireV1CandidateVector struct {
	Schema   string `json:"schema"`
	Status   string `json:"status"`
	Recovery struct {
		PublicKeyHex  string `json:"public_key_hex"`
		CommitmentHex string `json:"commitment_hex"`
	} `json:"recovery"`
	Enrollment struct {
		DomainASCII        string `json:"domain_ascii"`
		AccountIDHex       string `json:"account_id_hex"`
		Epoch              uint64 `json:"epoch"`
		DeviceIDHex        string `json:"device_id_hex"`
		DSKPublicKeyHex    string `json:"dsk_public_key_hex"`
		DDHKPublicKeyHex   string `json:"ddhk_public_key_hex"`
		CoreCBORHex        string `json:"core_cbor_hex"`
		SignedMessageHex   string `json:"signed_message_hex"`
		SignatureHex       string `json:"signature_hex"`
		SHACertificateHex  string `json:"sha256_certificate_hex"`
		CertificateCBORHex string `json:"certificate_cbor_hex"`
	} `json:"enrollment"`
	RecoveryRequest struct {
		DomainASCII                    string `json:"domain_ascii"`
		AccountIDHex                   string `json:"account_id_hex"`
		OldEpoch                       uint64 `json:"old_epoch"`
		NewEpoch                       uint64 `json:"new_epoch"`
		RequestIDHex                   string `json:"request_id_hex"`
		TargetDeviceIDHex              string `json:"target_device_id_hex"`
		EnrollmentCertificateDigestHex string `json:"enrollment_certificate_digest_sha256_hex"`
		CoreCBORHex                    string `json:"core_cbor_hex"`
		SignedMessageHex               string `json:"signed_message_hex"`
		SignatureHex                   string `json:"signature_hex"`
		RequestCBORHex                 string `json:"request_cbor_hex"`
	} `json:"recovery_request"`
}

func decodeLifecycleHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid fixture hex: %v", err)
	}
	return decoded
}

func lifecycleFixed(t *testing.T, value string, length int) []byte {
	t.Helper()
	decoded := decodeLifecycleHex(t, value)
	if len(decoded) != length {
		t.Fatalf("fixture field has %d bytes; want %d", len(decoded), length)
	}
	return decoded
}

func readLifecycleWireCandidateVector(t *testing.T) lifecycleWireV1CandidateVector {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "test-vectors", "v1", "lifecycle_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared lifecycle candidate vector %q: %v", path, err)
	}
	var vector lifecycleWireV1CandidateVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("decode shared lifecycle candidate vector: %v", err)
	}
	if vector.Schema != "lifecycle-wire-v1-candidate" || vector.Status != "candidate_not_frozen" {
		t.Fatalf("unexpected lifecycle vector metadata: schema=%q status=%q", vector.Schema, vector.Status)
	}
	return vector
}

func TestRecoveryRequestV1CandidateVectorMatchesRustExactly(t *testing.T) {
	v := readLifecycleWireCandidateVector(t)
	recoveryPubBytes := lifecycleFixed(t, v.Recovery.PublicKeyHex, 32)
	var recoveryPub [32]byte
	copy(recoveryPub[:], recoveryPubBytes)
	commitment := RecoveryCommitment(recoveryPub)
	if got := hex.EncodeToString(commitment[:]); got != v.Recovery.CommitmentHex {
		t.Fatalf("recovery commitment mismatch: got %s", got)
	}

	enrollmentRaw := decodeLifecycleHex(t, v.Enrollment.CertificateCBORHex)
	enrollment, err := ParseDeviceEnrollmentAuthorizationV1(enrollmentRaw)
	if err != nil {
		t.Fatalf("parse enrollment fixture: %v", err)
	}
	if err := enrollment.Verify(recoveryPub); err != nil {
		t.Fatalf("verify enrollment fixture: %v", err)
	}
	var expectedEnrollmentAccount [16]byte
	copy(expectedEnrollmentAccount[:], lifecycleFixed(t, v.Enrollment.AccountIDHex, 16))
	if enrollment.AccountID != expectedEnrollmentAccount {
		t.Fatal("enrollment AccountID mismatch")
	}
	if enrollment.Epoch != v.Enrollment.Epoch {
		t.Fatal("enrollment epoch mismatch")
	}
	if got := hex.EncodeToString(enrollment.Signature[:]); got != v.Enrollment.SignatureHex {
		t.Fatal("enrollment signature mismatch")
	}
	enrollmentDigest := sha256.Sum256(enrollmentRaw)
	if got := hex.EncodeToString(enrollmentDigest[:]); got != v.Enrollment.SHACertificateHex {
		t.Fatalf("enrollment exact-byte digest mismatch: got %s", got)
	}
	if _, err := ParseDeviceEnrollmentAuthorizationV1(append(append([]byte(nil), enrollmentRaw...), 0)); err == nil {
		t.Fatal("enrollment parser accepted trailing bytes")
	}

	requestRaw := decodeLifecycleHex(t, v.RecoveryRequest.RequestCBORHex)
	request, err := ParseRecoveryRequestV1(requestRaw)
	if err != nil {
		t.Fatalf("parse recovery-request fixture: %v", err)
	}
	if err := request.Verify(recoveryPub); err != nil {
		t.Fatalf("verify recovery-request fixture: %v", err)
	}
	if err := request.VerifyForEnrollment(recoveryPub, enrollmentRaw); err != nil {
		t.Fatalf("verify request and referenced enrollment: %v", err)
	}
	if request.AccountID != enrollment.AccountID || request.TargetDeviceID != enrollment.DeviceID || request.NewEpoch != enrollment.Epoch {
		t.Fatal("request/enrollment binding mismatch")
	}
	if got := hex.EncodeToString(request.Signature[:]); got != v.RecoveryRequest.SignatureHex {
		t.Fatal("recovery-request signature mismatch")
	}
	if got := hex.EncodeToString(request.EnrollmentCertDigest[:]); got != v.RecoveryRequest.EnrollmentCertificateDigestHex {
		t.Fatal("request enrollment-certificate digest mismatch")
	}
	core, err := request.canonicalCore()
	if err != nil {
		t.Fatalf("encode canonical request core: %v", err)
	}
	if got := hex.EncodeToString(core); got != v.RecoveryRequest.CoreCBORHex {
		t.Fatalf("request core mismatch: got %s", got)
	}
	message := append([]byte(RecoveryRequestDomain), core...)
	if got := hex.EncodeToString(message); got != v.RecoveryRequest.SignedMessageHex {
		t.Fatalf("request signed-message mismatch: got %s", got)
	}
	if got := hex.EncodeToString(request.Raw); got != v.RecoveryRequest.RequestCBORHex {
		t.Fatal("request wire bytes differ from fixture")
	}
}

func signTestEnrollmentForRecoveryRequestV1(t *testing.T, private ed25519.PrivateKey, accountID [16]byte, epoch uint64, deviceID [16]byte, dskPub, ddhkPub [32]byte) []byte {
	t.Helper()
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), uintPair(3, epoch),
		bytesPair(4, deviceID[:]), bytesPair(5, dskPub[:]), bytesPair(6, ddhkPub[:]),
	}})
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(DeviceEnrollmentDomain), core...)
	sig := ed25519.Sign(private, message)
	return mustEncodeLifecycleMap(t, []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), uintPair(3, epoch),
		bytesPair(4, deviceID[:]), bytesPair(5, dskPub[:]), bytesPair(6, ddhkPub[:]), bytesPair(7, sig),
	})
}

func signTestRecoveryRequestV1(t *testing.T, private ed25519.PrivateKey, accountID [16]byte, oldEpoch, newEpoch uint64, requestID, deviceID [16]byte, enrollmentRaw []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(enrollmentRaw)
	corePairs := []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), uintPair(3, oldEpoch),
		uintPair(4, newEpoch), bytesPair(5, requestID[:]), bytesPair(6, deviceID[:]), bytesPair(7, digest[:]),
	}
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: corePairs})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(private, append([]byte(RecoveryRequestDomain), core...))
	corePairs = append(corePairs, bytesPair(8, sig))
	return mustEncodeLifecycleMap(t, corePairs)
}

func mustEncodeLifecycleMap(t *testing.T, pairs []cbor.Pair) []byte {
	t.Helper()
	encoded, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: pairs})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRecoveryRequestV1CandidateRejectsTamperMalformedAndWrongKey(t *testing.T) {
	v := readLifecycleWireCandidateVector(t)
	pubBytes := lifecycleFixed(t, v.Recovery.PublicKeyHex, 32)
	var pub [32]byte
	copy(pub[:], pubBytes)
	raw := decodeLifecycleHex(t, v.RecoveryRequest.RequestCBORHex)
	request, err := ParseRecoveryRequestV1(raw)
	if err != nil {
		t.Fatal(err)
	}

	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var wrong [32]byte
	copy(wrong[:], wrongPublic)
	if err := request.Verify(wrong); err == nil {
		t.Fatal("request verified under wrong recovery key")
	}

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 1
	parsedTampered, err := ParseRecoveryRequestV1(tampered)
	if err != nil {
		t.Fatalf("signature tamper should remain structurally parseable: %v", err)
	}
	if err := parsedTampered.Verify(pub); err == nil {
		t.Fatal("tampered signature was accepted")
	}
	if _, err := ParseRecoveryRequestV1(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated request was accepted")
	}
	if _, err := ParseRecoveryRequestV1(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("request with trailing bytes was accepted")
	}
}

func TestRecoveryRequestV1CandidateBindsExactEnrollmentAndSameRecoveryKey(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryPubA, recoveryPubB [32]byte
	copy(recoveryPubA[:], pubA)
	copy(recoveryPubB[:], pubB)
	var accountID, deviceID, requestID [16]byte
	accountID[0], deviceID[0], requestID[0] = 0x11, 0x22, 0x66
	var dskA, dskB, ddhk [32]byte
	dskA[0], dskB[0], ddhk[0] = 0x33, 0x34, 0x44
	enrollmentA := signTestEnrollmentForRecoveryRequestV1(t, privA, accountID, 4, deviceID, dskA, ddhk)
	enrollmentB := signTestEnrollmentForRecoveryRequestV1(t, privA, accountID, 4, deviceID, dskB, ddhk)
	requestRawA := signTestRecoveryRequestV1(t, privA, accountID, 3, 4, requestID, deviceID, enrollmentA)
	requestA, err := ParseRecoveryRequestV1(requestRawA)
	if err != nil {
		t.Fatal(err)
	}
	if err := requestA.VerifyForEnrollment(recoveryPubA, enrollmentA); err != nil {
		t.Fatalf("matching request/enrollment should verify: %v", err)
	}
	if err := requestA.VerifyForEnrollment(recoveryPubA, enrollmentB); err == nil {
		t.Fatal("valid but different enrollment certificate passed exact digest binding")
	}

	requestRawB := signTestRecoveryRequestV1(t, privB, accountID, 3, 4, requestID, deviceID, enrollmentA)
	requestB, err := ParseRecoveryRequestV1(requestRawB)
	if err != nil {
		t.Fatal(err)
	}
	if err := requestB.VerifyForEnrollment(recoveryPubA, enrollmentA); err == nil {
		t.Fatal("request signed by a different recovery key was accepted")
	}
	if err := requestB.VerifyForEnrollment(recoveryPubB, enrollmentA); err == nil {
		t.Fatal("enrollment signed by a different recovery key was accepted")
	}
}

func TestRecoveryRequestV1CandidateRejectsEpochAndIdentifierBoundaries(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var accountID, deviceID, requestID [16]byte
	accountID[0], deviceID[0], requestID[0] = 1, 2, 3
	var dsk, ddhk [32]byte
	enrollment := signTestEnrollmentForRecoveryRequestV1(t, private, accountID, LifecycleWireV1MaxEpoch, deviceID, dsk, ddhk)
	goodRequestRaw := signTestRecoveryRequestV1(t, private, accountID, LifecycleWireV1MaxEpoch-1, LifecycleWireV1MaxEpoch, requestID, deviceID, enrollment)
	if _, err := ParseRecoveryRequestV1(goodRequestRaw); err != nil {
		t.Fatalf("maximum valid new epoch should parse: %v", err)
	}
	tooHighRaw := signTestRecoveryRequestV1(t, private, accountID, LifecycleWireV1MaxEpoch, LifecycleWireV1MaxEpoch+1, requestID, deviceID, enrollment)
	if _, err := ParseRecoveryRequestV1(tooHighRaw); err == nil {
		t.Fatal("out-of-range epoch was accepted")
	}
	zeroID := [16]byte{}
	zeroRequestRaw := signTestRecoveryRequestV1(t, private, accountID, 1, 2, zeroID, deviceID, enrollment)
	if _, err := ParseRecoveryRequestV1(zeroRequestRaw); err == nil {
		t.Fatal("zero request ID was accepted")
	}
}
