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

type deviceEnrollmentPoPCandidateFixture struct {
	Schema   string `json:"schema"`
	Status   string `json:"status"`
	Recovery struct {
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"recovery"`
	PopEnrollmentCertificate struct {
		AccountIDHex         string `json:"account_id_hex"`
		Epoch                uint64 `json:"epoch"`
		DeviceIDHex          string `json:"device_id_hex"`
		DSKPublicKeyHex      string `json:"dsk_public_key_hex"`
		SHA256CertificateHex string `json:"sha256_certificate_hex"`
		CertificateCBORHex   string `json:"certificate_cbor_hex"`
	} `json:"pop_enrollment_certificate"`
	DeviceEnrollmentPoP struct {
		DomainASCII                    string `json:"domain_ascii"`
		AccountIDHex                   string `json:"account_id_hex"`
		DeviceIDHex                    string `json:"device_id_hex"`
		Epoch                          uint64 `json:"epoch"`
		EnrollmentCertificateDigestHex string `json:"enrollment_certificate_digest_sha256_hex"`
		ChallengeIDHex                 string `json:"challenge_id_hex"`
		ChallengeNonceHex              string `json:"challenge_nonce_hex"`
		CoreCBORHex                    string `json:"core_cbor_hex"`
		SignedMessageHex               string `json:"signed_message_hex"`
		SignatureHex                   string `json:"signature_hex"`
		ProofCBORHex                   string `json:"proof_cbor_hex"`
	} `json:"device_enrollment_pop"`
}

func readDeviceEnrollmentPoPCandidateFixture(t *testing.T) deviceEnrollmentPoPCandidateFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "test-vectors", "v1", "lifecycle_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lifecycle candidate fixture %q: %v", path, err)
	}
	var fixture deviceEnrollmentPoPCandidateFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode lifecycle candidate fixture: %v", err)
	}
	if fixture.Schema != "lifecycle-wire-v1-candidate" || fixture.Status != "candidate_not_frozen" {
		t.Fatalf("unexpected lifecycle candidate metadata: schema=%q status=%q", fixture.Schema, fixture.Status)
	}
	if fixture.DeviceEnrollmentPoP.DomainASCII != DeviceEnrollmentPoPDomain {
		t.Fatal("unexpected DeviceEnrollmentPoPV1 domain")
	}
	return fixture
}

func decodeDeviceEnrollmentPoPHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid lifecycle fixture hex: %v", err)
	}
	return out
}

func fixedDeviceEnrollmentPoPBytes(t *testing.T, value string, length int) []byte {
	t.Helper()
	out := decodeDeviceEnrollmentPoPHex(t, value)
	if len(out) != length {
		t.Fatalf("fixture field length=%d, want %d", len(out), length)
	}
	return out
}

func deviceEnrollmentPoPWireForTest(t *testing.T, accountID, deviceID [16]byte, epoch uint64, digest [32]byte, challengeID [16]byte, nonce [32]byte, signature [64]byte) []byte {
	t.Helper()
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), bytesPair(3, deviceID[:]),
		uintPair(4, epoch), bytesPair(5, digest[:]), bytesPair(6, challengeID[:]), bytesPair(7, nonce[:]), bytesPair(8, signature[:]),
	}})
	if err != nil {
		t.Fatalf("encode test PoP wire: %v", err)
	}
	return raw
}

func TestDeviceEnrollmentPoPV1CandidateVectorMatchesRustExactly(t *testing.T) {
	fixture := readDeviceEnrollmentPoPCandidateFixture(t)
	recoveryBytes := fixedDeviceEnrollmentPoPBytes(t, fixture.Recovery.PublicKeyHex, 32)
	var recoveryPub [32]byte
	copy(recoveryPub[:], recoveryBytes)
	enrollmentRaw := decodeDeviceEnrollmentPoPHex(t, fixture.PopEnrollmentCertificate.CertificateCBORHex)
	enrollment, err := ParseDeviceEnrollmentAuthorizationV1(enrollmentRaw)
	if err != nil {
		t.Fatalf("parse candidate PoP enrollment certificate: %v", err)
	}
	if err := enrollment.Verify(recoveryPub); err != nil {
		t.Fatalf("verify recovery-signed PoP enrollment certificate: %v", err)
	}
	if got := hex.EncodeToString(enrollmentRaw); got != fixture.PopEnrollmentCertificate.CertificateCBORHex {
		t.Fatal("enrollment raw bytes changed")
	}
	if got := hex.EncodeToString(enrollment.DSKPub[:]); got != fixture.PopEnrollmentCertificate.DSKPublicKeyHex {
		t.Fatalf("DSK mismatch: %s", got)
	}
	if got := hex.EncodeToString(enrollment.AccountID[:]); got != fixture.PopEnrollmentCertificate.AccountIDHex {
		t.Fatal("enrollment account ID mismatch")
	}
	if got := hex.EncodeToString(enrollment.DeviceID[:]); got != fixture.PopEnrollmentCertificate.DeviceIDHex {
		t.Fatal("enrollment device ID mismatch")
	}
	if enrollment.Epoch != fixture.PopEnrollmentCertificate.Epoch {
		t.Fatal("enrollment epoch mismatch")
	}
	certificateDigest := sha256.Sum256(enrollmentRaw)
	if got := hex.EncodeToString(certificateDigest[:]); got != fixture.PopEnrollmentCertificate.SHA256CertificateHex {
		t.Fatal("exact complete enrollment certificate digest mismatch")
	}

	proofRaw := decodeDeviceEnrollmentPoPHex(t, fixture.DeviceEnrollmentPoP.ProofCBORHex)
	proof, err := ParseDeviceEnrollmentPoPV1(proofRaw)
	if err != nil {
		t.Fatalf("parse DeviceEnrollmentPoPV1 candidate: %v", err)
	}
	challengeIDBytes := fixedDeviceEnrollmentPoPBytes(t, fixture.DeviceEnrollmentPoP.ChallengeIDHex, 16)
	challengeNonceBytes := fixedDeviceEnrollmentPoPBytes(t, fixture.DeviceEnrollmentPoP.ChallengeNonceHex, 32)
	var challengeID [16]byte
	var challengeNonce [32]byte
	copy(challengeID[:], challengeIDBytes)
	copy(challengeNonce[:], challengeNonceBytes)
	if err := proof.VerifyForEnrollmentAndChallenge(recoveryPub, enrollmentRaw, challengeID, challengeNonce); err != nil {
		t.Fatalf("verify PoP against the exact enrollment certificate and fixture challenge: %v", err)
	}
	if got := hex.EncodeToString(proof.AccountID[:]); got != fixture.DeviceEnrollmentPoP.AccountIDHex {
		t.Fatal("PoP account ID mismatch")
	}
	if got := hex.EncodeToString(proof.DeviceID[:]); got != fixture.DeviceEnrollmentPoP.DeviceIDHex {
		t.Fatal("PoP device ID mismatch")
	}
	if proof.Epoch != fixture.DeviceEnrollmentPoP.Epoch {
		t.Fatal("PoP epoch mismatch")
	}
	if got := hex.EncodeToString(proof.EnrollmentCertificateDigest[:]); got != fixture.DeviceEnrollmentPoP.EnrollmentCertificateDigestHex {
		t.Fatal("PoP enrollment digest mismatch")
	}
	if got := hex.EncodeToString(proof.Signature[:]); got != fixture.DeviceEnrollmentPoP.SignatureHex {
		t.Fatal("PoP signature mismatch")
	}
	if got := hex.EncodeToString(proof.Raw); got != fixture.DeviceEnrollmentPoP.ProofCBORHex {
		t.Fatal("PoP raw bytes mismatch")
	}

	core, err := proof.canonicalCore()
	if err != nil {
		t.Fatalf("encode canonical PoP core: %v", err)
	}
	if got := hex.EncodeToString(core); got != fixture.DeviceEnrollmentPoP.CoreCBORHex {
		t.Fatalf("PoP core mismatch: %s", got)
	}
	signedMessage := append([]byte(DeviceEnrollmentPoPDomain), core...)
	if got := hex.EncodeToString(signedMessage); got != fixture.DeviceEnrollmentPoP.SignedMessageHex {
		t.Fatalf("PoP signed-message mismatch: %s", got)
	}
}

func TestDeviceEnrollmentPoPV1CandidateRejectsWrongKeysAndMismatchedCertificateOrChallenge(t *testing.T) {
	fixture := readDeviceEnrollmentPoPCandidateFixture(t)
	var recoveryPub [32]byte
	copy(recoveryPub[:], decodeDeviceEnrollmentPoPHex(t, fixture.Recovery.PublicKeyHex))
	enrollmentRaw := decodeDeviceEnrollmentPoPHex(t, fixture.PopEnrollmentCertificate.CertificateCBORHex)
	proofRaw := decodeDeviceEnrollmentPoPHex(t, fixture.DeviceEnrollmentPoP.ProofCBORHex)
	proof, err := ParseDeviceEnrollmentPoPV1(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	challengeIDBytes := decodeDeviceEnrollmentPoPHex(t, fixture.DeviceEnrollmentPoP.ChallengeIDHex)
	challengeNonceBytes := decodeDeviceEnrollmentPoPHex(t, fixture.DeviceEnrollmentPoP.ChallengeNonceHex)
	var challengeID [16]byte
	var challengeNonce [32]byte
	copy(challengeID[:], challengeIDBytes)
	copy(challengeNonce[:], challengeNonceBytes)

	wrongPubBytes, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var wrongPub [32]byte
	copy(wrongPub[:], wrongPubBytes)
	if err := proof.Verify(wrongPub); err == nil {
		t.Fatal("PoP accepted wrong DSK public key")
	}
	if err := proof.VerifyForEnrollmentAndChallenge(wrongPub, enrollmentRaw, challengeID, challengeNonce); err == nil {
		t.Fatal("PoP accepted wrong recovery public key")
	}
	changedID := challengeID
	changedID[0] ^= 1
	if err := proof.VerifyForEnrollmentAndChallenge(recoveryPub, enrollmentRaw, changedID, challengeNonce); err == nil {
		t.Fatal("PoP accepted mismatched challenge ID")
	}
	changedNonce := challengeNonce
	changedNonce[0] ^= 1
	if err := proof.VerifyForEnrollmentAndChallenge(recoveryPub, enrollmentRaw, challengeID, changedNonce); err == nil {
		t.Fatal("PoP accepted mismatched challenge nonce")
	}
	changedCertificate := append([]byte(nil), enrollmentRaw...)
	changedCertificate[len(changedCertificate)-1] ^= 1
	if err := proof.VerifyForEnrollmentAndChallenge(recoveryPub, changedCertificate, challengeID, challengeNonce); err == nil {
		t.Fatal("PoP accepted a certificate whose exact signed bytes differ")
	}

	tampered := append([]byte(nil), proofRaw...)
	tampered[len(tampered)-1] ^= 1
	tamperedProof, err := ParseDeviceEnrollmentPoPV1(tampered)
	if err != nil {
		t.Fatalf("signature tamper should remain structurally parseable: %v", err)
	}
	enrollment, err := ParseDeviceEnrollmentAuthorizationV1(enrollmentRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := tamperedProof.Verify(enrollment.DSKPub); err == nil {
		t.Fatal("tampered PoP signature was accepted")
	}
}

func makeDeviceEnrollmentPoPCertificateForTest(t *testing.T, recoveryPrivate ed25519.PrivateKey, accountID, deviceID [16]byte, epoch uint64, dskPub, ddhkPub [32]byte) []byte {
	t.Helper()
	corePairs := []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), uintPair(3, epoch),
		bytesPair(4, deviceID[:]), bytesPair(5, dskPub[:]), bytesPair(6, ddhkPub[:]),
	}
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: corePairs})
	if err != nil {
		t.Fatalf("encode test enrollment core: %v", err)
	}
	signature := ed25519.Sign(recoveryPrivate, append([]byte(DeviceEnrollmentDomain), core...))
	wirePairs := append(append([]cbor.Pair(nil), corePairs...), bytesPair(7, signature))
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: wirePairs})
	if err != nil {
		t.Fatalf("encode test enrollment certificate: %v", err)
	}
	return raw
}

func makeDeviceEnrollmentPoPProofForTest(t *testing.T, devicePrivate ed25519.PrivateKey, accountID, deviceID [16]byte, epoch uint64, certificateDigest [32]byte, challengeID [16]byte, nonce [32]byte) []byte {
	t.Helper()
	corePairs := []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion), bytesPair(2, accountID[:]), bytesPair(3, deviceID[:]),
		uintPair(4, epoch), bytesPair(5, certificateDigest[:]), bytesPair(6, challengeID[:]), bytesPair(7, nonce[:]),
	}
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: corePairs})
	if err != nil {
		t.Fatalf("encode test PoP core: %v", err)
	}
	signature := ed25519.Sign(devicePrivate, append([]byte(DeviceEnrollmentPoPDomain), core...))
	wirePairs := append(append([]cbor.Pair(nil), corePairs...), bytesPair(8, signature))
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: wirePairs})
	if err != nil {
		t.Fatalf("encode test PoP proof: %v", err)
	}
	return raw
}

func TestDeviceEnrollmentPoPV1RejectsDigestMismatchBetweenTwoValidCertificates(t *testing.T) {
	recoveryPubBytes, recoveryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryPub [32]byte
	copy(recoveryPub[:], recoveryPubBytes)
	devicePubBytes, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var devicePub [32]byte
	copy(devicePub[:], devicePubBytes)
	var accountID, deviceID, challengeID [16]byte
	accountID[0], deviceID[0], challengeID[0] = 0x81, 0x82, 0x83
	var ddhkA, ddhkB, nonce [32]byte
	ddhkA[0], ddhkB[0], nonce[0] = 0x91, 0x92, 0x93
	certA := makeDeviceEnrollmentPoPCertificateForTest(t, recoveryPrivate, accountID, deviceID, 9, devicePub, ddhkA)
	certB := makeDeviceEnrollmentPoPCertificateForTest(t, recoveryPrivate, accountID, deviceID, 9, devicePub, ddhkB)
	parsedA, err := ParseDeviceEnrollmentAuthorizationV1(certA)
	if err != nil {
		t.Fatal(err)
	}
	parsedB, err := ParseDeviceEnrollmentAuthorizationV1(certB)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsedA.Verify(recoveryPub); err != nil {
		t.Fatalf("first valid certificate failed signature: %v", err)
	}
	if err := parsedB.Verify(recoveryPub); err != nil {
		t.Fatalf("second valid certificate failed signature: %v", err)
	}
	digestA := sha256.Sum256(certA)
	proofRaw := makeDeviceEnrollmentPoPProofForTest(t, devicePrivate, accountID, deviceID, 9, digestA, challengeID, nonce)
	proof, err := ParseDeviceEnrollmentPoPV1(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyForEnrollmentAndChallenge(recoveryPub, certA, challengeID, nonce); err != nil {
		t.Fatalf("proof should verify against the exact certificate it signed: %v", err)
	}
	if err := proof.VerifyForEnrollmentAndChallenge(recoveryPub, certB, challengeID, nonce); err == nil {
		t.Fatal("proof was accepted for a different valid certificate with matching account/device/epoch but different exact digest")
	}
}

func TestDeviceEnrollmentPoPV1CandidateRejectsMalformedInputAndBounds(t *testing.T) {
	fixture := readDeviceEnrollmentPoPCandidateFixture(t)
	raw := decodeDeviceEnrollmentPoPHex(t, fixture.DeviceEnrollmentPoP.ProofCBORHex)
	if _, err := ParseDeviceEnrollmentPoPV1(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated PoP was accepted")
	}
	if _, err := ParseDeviceEnrollmentPoPV1(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("PoP with trailing bytes was accepted")
	}
	parsed, err := ParseDeviceEnrollmentPoPV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	zeroAccount := parsed.AccountID
	zeroAccount = [16]byte{}
	if _, err := ParseDeviceEnrollmentPoPV1(deviceEnrollmentPoPWireForTest(t, zeroAccount, parsed.DeviceID, parsed.Epoch, parsed.EnrollmentCertificateDigest, parsed.ChallengeID, parsed.ChallengeNonce, parsed.Signature)); err == nil {
		t.Fatal("PoP with zero AccountID was accepted")
	}
	zeroChallenge := [16]byte{}
	if _, err := ParseDeviceEnrollmentPoPV1(deviceEnrollmentPoPWireForTest(t, parsed.AccountID, parsed.DeviceID, parsed.Epoch, parsed.EnrollmentCertificateDigest, zeroChallenge, parsed.ChallengeNonce, parsed.Signature)); err == nil {
		t.Fatal("PoP with zero challenge ID was accepted")
	}
	if _, err := ParseDeviceEnrollmentPoPV1(deviceEnrollmentPoPWireForTest(t, parsed.AccountID, parsed.DeviceID, LifecycleWireV1MaxEpoch+1, parsed.EnrollmentCertificateDigest, parsed.ChallengeID, parsed.ChallengeNonce, parsed.Signature)); err == nil {
		t.Fatal("PoP epoch above candidate maximum was accepted")
	}
	if _, err := ParseDeviceEnrollmentPoPV1(deviceEnrollmentPoPWireForTest(t, parsed.AccountID, parsed.DeviceID, 0, parsed.EnrollmentCertificateDigest, parsed.ChallengeID, parsed.ChallengeNonce, parsed.Signature)); err == nil {
		t.Fatal("zero PoP epoch was accepted")
	}
}
