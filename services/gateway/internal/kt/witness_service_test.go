package kt

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

func newWitnessVerifierFromVector(t *testing.T, v equivocationVector) *WitnessVerifier {
	t.Helper()

	registry := make(map[[16]byte][32]byte, len(v.WitnessRegistry))
	for _, entry := range v.WitnessRegistry {
		id := mustFixed16(t, entry.WitnessIDHex)
		registry[id] = mustFixed32(t, entry.PublicKeyHex)
	}

	verifier, err := NewWitnessVerifier(registry)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func loadVectorSTH(t *testing.T, v equivocationVector, raw string) SignedTreeHeadV1 {
	t.Helper()

	logPublic := mustFixed32(t, v.Log.PublicKeyHex)
	sth, err := VerifySignedTreeHeadV1(mustVerifyHex(t, raw), logPublic)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}

func TestWitnessVerifierQuorumTwoOfThree(t *testing.T) {
	v := loadEquivocationVector(t)
	verifier := newWitnessVerifierFromVector(t, v)
	sth := loadVectorSTH(t, v, v.STHAHex)

	statements := [][]byte{
		mustVerifyHex(t, v.WitnessRegistry[0].StatementHex),
		mustVerifyHex(t, v.WitnessRegistry[1].StatementHex),
	}

	result, err := verifier.Verify(sth, statements)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != WitnessStateVerified {
		t.Fatalf("state = %d, want VERIFIED", result.State)
	}
	if result.AgreeingCount != 2 {
		t.Fatalf("agreeing count = %d, want 2", result.AgreeingCount)
	}
}

func TestWitnessVerifierDegradedWithOneWitness(t *testing.T) {
	v := loadEquivocationVector(t)
	verifier := newWitnessVerifierFromVector(t, v)
	sth := loadVectorSTH(t, v, v.STHAHex)

	statements := [][]byte{
		mustVerifyHex(t, v.WitnessRegistry[0].StatementHex),
	}

	result, err := verifier.Verify(sth, statements)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != WitnessStateDegraded {
		t.Fatalf("state = %d, want DEGRADED", result.State)
	}
	if result.AgreeingCount != 1 {
		t.Fatalf("agreeing count = %d, want 1", result.AgreeingCount)
	}
}

func TestWitnessVerifierDetectsConflictingValidStatements(t *testing.T) {
	v := loadEquivocationVector(t)
	verifier := newWitnessVerifierFromVector(t, v)
	sth := loadVectorSTH(t, v, v.STHAHex)

	statements := [][]byte{
		mustVerifyHex(t, v.WitnessRegistry[0].StatementHex),
		mustVerifyHex(t, v.WitnessRegistry[1].StatementHex),
		mustVerifyHex(t, v.WitnessRegistry[2].StatementHex),
	}

	result, err := verifier.Verify(sth, statements)
	if !errors.Is(err, ErrWitnessQuorumConflict) {
		t.Fatalf("error = %v, want ErrWitnessQuorumConflict", err)
	}
	if result.State != WitnessStateSecurityFailure {
		t.Fatalf("state = %d, want SECURITY_FAILURE", result.State)
	}
}

func TestWitnessVerifierRejectsInvalidWitnessSignature(t *testing.T) {
	v := loadEquivocationVector(t)
	verifier := newWitnessVerifierFromVector(t, v)
	sth := loadVectorSTH(t, v, v.STHAHex)

	tampered := mustVerifyHex(t, v.WitnessRegistry[0].StatementHex)
	tampered[len(tampered)-1] ^= 0x01

	result, err := verifier.Verify(sth, [][]byte{tampered})
	if err == nil {
		t.Fatal("tampered witness statement accepted")
	}
	if result.State != WitnessStateSecurityFailure {
		t.Fatalf("state = %d, want SECURITY_FAILURE", result.State)
	}
}

func TestWitnessVerifierRequiresExactlyThreeConfiguredWitnesses(t *testing.T) {
	v := loadEquivocationVector(t)

	registry := make(map[[16]byte][32]byte, 2)
	for _, entry := range v.WitnessRegistry[:2] {
		id := mustFixed16(t, entry.WitnessIDHex)
		registry[id] = mustFixed32(t, entry.PublicKeyHex)
	}

	if _, err := NewWitnessVerifier(registry); !errors.Is(err, ErrInvalidWitnessRegistry) {
		t.Fatalf("error = %v, want ErrInvalidWitnessRegistry", err)
	}
}

func TestWitnessVerifierDetectsSameWitnessConflictingDigests(t *testing.T) {
	witnessID := [16]byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
	}

	logID := [32]byte{0x02}

	var digestA [32]byte
	var digestB [32]byte
	digestA[0] = 0xaa
	digestB[0] = 0xbb

	statements := []WitnessStatementV1{
		{
			WitnessID: witnessID,
			LogID:     logID,
			TreeSize:  32,
			STHDigest: digestA,
		},
		{
			WitnessID: witnessID,
			LogID:     logID,
			TreeSize:  32,
			STHDigest: digestB,
		},
	}

	if !WitnessConflictExists(statements) {
		t.Fatal("expected same-witness conflicting digests to be detected")
	}
}

func makeWitnessKeyPair(seedByte byte) (ed25519.PrivateKey, [32]byte) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = seedByte

	private := ed25519.NewKeyFromSeed(seed)

	var public [32]byte
	copy(public[:], private.Public().(ed25519.PublicKey))

	return private, public
}

func makeSignedWitnessStatement(
	t *testing.T,
	private ed25519.PrivateKey,
	witnessID [16]byte,
	logID [32]byte,
	treeSize uint64,
	sthDigest [32]byte,
) []byte {
	t.Helper()

	statement := WitnessStatementV1{
		WitnessID: witnessID,
		LogID:     logID,
		TreeSize:  treeSize,
		STHDigest: sthDigest,
	}

	body := witnessBodyValue(statement)

	canonicalBody, err := cbor.EncodeCanonical(body)
	if err != nil {
		t.Fatal(err)
	}

	message := append([]byte(witnessSignDomain), canonicalBody...)
	signature := ed25519.Sign(private, message)

	raw := cbor.Value{
		Kind: cbor.KindMap,
		Map:  append(body.Map, bytesPair(6, signature)),
	}

	encoded, err := cbor.EncodeCanonical(raw)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func TestWitnessVerifierDetectsSameWitnessConflictingDigestsThroughVerify(t *testing.T) {
	privateA, publicA := makeWitnessKeyPair(1)
	_, publicB := makeWitnessKeyPair(2)
	_, publicC := makeWitnessKeyPair(3)

	witnessA := [16]byte{0x01}
	witnessB := [16]byte{0x02}
	witnessC := [16]byte{0x03}

	registry := map[[16]byte][32]byte{
		witnessA: publicA,
		witnessB: publicB,
		witnessC: publicC,
	}

	verifier, err := NewWitnessVerifier(registry)
	if err != nil {
		t.Fatal(err)
	}

	var logID [32]byte
	logID[0] = 0x09

	var digestA [32]byte
	digestA[0] = 0xaa

	var digestB [32]byte
	digestB[0] = 0xbb

	sth := SignedTreeHeadV1{
		LogID:     logID,
		TreeSize:  32,
		STHDigest: digestA,
	}

	statementA := makeSignedWitnessStatement(
		t,
		privateA,
		witnessA,
		logID,
		32,
		digestA,
	)

	statementB := makeSignedWitnessStatement(
		t,
		privateA,
		witnessA,
		logID,
		32,
		digestB,
	)

	result, err := verifier.Verify(
		sth,
		[][]byte{statementA, statementB},
	)

	if !errors.Is(err, ErrWitnessQuorumConflict) {
		t.Fatalf("error = %v, want ErrWitnessQuorumConflict", err)
	}

	if result.State != WitnessStateSecurityFailure {
		t.Fatalf(
			"state = %d, want SECURITY_FAILURE",
			result.State,
		)
	}
}
