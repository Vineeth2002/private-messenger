package authorization

import (
	"crypto/ed25519"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

func signedEnrollmentForEpochTest(t *testing.T, private ed25519.PrivateKey, accountID, deviceID [16]byte, epoch uint64) []byte {
	t.Helper()
	var dsk, ddhk [32]byte
	dsk[0], ddhk[0] = 1, 2
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, accountID[:]),
		uintPair(3, epoch),
		bytesPair(4, deviceID[:]),
		bytesPair(5, dsk[:]),
		bytesPair(6, ddhk[:]),
	}})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte(DeviceEnrollmentDomain), core...))
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, accountID[:]),
		uintPair(3, epoch),
		bytesPair(4, deviceID[:]),
		bytesPair(5, dsk[:]),
		bytesPair(6, ddhk[:]),
		bytesPair(7, signature),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signedTransitionForEpochTest(t *testing.T, private ed25519.PrivateKey, accountID, deviceID [16]byte, oldEpoch, newEpoch uint64) []byte {
	t.Helper()
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, accountID[:]),
		uintPair(3, oldEpoch),
		uintPair(4, newEpoch),
		uintPair(5, uint64(RevokeDeviceAction)),
		bytesPair(6, deviceID[:]),
	}})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte(EpochTransitionDomain), core...))
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, accountID[:]),
		uintPair(3, oldEpoch),
		uintPair(4, newEpoch),
		uintPair(5, uint64(RevokeDeviceAction)),
		bytesPair(6, deviceID[:]),
		bytesPair(7, signature),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLifecycleCertificateEpochDomainIsEnforced(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var accountID, deviceID [16]byte
	accountID[15], deviceID[15] = 1, 2
	var recoveryPublic [32]byte
	copy(recoveryPublic[:], public)
	max := LifecycleWireV1MaxEpoch
	u64Max := ^uint64(0)

	// The maximum is inclusive for enrollment and as the destination of a transition.
	enrollmentAtMax, err := ParseDeviceEnrollmentAuthorizationV1(
		signedEnrollmentForEpochTest(t, private, accountID, deviceID, max),
	)
	if err != nil {
		t.Fatalf("enrollment at max epoch rejected: %v", err)
	}
	if err := enrollmentAtMax.Verify(recoveryPublic); err != nil {
		t.Fatalf("enrollment signature at max epoch rejected: %v", err)
	}

	// Zero, max+1, and the full uint64 maximum must be rejected by both
	// parsing correctly signed wire objects and verifying constructed values.
	for _, epoch := range []uint64{0, max + 1, u64Max} {
		if _, err := ParseDeviceEnrollmentAuthorizationV1(
			signedEnrollmentForEpochTest(t, private, accountID, deviceID, epoch),
		); err == nil {
			t.Fatalf("enrollment parser accepted epoch %d", epoch)
		}
		invalid := DeviceEnrollmentAuthorizationV1{
			Raw: signedEnrollmentForEpochTest(t, private, accountID, deviceID, epoch),
			AccountID: accountID, DeviceID: deviceID, Epoch: epoch,
			DSKPub: [32]byte{1}, DDHKPub: [32]byte{2},
		}
		core, err := invalid.canonicalCore()
		if err != nil {
			t.Fatal(err)
		}
		copy(invalid.Signature[:], ed25519.Sign(private, append([]byte(DeviceEnrollmentDomain), core...)))
		if err := invalid.Verify(recoveryPublic); err == nil {
			t.Fatalf("enrollment verifier accepted epoch %d", epoch)
		}
	}

	transitionAtMax, err := ParseEpochTransitionAuthorizationV1(
		signedTransitionForEpochTest(t, private, accountID, deviceID, max-1, max),
	)
	if err != nil {
		t.Fatalf("transition to max epoch rejected: %v", err)
	}
	if err := transitionAtMax.Verify(recoveryPublic); err != nil {
		t.Fatalf("transition signature to max epoch rejected: %v", err)
	}

	// old=u64Max/new=0 specifically proves boundary checks precede oldEpoch+1.
	invalidTransitions := []struct {
		oldEpoch uint64
		newEpoch uint64
	}{
		{oldEpoch: 0, newEpoch: 1},
		{oldEpoch: 1, newEpoch: 0},
		{oldEpoch: max, newEpoch: max + 1},
		{oldEpoch: 1, newEpoch: u64Max},
		{oldEpoch: u64Max, newEpoch: 0},
	}
	for _, value := range invalidTransitions {
		if _, err := ParseEpochTransitionAuthorizationV1(
			signedTransitionForEpochTest(t, private, accountID, deviceID, value.oldEpoch, value.newEpoch),
		); err == nil {
			t.Fatalf("transition parser accepted %d -> %d", value.oldEpoch, value.newEpoch)
		}
		invalid := EpochTransitionAuthorizationV1{
			Raw: signedTransitionForEpochTest(t, private, accountID, deviceID, value.oldEpoch, value.newEpoch),
			AccountID: accountID, OldEpoch: value.oldEpoch, NewEpoch: value.newEpoch,
			Action: RevokeDeviceAction, DeviceID: deviceID,
		}
		core, err := invalid.canonicalCore()
		if err != nil {
			t.Fatal(err)
		}
		copy(invalid.Signature[:], ed25519.Sign(private, append([]byte(EpochTransitionDomain), core...)))
		if err := invalid.Verify(recoveryPublic); err == nil {
			t.Fatalf("transition verifier accepted %d -> %d", value.oldEpoch, value.newEpoch)
		}
	}

	a := NewAuthorizer()
	for _, epoch := range []uint64{0, max + 1, u64Max} {
		if err := a.EnsureAccount(accountID, epoch, RecoveryCommitment(recoveryPublic), recoveryPublic); err == nil {
			t.Fatalf("in-memory account accepted epoch %d", epoch)
		}
	}
	if err := a.EnsureAccount(accountID, max, RecoveryCommitment(recoveryPublic), recoveryPublic); err != nil {
		t.Fatalf("in-memory account rejected max epoch: %v", err)
	}
}
