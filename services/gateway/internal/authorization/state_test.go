package authorization

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

func testEnrollmentCert(t *testing.T, priv ed25519.PrivateKey, accountID, deviceID [16]byte, epoch uint64, dsk, ddhk [32]byte) DeviceEnrollmentAuthorizationV1 {
	t.Helper()
	core, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, 1), bytesPair(2, accountID[:]), uintPair(3, epoch), bytesPair(4, deviceID[:]), bytesPair(5, dsk[:]), bytesPair(6, ddhk[:]),
	}})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, append([]byte(DeviceEnrollmentDomain), core...))
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, 1), bytesPair(2, accountID[:]), uintPair(3, epoch), bytesPair(4, deviceID[:]), bytesPair(5, dsk[:]), bytesPair(6, ddhk[:]), bytesPair(7, sig),
	}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseDeviceEnrollmentAuthorizationV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestEnrollmentAuthorizationVerifyAndReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var account, device [16]byte
	account[15] = 1
	device[15] = 2
	var dsk, ddhk [32]byte
	dsk[0] = 1
	ddhk[0] = 2
	var pubArr [32]byte
	copy(pubArr[:], pub)
	var cmt [32]byte
	cmt = RecoveryCommitment(pubArr)
	a := NewAuthorizer()
	if err := a.EnsureAccount(account, 1, cmt, pubArr); err != nil {
		t.Fatal(err)
	}
	cert := testEnrollmentCert(t, priv, account, device, 1, dsk, ddhk)
	if err := a.Enroll(cert, pubArr); err != nil {
		t.Fatal(err)
	}
	if err := a.Enroll(cert, pubArr); err != nil {
		t.Fatal(err)
	}
	leaf := kt.TransparencyLeafV1{AccountID: account, Epoch: 1, DeviceID: device, DSKPub: dsk, DDHKPub: ddhk}
	if err := a.ValidateLeaf(leaf); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCommitmentRejectsWrongPublicKey(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	var a, b [32]byte
	copy(a[:], pub1)
	copy(b[:], pub2)
	if VerifyRecoveryCommitment(RecoveryCommitment(a), b) {
		t.Fatal("accepted wrong recovery public key")
	}
}

func testTransitionCert(
	t *testing.T,
	priv ed25519.PrivateKey,
	accountID, deviceID [16]byte,
	oldEpoch, newEpoch uint64,
	action EpochTransitionAction,
) EpochTransitionAuthorizationV1 {
	t.Helper()

	target := deviceID[:]
	if action == RecoveryResetAction {
		target = []byte{}
	}

	core, err := cbor.EncodeCanonical(cbor.Value{
		Kind: cbor.KindMap,
		Map: []cbor.Pair{
			uintPair(1, 1),
			bytesPair(2, accountID[:]),
			uintPair(3, oldEpoch),
			uintPair(4, newEpoch),
			uintPair(5, uint64(action)),
			bytesPair(6, target),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	sig := ed25519.Sign(priv, append([]byte(EpochTransitionDomain), core...))

	raw, err := cbor.EncodeCanonical(cbor.Value{
		Kind: cbor.KindMap,
		Map: []cbor.Pair{
			uintPair(1, 1),
			bytesPair(2, accountID[:]),
			uintPair(3, oldEpoch),
			uintPair(4, newEpoch),
			uintPair(5, uint64(action)),
			bytesPair(6, target),
			bytesPair(7, sig),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := ParseEpochTransitionAuthorizationV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTransitionExactReplayRemainsIdempotentAfterEpochAdvance(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var account, target, survivor [16]byte
	account[15] = 10
	target[15] = 11
	survivor[15] = 12
	var dsk1, ddhk1, dsk2, ddhk2 [32]byte
	dsk1[0], ddhk1[0], dsk2[0], ddhk2[0] = 1, 2, 3, 4
	var pubArr [32]byte
	copy(pubArr[:], pub)
	a := NewAuthorizer()
	if err := a.EnsureAccount(account, 1, RecoveryCommitment(pubArr), pubArr); err != nil {
		t.Fatal(err)
	}
	if err := a.Enroll(testEnrollmentCert(t, priv, account, target, 1, dsk1, ddhk1), pubArr); err != nil {
		t.Fatal(err)
	}
	if err := a.Enroll(testEnrollmentCert(t, priv, account, survivor, 1, dsk2, ddhk2), pubArr); err != nil {
		t.Fatal(err)
	}
	revoke := testTransitionCert(t, priv, account, target, 1, 2, RevokeDeviceAction)
	if err := a.Revoke(revoke, pubArr); err != nil {
		t.Fatal(err)
	}
	if err := a.Revoke(revoke, pubArr); err != nil {
		t.Fatalf("exact replay after epoch advance must be idempotent: %v", err)
	}
}

func TestLegacyRecoveryResetActionIsRejectedWithoutStateMutation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var account, target, survivor [16]byte
	account[15], target[15], survivor[15] = 20, 21, 22
	var pubArr, dsk1, ddhk1, dsk2, ddhk2 [32]byte
	copy(pubArr[:], pub)
	dsk1[0], ddhk1[0], dsk2[0], ddhk2[0] = 1, 2, 3, 4

	mem := NewAuthorizer()
	if err := mem.EnsureAccount(account, 1, RecoveryCommitment(pubArr), pubArr); err != nil {
		t.Fatal(err)
	}
	if err := mem.Enroll(testEnrollmentCert(t, priv, account, target, 1, dsk1, ddhk1), pubArr); err != nil {
		t.Fatal(err)
	}
	if err := mem.Enroll(testEnrollmentCert(t, priv, account, survivor, 1, dsk2, ddhk2), pubArr); err != nil {
		t.Fatal(err)
	}

	reset := testTransitionCert(t, priv, account, [16]byte{}, 1, 2, RecoveryResetAction)
	if err := mem.RecoveryReset(reset, pubArr); err != ErrInvalidAuthorization {
		t.Fatalf("in-memory legacy recovery reset error = %v, want %v", err, ErrInvalidAuthorization)
	}
	gotAccount, ok := mem.Account(account)
	if !ok || gotAccount.Epoch != 1 || gotAccount.Status != AccountActive {
		t.Fatalf("legacy recovery reset mutated account: %+v (exists=%v)", gotAccount, ok)
	}
	for _, deviceID := range [][16]byte{target, survivor} {
		gotDevice, ok := mem.Device(account, deviceID)
		if !ok || gotDevice.Status != DeviceActive || gotDevice.AuthorizedEpoch != 1 {
			t.Fatalf("legacy recovery reset mutated device %x: %+v (exists=%v)", deviceID, gotDevice, ok)
		}
	}

	// The PostgreSQL implementation must reject this action before opening a
	// transaction. A zero-value sql.DB detects accidental DB access: that would
	// return a database error instead of ErrInvalidAuthorization.
	pg := NewPostgresAuthorizer(&sql.DB{})
	if err := pg.Transition(context.Background(), reset, pubArr); err != ErrInvalidAuthorization {
		t.Fatalf("PostgreSQL legacy recovery reset error = %v, want %v", err, ErrInvalidAuthorization)
	}
}

func TestInMemoryEnrollmentCannotUnlockRecoveryLockedAccount(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var accountID, deviceID [16]byte
	accountID[15] = 41
	deviceID[15] = 42
	var recoveryPub [32]byte
	copy(recoveryPub[:], publicKey)
	var dsk, ddhk [32]byte
	dsk[0], ddhk[0] = 0x31, 0x32

	a := NewAuthorizer()
	a.accounts[accountID] = Account{
		ID:                 accountID,
		Epoch:              1,
		RecoveryCommitment: RecoveryCommitment(recoveryPub),
		RecoveryPub:        recoveryPub,
		Status:             AccountRecoveryLocked,
	}
	cert := testEnrollmentCert(t, privateKey, accountID, deviceID, 1, dsk, ddhk)
	if err := a.Enroll(cert, recoveryPub); err != ErrAccountLocked {
		t.Fatalf("enrollment into recovery-locked account error = %v, want %v", err, ErrAccountLocked)
	}
	gotAccount, ok := a.Account(accountID)
	if !ok || gotAccount.Status != AccountRecoveryLocked || gotAccount.Epoch != 1 {
		t.Fatalf("ordinary enrollment changed recovery-locked account: %+v (exists=%v)", gotAccount, ok)
	}
	if _, ok := a.Device(accountID, deviceID); ok {
		t.Fatal("ordinary enrollment created a device in a recovery-locked account")
	}
	if len(a.enrollmentByDigest) != 0 {
		t.Fatalf("ordinary enrollment recorded %d enrollment digests for rejected recovery-locked account", len(a.enrollmentByDigest))
	}
}
