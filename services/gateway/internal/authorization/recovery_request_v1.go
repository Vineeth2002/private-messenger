package authorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const (
	RecoveryRequestDomain   = "PM-V1-RECOVERY-REQUEST-v1"
	LifecycleWireV1MaxEpoch = uint64(1<<32 - 1)
)

// RecoveryRequestV1 is a wire-level candidate only. Parsing and signature verification
// do not make a request pending or authorize any account/device state transition.
type RecoveryRequestV1 struct {
	Raw                  []byte
	AccountID            [16]byte
	OldEpoch             uint64
	NewEpoch             uint64
	RequestID            [16]byte
	TargetDeviceID       [16]byte
	EnrollmentCertDigest [32]byte
	Signature            [64]byte
}

func (a RecoveryRequestV1) Digest() [32]byte { return sha256.Sum256(a.Raw) }

func (a RecoveryRequestV1) canonicalCore() ([]byte, error) {
	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, a.AccountID[:]),
		uintPair(3, a.OldEpoch),
		uintPair(4, a.NewEpoch),
		bytesPair(5, a.RequestID[:]),
		bytesPair(6, a.TargetDeviceID[:]),
		bytesPair(7, a.EnrollmentCertDigest[:]),
	}})
}

// ParseRecoveryRequestV1 strictly parses the separate 8-field candidate format.
func ParseRecoveryRequestV1(raw []byte) (RecoveryRequestV1, error) {
	fields, err := decodeMap(raw)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7, 8); err != nil {
		return RecoveryRequestV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	if version != AuthorizationProtocolVersion {
		return RecoveryRequestV1{}, fmt.Errorf("authorization: unsupported recovery-request version %d", version)
	}
	accountID, err := takeFixed16(fields, 2)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	oldEpoch, err := takeUint(fields, 3)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	newEpoch, err := takeUint(fields, 4)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	requestID, err := takeFixed16(fields, 5)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	targetDeviceID, err := takeFixed16(fields, 6)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	enrollmentDigest, err := takeFixed32(fields, 7)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	signature, err := takeFixed64(fields, 8)
	if err != nil {
		return RecoveryRequestV1{}, err
	}
	if accountID == [16]byte{} || requestID == [16]byte{} || targetDeviceID == [16]byte{} {
		return RecoveryRequestV1{}, ErrInvalidAuthorization
	}
	if oldEpoch == 0 || oldEpoch >= LifecycleWireV1MaxEpoch || newEpoch != oldEpoch+1 || newEpoch > LifecycleWireV1MaxEpoch {
		return RecoveryRequestV1{}, ErrInvalidEpoch
	}
	return RecoveryRequestV1{
		Raw: append([]byte(nil), raw...), AccountID: accountID, OldEpoch: oldEpoch, NewEpoch: newEpoch,
		RequestID: requestID, TargetDeviceID: targetDeviceID,
		EnrollmentCertDigest: enrollmentDigest, Signature: signature,
	}, nil
}

// Verify checks only the recovery signature and structural invariants. It does not
// check the current stored recovery commitment, uniqueness, pending status, or deadline.
func (a RecoveryRequestV1) Verify(recoveryPub [32]byte) error {
	if len(a.Raw) == 0 || a.AccountID == [16]byte{} || a.RequestID == [16]byte{} || a.TargetDeviceID == [16]byte{} {
		return ErrInvalidAuthorization
	}
	if a.OldEpoch == 0 || a.OldEpoch >= LifecycleWireV1MaxEpoch || a.NewEpoch != a.OldEpoch+1 || a.NewEpoch > LifecycleWireV1MaxEpoch {
		return ErrInvalidEpoch
	}
	core, err := a.canonicalCore()
	if err != nil {
		return err
	}
	message := append([]byte(RecoveryRequestDomain), core...)
	if !ed25519.Verify(ed25519.PublicKey(recoveryPub[:]), message, a.Signature[:]) {
		return ErrInvalidAuthorization
	}
	return nil
}

// VerifyForEnrollment verifies both signed objects under the same recovery public key,
// then binds request fields and SHA-256 of the exact complete enrollment wire bytes.
func (a RecoveryRequestV1) VerifyForEnrollment(recoveryPub [32]byte, enrollmentRaw []byte) error {
	if err := a.Verify(recoveryPub); err != nil {
		return err
	}
	digest := sha256.Sum256(enrollmentRaw)
	if digest != a.EnrollmentCertDigest {
		return ErrInvalidAuthorization
	}
	enrollment, err := ParseDeviceEnrollmentAuthorizationV1(enrollmentRaw)
	if err != nil {
		return err
	}
	if err := enrollment.Verify(recoveryPub); err != nil {
		return err
	}
	if enrollment.AccountID != a.AccountID || enrollment.DeviceID != a.TargetDeviceID || enrollment.Epoch != a.NewEpoch {
		return ErrInvalidAuthorization
	}
	return nil
}
