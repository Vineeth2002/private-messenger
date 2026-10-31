package authorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const RecoveryAbortDomain = "PM-V1-RECOVERY-ABORT-v1"

// RecoveryAbortV1 is a wire-level lifecycle candidate only. It does not establish
// that the request remains pending, that the aborting device is currently active,
// or that the abort arrived before the database deadline.
type RecoveryAbortV1 struct {
	Raw                   []byte
	AccountID             [16]byte
	DeviceID              [16]byte
	OldEpoch              uint64
	NewEpoch              uint64
	RequestID             [16]byte
	RecoveryRequestDigest [32]byte
	Signature             [64]byte
}

func (a RecoveryAbortV1) Digest() [32]byte { return sha256.Sum256(a.Raw) }

func validateRecoveryAbortV1Fields(accountID, deviceID, requestID [16]byte, oldEpoch, newEpoch uint64) error {
	if accountID == [16]byte{} || deviceID == [16]byte{} || requestID == [16]byte{} {
		return ErrInvalidAuthorization
	}
	if oldEpoch == 0 || oldEpoch >= LifecycleWireV1MaxEpoch || newEpoch != oldEpoch+1 || newEpoch > LifecycleWireV1MaxEpoch {
		return ErrInvalidEpoch
	}
	return nil
}

func (a RecoveryAbortV1) canonicalCore() ([]byte, error) {
	if err := validateRecoveryAbortV1Fields(a.AccountID, a.DeviceID, a.RequestID, a.OldEpoch, a.NewEpoch); err != nil {
		return nil, err
	}
	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, a.AccountID[:]),
		bytesPair(3, a.DeviceID[:]),
		uintPair(4, a.OldEpoch),
		uintPair(5, a.NewEpoch),
		bytesPair(6, a.RequestID[:]),
		bytesPair(7, a.RecoveryRequestDigest[:]),
	}})
}

// ParseRecoveryAbortV1 strictly parses the separate 8-field candidate format.
func ParseRecoveryAbortV1(raw []byte) (RecoveryAbortV1, error) {
	fields, err := decodeMap(raw)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7, 8); err != nil {
		return RecoveryAbortV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	if version != AuthorizationProtocolVersion {
		return RecoveryAbortV1{}, fmt.Errorf("authorization: unsupported recovery-abort version %d", version)
	}
	accountID, err := takeFixed16(fields, 2)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	deviceID, err := takeFixed16(fields, 3)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	oldEpoch, err := takeUint(fields, 4)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	newEpoch, err := takeUint(fields, 5)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	requestID, err := takeFixed16(fields, 6)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	requestDigest, err := takeFixed32(fields, 7)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	signature, err := takeFixed64(fields, 8)
	if err != nil {
		return RecoveryAbortV1{}, err
	}
	if err := validateRecoveryAbortV1Fields(accountID, deviceID, requestID, oldEpoch, newEpoch); err != nil {
		return RecoveryAbortV1{}, err
	}
	return RecoveryAbortV1{
		Raw: append([]byte(nil), raw...), AccountID: accountID, DeviceID: deviceID,
		OldEpoch: oldEpoch, NewEpoch: newEpoch, RequestID: requestID,
		RecoveryRequestDigest: requestDigest, Signature: signature,
	}, nil
}

// Verify checks the DSK signature over the canonical abort core. The caller must
// obtain deviceSigningPub from authoritative device state, not from the abort object.
func (a RecoveryAbortV1) Verify(deviceSigningPub [32]byte) error {
	if len(a.Raw) == 0 {
		return ErrInvalidAuthorization
	}
	core, err := a.canonicalCore()
	if err != nil {
		return err
	}
	message := append([]byte(RecoveryAbortDomain), core...)
	if !ed25519.Verify(ed25519.PublicKey(deviceSigningPub[:]), message, a.Signature[:]) {
		return ErrInvalidAuthorization
	}
	return nil
}

// VerifyForRequest binds an abort to the exact signed request bytes, and checks both
// signatures and matching account/request/epoch fields. Current pending status,
// active-device status, database-time deadline, and abort/finalize serialization remain external.
func (a RecoveryAbortV1) VerifyForRequest(recoveryPub, deviceSigningPub [32]byte, recoveryRequestRaw []byte) error {
	if err := a.Verify(deviceSigningPub); err != nil {
		return err
	}
	request, err := ParseRecoveryRequestV1(recoveryRequestRaw)
	if err != nil {
		return err
	}
	if err := request.Verify(recoveryPub); err != nil {
		return err
	}
	digest := sha256.Sum256(recoveryRequestRaw)
	if digest != a.RecoveryRequestDigest || a.AccountID != request.AccountID ||
		a.OldEpoch != request.OldEpoch || a.NewEpoch != request.NewEpoch || a.RequestID != request.RequestID {
		return ErrInvalidAuthorization
	}
	return nil
}
