package authorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const (
	AuthorizationProtocolVersion uint64 = 1
	DeviceEnrollmentDomain              = "PM-V1-DEVICE-ENROLL-v1"
	EpochTransitionDomain               = "PM-V1-EPOCH-TRANSITION-v1"
	RecoveryCommitmentDomain            = "PM-V1-RECOVERY-COMMITMENT"
)

type DeviceEnrollmentAuthorizationV1 struct {
	Raw       []byte
	AccountID [16]byte
	Epoch     uint64
	DeviceID  [16]byte
	DSKPub    [32]byte
	DDHKPub   [32]byte
	Signature [64]byte
}

type EpochTransitionAction uint64

const (
	RevokeDeviceAction EpochTransitionAction = 1
	// RecoveryResetAction is retained only so legacy signed V1 messages remain
	// decodable. State-mutating APIs must reject it; delayed recovery uses the
	// separate RecoveryRequestV1 protocol.
	RecoveryResetAction EpochTransitionAction = 2
)

type EpochTransitionAuthorizationV1 struct {
	Raw       []byte
	AccountID [16]byte
	OldEpoch  uint64
	NewEpoch  uint64
	Action    EpochTransitionAction
	DeviceID  [16]byte
	Signature [64]byte
}

func RecoveryCommitment(recoveryPub [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(RecoveryCommitmentDomain))
	_, _ = h.Write(recoveryPub[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func VerifyRecoveryCommitment(commitment, recoveryPub [32]byte) bool {
	return RecoveryCommitment(recoveryPub) == commitment
}

func (a DeviceEnrollmentAuthorizationV1) Digest() [32]byte { return sha256.Sum256(a.Raw) }
func (a EpochTransitionAuthorizationV1) Digest() [32]byte  { return sha256.Sum256(a.Raw) }

func (a DeviceEnrollmentAuthorizationV1) Verify(recoveryPub [32]byte) error {
	if len(a.Raw) == 0 || a.AccountID == [16]byte{} || a.DeviceID == [16]byte{} ||
		a.Epoch == 0 || a.Epoch > LifecycleWireV1MaxEpoch {
		return ErrInvalidAuthorization
	}
	core, err := a.canonicalCore()
	if err != nil {
		return err
	}
	msg := append([]byte(DeviceEnrollmentDomain), core...)
	if !ed25519.Verify(ed25519.PublicKey(recoveryPub[:]), msg, a.Signature[:]) {
		return ErrInvalidAuthorization
	}
	return nil
}

func (a EpochTransitionAuthorizationV1) Verify(recoveryPub [32]byte) error {
	if len(a.Raw) == 0 || a.AccountID == [16]byte{} || a.OldEpoch == 0 || a.NewEpoch == 0 {
		return ErrInvalidAuthorization
	}
	if a.OldEpoch >= LifecycleWireV1MaxEpoch ||
		a.NewEpoch > LifecycleWireV1MaxEpoch ||
		a.NewEpoch != a.OldEpoch+1 {
		return ErrInvalidEpoch
	}
	switch a.Action {
	case RevokeDeviceAction:
		if a.DeviceID == [16]byte{} {
			return ErrInvalidAuthorization
		}
	case RecoveryResetAction:
		if a.DeviceID != [16]byte{} {
			return ErrInvalidAuthorization
		}
	default:
		return fmt.Errorf("authorization: unknown epoch transition action %d", a.Action)
	}
	core, err := a.canonicalCore()
	if err != nil {
		return err
	}
	msg := append([]byte(EpochTransitionDomain), core...)
	if !ed25519.Verify(ed25519.PublicKey(recoveryPub[:]), msg, a.Signature[:]) {
		return ErrInvalidAuthorization
	}
	return nil
}

func (a DeviceEnrollmentAuthorizationV1) canonicalCore() ([]byte, error) {
	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, a.AccountID[:]),
		uintPair(3, a.Epoch),
		bytesPair(4, a.DeviceID[:]),
		bytesPair(5, a.DSKPub[:]),
		bytesPair(6, a.DDHKPub[:]),
	}})
}

func (a EpochTransitionAuthorizationV1) canonicalCore() ([]byte, error) {
	target := a.DeviceID[:]
	if a.Action == RecoveryResetAction {
		target = []byte{}
	}

	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, a.AccountID[:]),
		uintPair(3, a.OldEpoch),
		uintPair(4, a.NewEpoch),
		uintPair(5, uint64(a.Action)),
		bytesPair(6, target),
	}})
}

func ParseDeviceEnrollmentAuthorizationV1(raw []byte) (DeviceEnrollmentAuthorizationV1, error) {
	fields, err := decodeMap(raw)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7); err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	if version != AuthorizationProtocolVersion {
		return DeviceEnrollmentAuthorizationV1{}, fmt.Errorf("authorization: unsupported protocol version %d", version)
	}
	accountID, err := takeFixed16(fields, 2)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	epoch, err := takeUint(fields, 3)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	deviceID, err := takeFixed16(fields, 4)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	dskPub, err := takeFixed32(fields, 5)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	ddhkPub, err := takeFixed32(fields, 6)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	sig, err := takeFixed64(fields, 7)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, err
	}
	if epoch == 0 || epoch > LifecycleWireV1MaxEpoch ||
		accountID == [16]byte{} || deviceID == [16]byte{} {
		return DeviceEnrollmentAuthorizationV1{}, ErrInvalidAuthorization
	}
	return DeviceEnrollmentAuthorizationV1{Raw: append([]byte(nil), raw...), AccountID: accountID, Epoch: epoch, DeviceID: deviceID, DSKPub: dskPub, DDHKPub: ddhkPub, Signature: sig}, nil
}

func ParseEpochTransitionAuthorizationV1(raw []byte) (EpochTransitionAuthorizationV1, error) {
	fields, err := decodeMap(raw)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7); err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	if version != AuthorizationProtocolVersion {
		return EpochTransitionAuthorizationV1{}, fmt.Errorf("authorization: unsupported protocol version %d", version)
	}
	accountID, err := takeFixed16(fields, 2)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	oldEpoch, err := takeUint(fields, 3)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	newEpoch, err := takeUint(fields, 4)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	action, err := takeUint(fields, 5)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	deviceRaw, err := takeBytes(fields, 6)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	sig, err := takeFixed64(fields, 7)
	if err != nil {
		return EpochTransitionAuthorizationV1{}, err
	}
	if oldEpoch == 0 || oldEpoch >= LifecycleWireV1MaxEpoch ||
		newEpoch > LifecycleWireV1MaxEpoch || newEpoch != oldEpoch+1 ||
		accountID == [16]byte{} {
		return EpochTransitionAuthorizationV1{}, ErrInvalidEpoch
	}
	var deviceID [16]byte
	if len(deviceRaw) == 16 {
		copy(deviceID[:], deviceRaw)
	} else if len(deviceRaw) != 0 {
		return EpochTransitionAuthorizationV1{}, errors.New("authorization: target device must be bstr(16) or empty")
	}
	out := EpochTransitionAuthorizationV1{Raw: append([]byte(nil), raw...), AccountID: accountID, OldEpoch: oldEpoch, NewEpoch: newEpoch, Action: EpochTransitionAction(action), DeviceID: deviceID, Signature: sig}
	if out.Action == RevokeDeviceAction && deviceID == [16]byte{} {
		return EpochTransitionAuthorizationV1{}, ErrInvalidAuthorization
	}
	if out.Action == RecoveryResetAction && deviceID != [16]byte{} {
		return EpochTransitionAuthorizationV1{}, ErrInvalidAuthorization
	}
	if out.Action != RevokeDeviceAction && out.Action != RecoveryResetAction {
		return EpochTransitionAuthorizationV1{}, fmt.Errorf("authorization: unknown epoch transition action %d", action)
	}
	return out, nil
}

func decodeMap(data []byte) (map[uint64]cbor.Value, error) {
	value, err := cbor.DecodeStrict(data)
	if err != nil {
		return nil, err
	}
	if value.Kind != cbor.KindMap {
		return nil, errors.New("authorization: expected CBOR map")
	}
	out := make(map[uint64]cbor.Value, len(value.Map))
	for _, pair := range value.Map {
		if pair.Key.Kind != cbor.KindInt || pair.Key.Int.Neg {
			return nil, errors.New("authorization: map key is not an unsigned integer")
		}
		key := pair.Key.Int.Arg
		if _, ok := out[key]; ok {
			return nil, fmt.Errorf("authorization: duplicate field %d", key)
		}
		out[key] = pair.Val
	}
	return out, nil
}

func requireFields(fields map[uint64]cbor.Value, keys ...uint64) error {
	if len(fields) != len(keys) {
		return fmt.Errorf("authorization: wrong field count: got %d want %d", len(fields), len(keys))
	}
	want := make(map[uint64]struct{}, len(keys))
	for _, key := range keys {
		want[key] = struct{}{}
	}
	for key := range fields {
		if _, ok := want[key]; !ok {
			return fmt.Errorf("authorization: unknown field %d", key)
		}
	}
	return nil
}

func takeUint(fields map[uint64]cbor.Value, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("authorization: missing field %d", key)
	}
	if value.Kind != cbor.KindInt || value.Int.Neg {
		return 0, fmt.Errorf("authorization: field %d is not an unsigned integer", key)
	}
	return value.Int.Arg, nil
}

func takeBytes(fields map[uint64]cbor.Value, key uint64) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("authorization: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes {
		return nil, fmt.Errorf("authorization: field %d is not a byte string", key)
	}
	return append([]byte(nil), value.Bytes...), nil
}

func takeFixed16(fields map[uint64]cbor.Value, key uint64) ([16]byte, error) {
	var out [16]byte
	value, ok := fields[key]
	if !ok {
		return out, fmt.Errorf("authorization: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != 16 {
		return out, fmt.Errorf("authorization: field %d has wrong byte length", key)
	}
	copy(out[:], value.Bytes)
	return out, nil
}

func takeFixed32(fields map[uint64]cbor.Value, key uint64) ([32]byte, error) {
	var out [32]byte
	value, ok := fields[key]
	if !ok {
		return out, fmt.Errorf("authorization: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != 32 {
		return out, fmt.Errorf("authorization: field %d has wrong byte length", key)
	}
	copy(out[:], value.Bytes)
	return out, nil
}

func takeFixed64(fields map[uint64]cbor.Value, key uint64) ([64]byte, error) {
	var out [64]byte
	value, ok := fields[key]
	if !ok {
		return out, fmt.Errorf("authorization: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != 64 {
		return out, fmt.Errorf("authorization: field %d has wrong byte length", key)
	}
	copy(out[:], value.Bytes)
	return out, nil
}

func uintPair(key, value uint64) cbor.Pair {
	return cbor.Pair{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}}, Val: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}}}
}
func bytesPair(key uint64, value []byte) cbor.Pair {
	return cbor.Pair{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: append([]byte(nil), value...)}}
}
