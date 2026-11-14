// Package signedprekeyv1 parses and verifies the candidate PM-V1 signed-prekey
// object. The protocol remains a candidate and this package is not wired to an
// HTTP route or enrollment/activation path until the contract is frozen.
package signedprekeyv1

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const (
	Version         = uint64(1)
	MaxEpoch        = uint64(^uint32(0))
	MaxID           = uint64(^uint32(0))
	MaxWireBytes    = 4096
	signatureDomain = "PM-V1-SIGNED-PREKEY-v1"
	fieldCount      = 7
	coreFieldCount  = 6
)

var (
	ErrInvalidCBOR         = errors.New("signed prekey v1: invalid or non-canonical CBOR")
	ErrInvalidShape        = errors.New("signed prekey v1: invalid object shape")
	ErrUnsupportedVersion  = errors.New("signed prekey v1: unsupported version")
	ErrInvalidField        = errors.New("signed prekey v1: invalid field")
	ErrInvalidX25519Public = errors.New("signed prekey v1: unusable X25519 public key")
	ErrInvalidSignature    = errors.New("signed prekey v1: signature verification failed")
)

// Object is a parsed candidate signed-prekey record. The original canonical
// bytes are kept private and are exposed only through a defensive copy.
type Object struct {
	raw          []byte
	AccountID    [16]byte
	AccountEpoch uint32
	DeviceID     [16]byte
	SPKID        uint32
	SPKPub       [32]byte
	Signature    [ed25519.SignatureSize]byte
}

// Parse accepts only the exact seven-field canonical CBOR candidate object.
// It validates shape and key usability but does not authorize the object for a
// device; callers must compare account/device/epoch to authoritative state.
func Parse(raw []byte) (Object, error) {
	var out Object
	if len(raw) == 0 || len(raw) > MaxWireBytes {
		return out, ErrInvalidCBOR
	}

	decoded, err := cbor.DecodeStrict(raw)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalidCBOR, err)
	}
	canonical, err := cbor.EncodeCanonical(decoded)
	if err != nil || !bytes.Equal(canonical, raw) {
		return out, ErrInvalidCBOR
	}
	if decoded.Kind != cbor.KindMap || len(decoded.Map) != fieldCount {
		return out, ErrInvalidShape
	}

	fields := make(map[uint64]cbor.Value, fieldCount)
	for _, pair := range decoded.Map {
		if pair.Key.Kind != cbor.KindInt || pair.Key.Int.Neg {
			return out, ErrInvalidShape
		}
		key := pair.Key.Int.Arg
		if key < 1 || key > fieldCount {
			return out, ErrInvalidShape
		}
		if _, exists := fields[key]; exists {
			return out, ErrInvalidShape
		}
		fields[key] = pair.Val
	}
	if len(fields) != fieldCount {
		return out, ErrInvalidShape
	}
	for key := uint64(1); key <= fieldCount; key++ {
		if _, ok := fields[key]; !ok {
			return out, ErrInvalidShape
		}
	}

	version, err := readUint(fields[1])
	if err != nil {
		return out, ErrInvalidShape
	}
	if version != Version {
		return out, ErrUnsupportedVersion
	}
	account, err := readFixedBytes(fields[2], 16)
	if err != nil {
		return out, ErrInvalidField
	}
	epoch, err := readUint(fields[3])
	if err != nil || epoch == 0 || epoch > MaxEpoch {
		return out, ErrInvalidField
	}
	device, err := readFixedBytes(fields[4], 16)
	if err != nil {
		return out, ErrInvalidField
	}
	spkID, err := readUint(fields[5])
	if err != nil || spkID == 0 || spkID > MaxID {
		return out, ErrInvalidField
	}
	spkPub, err := readFixedBytes(fields[6], 32)
	if err != nil {
		return out, ErrInvalidField
	}
	signature, err := readFixedBytes(fields[7], ed25519.SignatureSize)
	if err != nil {
		return out, ErrInvalidField
	}

	copy(out.AccountID[:], account)
	copy(out.DeviceID[:], device)
	copy(out.SPKPub[:], spkPub)
	copy(out.Signature[:], signature)
	if out.AccountID == [16]byte{} || out.DeviceID == [16]byte{} {
		return Object{}, ErrInvalidField
	}
	if err := validateX25519Public(out.SPKPub[:]); err != nil {
		return Object{}, err
	}
	out.AccountEpoch = uint32(epoch)
	out.SPKID = uint32(spkID)
	out.raw = append([]byte(nil), raw...)
	return out, nil
}

// Verify checks the candidate signature against the separately trusted DSK.
// The exact signed transcript is domain || canonical CBOR map fields 1..6.
func (o Object) Raw() []byte {
	return append([]byte(nil), o.raw...)
}

func (o Object) Verify(dskPublicKey []byte) error {
	if len(dskPublicKey) != ed25519.PublicKeySize {
		return ErrInvalidSignature
	}
	parsed, err := Parse(o.raw)
	if err != nil {
		return err
	}
	core, err := coreBytes(parsed)
	if err != nil {
		return err
	}
	transcript := make([]byte, 0, len(signatureDomain)+len(core))
	transcript = append(transcript, signatureDomain...)
	transcript = append(transcript, core...)
	if !ed25519.Verify(ed25519.PublicKey(dskPublicKey), transcript, parsed.Signature[:]) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyRecordFields verifies the legacy database-column representation of a
// candidate signed-prekey against the authoritative device identity supplied by
// the caller. It reconstructs the exact seven-field candidate transcript; it
// does not trust stored columns merely because their lengths fit.
// EncodeRecord constructs the canonical seven-field candidate object from
// authoritative public fields and a precomputed DSK signature.
func EncodeRecord(accountID [16]byte, accountEpoch uint64, deviceID [16]byte, spkID uint64, spkPublicKey, signature []byte) ([]byte, error) {
	if accountID == [16]byte{} || deviceID == [16]byte{} || accountEpoch == 0 || accountEpoch > MaxEpoch || spkID == 0 || spkID > MaxID || len(spkPublicKey) != 32 || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidField
	}
	if err := validateX25519Public(spkPublicKey); err != nil {
		return nil, err
	}
	value := cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		{Key: uintValue(1), Val: uintValue(Version)},
		{Key: uintValue(2), Val: bytesValue(accountID[:])},
		{Key: uintValue(3), Val: uintValue(accountEpoch)},
		{Key: uintValue(4), Val: bytesValue(deviceID[:])},
		{Key: uintValue(5), Val: uintValue(spkID)},
		{Key: uintValue(6), Val: bytesValue(spkPublicKey)},
		{Key: uintValue(7), Val: bytesValue(signature)},
	}}
	return cbor.EncodeCanonical(value)
}
func VerifyRecordFields(accountID [16]byte, accountEpoch uint64, deviceID [16]byte, spkID int64, spkPublicKey, signature, dskPublicKey []byte) error {
	if accountID == [16]byte{} || deviceID == [16]byte{} {
		return ErrInvalidField
	}
	if accountEpoch == 0 || accountEpoch > MaxEpoch || spkID <= 0 || uint64(spkID) > MaxID {
		return ErrInvalidField
	}
	if len(spkPublicKey) != 32 || len(signature) != ed25519.SignatureSize {
		return ErrInvalidField
	}
	if err := validateX25519Public(spkPublicKey); err != nil {
		return err
	}
	var object Object
	object.AccountID = accountID
	object.AccountEpoch = uint32(accountEpoch)
	object.DeviceID = deviceID
	object.SPKID = uint32(spkID)
	copy(object.SPKPub[:], spkPublicKey)
	copy(object.Signature[:], signature)
	if len(dskPublicKey) != ed25519.PublicKeySize {
		return ErrInvalidSignature
	}
	core, err := coreBytes(object)
	if err != nil {
		return err
	}
	transcript := make([]byte, 0, len(signatureDomain)+len(core))
	transcript = append(transcript, signatureDomain...)
	transcript = append(transcript, core...)
	if !ed25519.Verify(ed25519.PublicKey(dskPublicKey), transcript, object.Signature[:]) {
		return ErrInvalidSignature
	}
	return nil
}

// ValidateX25519PublicKey applies the same low-order-point rejection used by
// Parse. It is exported for persistence readers that validate stored key rows.
func ValidateX25519PublicKey(public []byte) error {
	return validateX25519Public(public)
}
func coreBytes(o Object) ([]byte, error) {
	value := cbor.Value{
		Kind: cbor.KindMap,
		Map: []cbor.Pair{
			{Key: uintValue(1), Val: uintValue(Version)},
			{Key: uintValue(2), Val: bytesValue(o.AccountID[:])},
			{Key: uintValue(3), Val: uintValue(uint64(o.AccountEpoch))},
			{Key: uintValue(4), Val: bytesValue(o.DeviceID[:])},
			{Key: uintValue(5), Val: uintValue(uint64(o.SPKID))},
			{Key: uintValue(6), Val: bytesValue(o.SPKPub[:])},
		},
	}
	return cbor.EncodeCanonical(value)
}

func readUint(value cbor.Value) (uint64, error) {
	if value.Kind != cbor.KindInt || value.Int.Neg {
		return 0, ErrInvalidField
	}
	return value.Int.Arg, nil
}

func readFixedBytes(value cbor.Value, size int) ([]byte, error) {
	if value.Kind != cbor.KindBytes || len(value.Bytes) != size {
		return nil, ErrInvalidField
	}
	return value.Bytes, nil
}

func validateX25519Public(public []byte) error {
	if len(public) != 32 {
		return ErrInvalidX25519Public
	}
	privateBytes := bytes.Repeat([]byte{0x42}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return ErrInvalidX25519Public
	}
	publicKey, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return ErrInvalidX25519Public
	}
	if _, err := privateKey.ECDH(publicKey); err != nil {
		return ErrInvalidX25519Public
	}
	return nil
}

func uintValue(value uint64) cbor.Value {
	return cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}}
}

func bytesValue(value []byte) cbor.Value {
	return cbor.Value{Kind: cbor.KindBytes, Bytes: append([]byte(nil), value...)}
}
