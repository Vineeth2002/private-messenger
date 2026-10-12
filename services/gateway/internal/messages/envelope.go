package messages

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor/typed"
)

const (
	MessageEnvelopeVersion uint64 = 1
	MaxCiphertextBytes            = 65552
)

var (
	ErrInvalidMessageEnvelope      = errors.New("invalid message envelope")
	ErrInvalidMessageEnvelopeField = errors.New("invalid message envelope field")
	ErrNonCanonicalMessageEnvelope = errors.New("non-canonical message envelope")
)

type wireMessageEnvelopeV1 struct {
	Version            uint64 `cbor:"1,keyasint"`
	EnvelopeID         []byte `cbor:"2,keyasint"`
	SenderDeviceID     []byte `cbor:"3,keyasint"`
	RecipientDeviceID  []byte `cbor:"4,keyasint"`
	AccountEpoch       uint32 `cbor:"5,keyasint"`
	IsPrekeyHandshake  bool   `cbor:"6,keyasint"`
	RatchetHeaderBytes []byte `cbor:"7,keyasint"`
	Ciphertext         []byte `cbor:"8,keyasint"`
}

type MessageEnvelopeV1 struct {
	EnvelopeID        [16]byte
	SenderDeviceID    [16]byte
	RecipientDeviceID [16]byte
	AccountEpoch      uint32
	IsPrekeyHandshake bool
	RatchetHeader     []byte
	Ciphertext        []byte

	// Raw is the exact canonical PM-CBOR-2026 envelope received by the server.
	Raw []byte
}

func DecodeMessageEnvelopeV1(raw []byte) (MessageEnvelopeV1, error) {
	if len(raw) == 0 {
		return MessageEnvelopeV1{}, fmt.Errorf("%w: empty input", ErrInvalidMessageEnvelope)
	}

	var wire wireMessageEnvelopeV1
	ok, err := typed.RoundTripsExactly(raw, &wire)
	if err != nil {
		return MessageEnvelopeV1{}, fmt.Errorf("%w: decode: %v", ErrInvalidMessageEnvelope, err)
	}
	if !ok {
		return MessageEnvelopeV1{}, ErrNonCanonicalMessageEnvelope
	}

	if wire.Version != MessageEnvelopeVersion {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: version=%d",
			ErrInvalidMessageEnvelopeField,
			wire.Version,
		)
	}
	if len(wire.EnvelopeID) != 16 {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: envelope_id length=%d",
			ErrInvalidMessageEnvelopeField,
			len(wire.EnvelopeID),
		)
	}
	if len(wire.SenderDeviceID) != 16 {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: sender_device_id length=%d",
			ErrInvalidMessageEnvelopeField,
			len(wire.SenderDeviceID),
		)
	}
	if len(wire.RecipientDeviceID) != 16 {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: recipient_device_id length=%d",
			ErrInvalidMessageEnvelopeField,
			len(wire.RecipientDeviceID),
		)
	}
	if len(wire.RatchetHeaderBytes) == 0 {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: empty ratchet_header_bytes",
			ErrInvalidMessageEnvelopeField,
		)
	}
	if err := validateCanonicalCBOR(wire.RatchetHeaderBytes); err != nil {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: ratchet_header_bytes: %v",
			ErrInvalidMessageEnvelopeField,
			err,
		)
	}
	if len(wire.Ciphertext) > MaxCiphertextBytes {
		return MessageEnvelopeV1{}, fmt.Errorf(
			"%w: ciphertext length=%d",
			ErrInvalidMessageEnvelopeField,
			len(wire.Ciphertext),
		)
	}

	var envelope MessageEnvelopeV1
	copy(envelope.EnvelopeID[:], wire.EnvelopeID)
	copy(envelope.SenderDeviceID[:], wire.SenderDeviceID)
	copy(envelope.RecipientDeviceID[:], wire.RecipientDeviceID)
	envelope.AccountEpoch = wire.AccountEpoch
	envelope.IsPrekeyHandshake = wire.IsPrekeyHandshake
	envelope.RatchetHeader = append([]byte(nil), wire.RatchetHeaderBytes...)
	envelope.Ciphertext = append([]byte(nil), wire.Ciphertext...)
	envelope.Raw = append([]byte(nil), raw...)

	return envelope, nil
}

func validateCanonicalCBOR(raw []byte) error {
	value, err := cbor.DecodeStrict(raw)
	if err != nil {
		return err
	}

	canonical, err := cbor.EncodeCanonical(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return ErrNonCanonicalMessageEnvelope
	}

	return nil
}
