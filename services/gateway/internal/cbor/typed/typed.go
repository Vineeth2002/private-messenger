// Package typed holds the fxamacker/cbor/v2 mode configuration for typed
// application structs. It is deliberately separate from the core codec: the core
// codec (package cbor) is the arbiter of canonical bytes, and every typed decode
// here runs BEHIND cbor.DecodeStrict, so a library option can never loosen the
// protocol rules.
//
// NOTE: written without network/compiler access. Confirm the option names against
// the pinned fxamacker/cbor version with `go vet ./...` (see docs/IMPLEMENTATION_NOTES.md).
package typed

import (
	"bytes"
	"errors"
	"fmt"

	fx "github.com/fxamacker/cbor/v2"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

// EncMode: RFC 8949 s4.2.1 Core Deterministic Encoding.
func EncMode() (fx.EncMode, error) { return fx.CoreDetEncOptions().EncMode() }

// DecMode: hardened decoder (duplicate keys and indefinite lengths rejected).
func DecMode() (fx.DecMode, error) {
	return fx.DecOptions{
		DupMapKey:       fx.DupMapKeyEnforcedAPF,
		IndefLength:     fx.IndefLengthForbidden,
		MaxNestedLevels: cbor.MaxDepth,
	}.DecMode()
}

// Marshal encodes v deterministically and self-checks the result against the strict codec.
func Marshal(v any) ([]byte, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	b, err := em.Marshal(v)
	if err != nil {
		return nil, err
	}
	if !cbor.IsCanonical(b) {
		return nil, fmt.Errorf("typed.Marshal produced non-PM-CBOR-2026 bytes")
	}
	return b, nil
}

// UnmarshalStrict contract:
//  1. data must be valid PM-CBOR-2026 (cbor.DecodeStrict); otherwise the *cbor.Error
//     with the protocol category is returned and v is untouched;
//  2. data is then decoded into v with the hardened fxamacker mode (DecMode); a
//     *fx.DupMapKeyError is mapped to ERR_DUPLICATE_MAP_KEY.
//
// It does NOT verify decode/re-encode identity. By default fxamacker ignores unknown
// map keys when decoding into a struct, so a nil result does not prove that v
// represents every byte of data. Callers that handle cryptographic transcripts,
// signed structures or transparency leaves (unknown fields must FAIL, PM-CBOR-2026
// Rule 7) must use RoundTripsExactly instead.
func UnmarshalStrict(data []byte, v any) error {
	if _, err := cbor.DecodeStrict(data); err != nil {
		return err
	}
	dm, err := DecMode()
	if err != nil {
		return err
	}
	if err := dm.Unmarshal(data, v); err != nil {
		// Trap fxamacker's duplicate-key error and map it to the protocol category.
		var dup *fx.DupMapKeyError
		if errors.As(err, &dup) {
			return &cbor.Error{Cat: cbor.ErrDuplicateMapKey}
		}
		return err
	}
	return nil
}

// RoundTripsExactly performs UnmarshalStrict and then re-marshals v deterministically,
// reporting whether the result is byte-identical to data. It is the function that
// proves decode/re-encode identity: false (with a nil error) means data carried content
// that v does not represent, for example an unknown field that was silently ignored.
func RoundTripsExactly(data []byte, v any) (bool, error) {
	if err := UnmarshalStrict(data, v); err != nil {
		return false, err
	}
	again, err := Marshal(v)
	if err != nil {
		return false, err
	}
	return bytes.Equal(again, data), nil
}
