// Package kt contains the Go gateway's Key Transparency V1 wire boundary.
//
// This package mirrors only the frozen PM-CBOR object shapes. It does not invent
// HTTP envelopes, persistence schema, or account/device authorization rules.
// Cryptographic verification remains a separate boundary.
package kt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const (
	ProtocolVersion = 1
	EvidenceDomain  = "PM-V1-KT-EQUIVOCATION-v1"
)

// TransparencyLeafV1 is the exact frozen nine-field KT leaf.
type TransparencyLeafV1 struct {
	Raw       []byte
	AccountID [16]byte
	Epoch     uint64
	DeviceID  [16]byte
	DSKPub    [32]byte
	DDHKPub   [32]byte
	CertDH    [64]byte
	SPKPub    [32]byte
	PushPK    [32]byte
	Signature [64]byte
}

// SignedTreeHeadV1 is the exact frozen seven-field STH.
type SignedTreeHeadV1 struct {
	Raw         []byte
	TreeSize    uint64
	SMTRoot     [32]byte
	HistoryRoot [32]byte
	IssuedAt    uint64
	LogID       [32]byte
	Signature   [64]byte
	STHDigest   [32]byte
}

// HistoryEntryV1 is the exact frozen three-field history entry.
type HistoryEntryV1 struct {
	Raw      []byte
	Sequence uint64
	SMTKey   [32]byte
	LeafHash [32]byte
}

// WitnessStatementV1 is the exact frozen six-field witness statement.
type WitnessStatementV1 struct {
	Raw       []byte
	WitnessID [16]byte
	LogID     [32]byte
	TreeSize  uint64
	STHDigest [32]byte
	Signature [64]byte
}

// EquivocationEvidenceV1 is the exact frozen four-or-five-field evidence object.
type EquivocationEvidenceV1 struct {
	Raw               []byte
	STHA              []byte
	STHB              []byte
	WitnessStatements [][]byte
}

func decodeMap(data []byte) (map[uint64]cbor.Value, error) {
	value, err := cbor.DecodeStrict(data)
	if err != nil {
		return nil, err
	}
	if value.Kind != cbor.KindMap {
		return nil, fmt.Errorf("kt: expected CBOR map")
	}

	out := make(map[uint64]cbor.Value, len(value.Map))
	for _, pair := range value.Map {
		if pair.Key.Kind != cbor.KindInt || pair.Key.Int.Neg {
			return nil, fmt.Errorf("kt: map key is not an unsigned integer")
		}
		key := pair.Key.Int.Arg
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("kt: duplicate integer map key %d", key)
		}
		out[key] = pair.Val
	}
	return out, nil
}

func requireFields(fields map[uint64]cbor.Value, required ...uint64) error {
	want := make(map[uint64]struct{}, len(required))
	for _, key := range required {
		want[key] = struct{}{}
	}
	if len(fields) != len(want) {
		return fmt.Errorf("kt: wrong field count: got %d want %d", len(fields), len(want))
	}
	for key := range fields {
		if _, ok := want[key]; !ok {
			return fmt.Errorf("kt: unknown field %d", key)
		}
	}
	return nil
}

func takeUint(fields map[uint64]cbor.Value, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("kt: missing field %d", key)
	}
	if value.Kind != cbor.KindInt || value.Int.Neg {
		return 0, fmt.Errorf("kt: field %d is not an unsigned integer", key)
	}
	return value.Int.Arg, nil
}

func takeBytes(fields map[uint64]cbor.Value, key uint64, size int) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("kt: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != size {
		return nil, fmt.Errorf("kt: field %d is not bstr(%d)", key, size)
	}
	return value.Bytes, nil
}

func takeFixed16(fields map[uint64]cbor.Value, key uint64) ([16]byte, error) {
	var out [16]byte
	value, ok := fields[key]
	if !ok {
		return out, fmt.Errorf("kt: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != len(out) {
		return out, fmt.Errorf("kt: field %d has wrong byte length", key)
	}
	copy(out[:], value.Bytes)
	return out, nil
}

func takeFixed32(fields map[uint64]cbor.Value, key uint64) ([32]byte, error) {
	var out [32]byte
	value, ok := fields[key]
	if !ok {
		return out, fmt.Errorf("kt: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != len(out) {
		return out, fmt.Errorf("kt: field %d has wrong byte length", key)
	}
	copy(out[:], value.Bytes)
	return out, nil
}

func takeFixed64(fields map[uint64]cbor.Value, key uint64) ([64]byte, error) {
	var out [64]byte
	value, ok := fields[key]
	if !ok {
		return out, fmt.Errorf("kt: missing field %d", key)
	}
	if value.Kind != cbor.KindBytes || len(value.Bytes) != len(out) {
		return out, fmt.Errorf("kt: field %d has wrong byte length", key)
	}
	copy(out[:], value.Bytes)
	return out, nil
}

// ParseTransparencyLeafV1 validates the exact frozen field map and returns the
// parsed object. Signature verification is intentionally a separate operation.
func ParseTransparencyLeafV1(data []byte) (TransparencyLeafV1, error) {
	fields, err := decodeMap(data)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7, 8, 9); err != nil {
		return TransparencyLeafV1{}, err
	}
	epoch, err := takeUint(fields, 2)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	if epoch < 1 {
		return TransparencyLeafV1{}, fmt.Errorf("kt: leaf epoch must be >= 1")
	}
	accountID, err := takeFixed16(fields, 1)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	deviceID, err := takeFixed16(fields, 3)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	dsk, err := takeFixed32(fields, 4)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	ddhk, err := takeFixed32(fields, 5)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	cert, err := takeFixed64(fields, 6)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	spk, err := takeFixed32(fields, 7)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	push, err := takeFixed32(fields, 8)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	sig, err := takeFixed64(fields, 9)
	if err != nil {
		return TransparencyLeafV1{}, err
	}
	return TransparencyLeafV1{
		Raw:       append([]byte(nil), data...),
		AccountID: accountID,
		Epoch:     epoch,
		DeviceID:  deviceID,
		DSKPub:    dsk,
		DDHKPub:   ddhk,
		CertDH:    cert,
		SPKPub:    spk,
		PushPK:    push,
		Signature: sig,
	}, nil
}

// ParseSignedTreeHeadV1 validates the exact frozen STH field map.
func ParseSignedTreeHeadV1(data []byte) (SignedTreeHeadV1, error) {
	fields, err := decodeMap(data)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7); err != nil {
		return SignedTreeHeadV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	if version != ProtocolVersion {
		return SignedTreeHeadV1{}, fmt.Errorf("kt: unsupported protocol version %d", version)
	}
	treeSize, err := takeUint(fields, 2)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	smtRoot, err := takeFixed32(fields, 3)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	historyRoot, err := takeFixed32(fields, 4)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	issuedAt, err := takeUint(fields, 5)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	logID, err := takeFixed32(fields, 6)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	signature, err := takeFixed64(fields, 7)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}

	return SignedTreeHeadV1{
		Raw:         append([]byte(nil), data...),
		TreeSize:    treeSize,
		SMTRoot:     smtRoot,
		HistoryRoot: historyRoot,
		IssuedAt:    issuedAt,
		LogID:       logID,
		Signature:   signature,
		STHDigest:   sha256.Sum256(data),
	}, nil
}

// ParseHistoryEntryV1 validates the exact frozen history-entry field map.
func ParseHistoryEntryV1(data []byte) (HistoryEntryV1, error) {
	fields, err := decodeMap(data)
	if err != nil {
		return HistoryEntryV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3); err != nil {
		return HistoryEntryV1{}, err
	}
	sequence, err := takeUint(fields, 1)
	if err != nil {
		return HistoryEntryV1{}, err
	}
	if sequence < 1 {
		return HistoryEntryV1{}, fmt.Errorf("kt: history sequence must be >= 1")
	}
	smtKey, err := takeFixed32(fields, 2)
	if err != nil {
		return HistoryEntryV1{}, err
	}
	leafHash, err := takeFixed32(fields, 3)
	if err != nil {
		return HistoryEntryV1{}, err
	}
	return HistoryEntryV1{
		Raw:      append([]byte(nil), data...),
		Sequence: sequence,
		SMTKey:   smtKey,
		LeafHash: leafHash,
	}, nil
}

// ParseWitnessStatementV1 validates the exact frozen six-field witness statement.
func ParseWitnessStatementV1(data []byte) (WitnessStatementV1, error) {
	fields, err := decodeMap(data)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6); err != nil {
		return WitnessStatementV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	if version != ProtocolVersion {
		return WitnessStatementV1{}, fmt.Errorf("kt: unsupported protocol version %d", version)
	}
	witnessID, err := takeFixed16(fields, 2)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	logID, err := takeFixed32(fields, 3)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	treeSize, err := takeUint(fields, 4)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	sthDigest, err := takeFixed32(fields, 5)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	signature, err := takeFixed64(fields, 6)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	return WitnessStatementV1{
		Raw:       append([]byte(nil), data...),
		WitnessID: witnessID,
		LogID:     logID,
		TreeSize:  treeSize,
		STHDigest: sthDigest,
		Signature: signature,
	}, nil
}

// ParseEquivocationEvidenceV1 validates the frozen evidence object.
func ParseEquivocationEvidenceV1(data []byte) (EquivocationEvidenceV1, error) {
	fields, err := decodeMap(data)
	if err != nil {
		return EquivocationEvidenceV1{}, err
	}
	if len(fields) != 4 && len(fields) != 5 {
		return EquivocationEvidenceV1{}, fmt.Errorf("kt: equivocation evidence must contain 4 or 5 fields")
	}
	for key := range fields {
		if key < 1 || key > 5 {
			return EquivocationEvidenceV1{}, fmt.Errorf("kt: unknown evidence field %d", key)
		}
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return EquivocationEvidenceV1{}, err
	}
	if version != ProtocolVersion {
		return EquivocationEvidenceV1{}, fmt.Errorf("kt: unsupported protocol version %d", version)
	}
	domain, err := takeBytes(fields, 2, len(EvidenceDomain))
	if err != nil {
		return EquivocationEvidenceV1{}, err
	}
	if string(domain) != EvidenceDomain {
		return EquivocationEvidenceV1{}, fmt.Errorf("kt: wrong evidence domain")
	}
	sthA, err := func() ([]byte, error) {
		v, ok := fields[3]
		if !ok || v.Kind != cbor.KindBytes {
			return nil, fmt.Errorf("kt: field 3 is not a bstr")
		}
		return v.Bytes, nil
	}()
	if err != nil {
		return EquivocationEvidenceV1{}, err
	}
	sthB, err := func() ([]byte, error) {
		v, ok := fields[4]
		if !ok || v.Kind != cbor.KindBytes {
			return nil, fmt.Errorf("kt: field 4 is not a bstr")
		}
		return v.Bytes, nil
	}()
	if err != nil {
		return EquivocationEvidenceV1{}, err
	}

	var witnessStatements [][]byte
	if raw, ok := fields[5]; ok {
		if raw.Kind != cbor.KindArray {
			return EquivocationEvidenceV1{}, fmt.Errorf("kt: witness_statements must be an array")
		}
		witnessStatements = make([][]byte, 0, len(raw.Array))
		for _, item := range raw.Array {
			if item.Kind != cbor.KindBytes {
				return EquivocationEvidenceV1{}, fmt.Errorf("kt: witness statement item is not a bstr")
			}
			witnessStatements = append(witnessStatements, append([]byte(nil), item.Bytes...))
		}
	}

	return EquivocationEvidenceV1{
		Raw:               append([]byte(nil), data...),
		STHA:              append([]byte(nil), sthA...),
		STHB:              append([]byte(nil), sthB...),
		WitnessStatements: witnessStatements,
	}, nil
}

// SHA256Hex returns the SHA-256 digest of the original wire bytes.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
