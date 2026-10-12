package kt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

var (
	leafSignDomain = []byte("PM-V1-KT-LEAF-SIGN-v1")
	leafHashDomain = []byte("PM-V1-KT-LEAF-HASH-v1")
	smtKeyDomain   = []byte("PM-V1-SMT-KEY")
)

func leafCoreValue(leaf TransparencyLeafV1) cbor.Value {
	return cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 1}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.AccountID[:]}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 2}}, Val: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: leaf.Epoch}}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 3}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.DeviceID[:]}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 4}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.DSKPub[:]}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 5}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.DDHKPub[:]}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 6}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.CertDH[:]}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 7}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.SPKPub[:]}},
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 8}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: leaf.PushPK[:]}},
	}}
}

// VerifyTransparencyLeafV1 verifies the frozen DSK signature and returns its leaf hash.
func VerifyTransparencyLeafV1(data []byte) (TransparencyLeafV1, [32]byte, error) {
	leaf, err := ParseTransparencyLeafV1(data)
	if err != nil {
		return TransparencyLeafV1{}, [32]byte{}, err
	}
	core, err := cbor.EncodeCanonical(leafCoreValue(leaf))
	if err != nil {
		return TransparencyLeafV1{}, [32]byte{}, err
	}
	message := append(append([]byte{}, leafSignDomain...), core...)
	if !ed25519.Verify(ed25519.PublicKey(leaf.DSKPub[:]), message, leaf.Signature[:]) {
		return TransparencyLeafV1{}, [32]byte{}, fmt.Errorf("kt: invalid leaf signature")
	}
	h := sha256.New()
	h.Write(leafHashDomain)
	h.Write(data)
	var leafHash [32]byte
	copy(leafHash[:], h.Sum(nil))
	return leaf, leafHash, nil
}

// SMTKey implements SHA-256("PM-V1-SMT-KEY" || AccountID || DeviceID).
func SMTKey(accountID [16]byte, deviceID [16]byte) [32]byte {
	h := sha256.New()
	h.Write(smtKeyDomain)
	h.Write(accountID[:])
	h.Write(deviceID[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

const (
	sthSignDomain     = "PM-V1-KT-STH-SIGN-v1"
	witnessSignDomain = "PM-V1-KT-WITNESS-SIGN-v1"
)

func intPair(key, value uint64) cbor.Pair {
	return cbor.Pair{
		Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}},
		Val: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}},
	}
}

func bytesPair(key uint64, value []byte) cbor.Pair {
	return cbor.Pair{
		Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}},
		Val: cbor.Value{Kind: cbor.KindBytes, Bytes: value},
	}
}

func sthBodyValue(sth SignedTreeHeadV1) cbor.Value {
	return cbor.Value{
		Kind: cbor.KindMap,
		Map: []cbor.Pair{
			intPair(1, ProtocolVersion),
			intPair(2, sth.TreeSize),
			bytesPair(3, sth.SMTRoot[:]),
			bytesPair(4, sth.HistoryRoot[:]),
			intPair(5, sth.IssuedAt),
			bytesPair(6, sth.LogID[:]),
		},
	}
}

func witnessBodyValue(statement WitnessStatementV1) cbor.Value {
	return cbor.Value{
		Kind: cbor.KindMap,
		Map: []cbor.Pair{
			intPair(1, ProtocolVersion),
			bytesPair(2, statement.WitnessID[:]),
			bytesPair(3, statement.LogID[:]),
			intPair(4, statement.TreeSize),
			bytesPair(5, statement.STHDigest[:]),
		},
	}
}

// VerifySignedTreeHeadV1 verifies the exact frozen STH signature.
func VerifySignedTreeHeadV1(data []byte, logPublic [32]byte) (SignedTreeHeadV1, error) {
	sth, err := ParseSignedTreeHeadV1(data)
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	body, err := cbor.EncodeCanonical(sthBodyValue(sth))
	if err != nil {
		return SignedTreeHeadV1{}, err
	}
	message := append(append([]byte{}, []byte(sthSignDomain)...), body...)
	if !ed25519.Verify(ed25519.PublicKey(logPublic[:]), message, sth.Signature[:]) {
		return SignedTreeHeadV1{}, fmt.Errorf("kt: invalid STH signature")
	}
	return sth, nil
}

// VerifyWitnessStatementV1 verifies a frozen witness statement against the registry.
func VerifyWitnessStatementV1(data []byte, registry map[[16]byte][32]byte) (WitnessStatementV1, error) {
	statement, err := ParseWitnessStatementV1(data)
	if err != nil {
		return WitnessStatementV1{}, err
	}
	public, ok := registry[statement.WitnessID]
	if !ok {
		return WitnessStatementV1{}, fmt.Errorf("kt: unknown witness")
	}
	body, err := cbor.EncodeCanonical(witnessBodyValue(statement))
	if err != nil {
		return WitnessStatementV1{}, err
	}
	message := append(append([]byte{}, []byte(witnessSignDomain)...), body...)
	if !ed25519.Verify(ed25519.PublicKey(public[:]), message, statement.Signature[:]) {
		return WitnessStatementV1{}, fmt.Errorf("kt: invalid witness signature")
	}
	return statement, nil
}

func IsSTHEquivocation(a, b SignedTreeHeadV1) bool {
	return a.TreeSize == b.TreeSize &&
		a.LogID == b.LogID &&
		(a.SMTRoot != b.SMTRoot || a.HistoryRoot != b.HistoryRoot)
}

func WitnessConflictExists(statements []WitnessStatementV1) bool {
	type conflictKey struct {
		logID    [32]byte
		treeSize uint64
	}
	seen := make(map[conflictKey][32]byte)
	for _, statement := range statements {
		key := conflictKey{logID: statement.LogID, treeSize: statement.TreeSize}
		if previous, ok := seen[key]; ok {
			if previous != statement.STHDigest {
				return true
			}
			continue
		}
		seen[key] = statement.STHDigest
	}
	return false
}

func WitnessQuorumCount(statements []WitnessStatementV1, sth SignedTreeHeadV1) int {
	seen := make(map[[16]byte]struct{})
	for _, statement := range statements {
		if statement.LogID == sth.LogID &&
			statement.TreeSize == sth.TreeSize &&
			statement.STHDigest == sth.STHDigest {
			seen[statement.WitnessID] = struct{}{}
		}
	}
	return len(seen)
}
