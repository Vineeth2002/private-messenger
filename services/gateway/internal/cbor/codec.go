// Package cbor implements PM-CBOR-2026 (RFC 8949 s4.2.1 Core Deterministic
// Encoding, strict profile). It mirrors native/crypto-core/src/cbor.rs.
//
// DecodeStrict validates the ORIGINAL BYTES while parsing; it never
// decode-then-reserializes to "repair" input. The fxamacker/cbor/v2 mode glue for
// typed structs lives in package typed and always runs behind DecodeStrict.
//
// Bounds (architecture-review lock): wire input <= 256 KiB, container nesting <= 8,
// map entries <= 32, byte string <= 65,552 bytes. Violations -> ErrLimitExceeded.
// IMPLEMENTATION DECISIONS: tags and simple values other than false/true/null ->
// ErrUnsupportedItem; ErrLimitExceeded is a category added here; integers limited
// to [-2^64, 2^64-1].
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"unicode/utf8"
)

const (
	MaxWireInput  = 256 * 1024 // bytes of wire input
	MaxDepth      = 8          // container nesting levels
	MaxMapEntries = 32
	MaxBstr       = 65552 // 65,536 plaintext + 16-byte Poly1305 tag
)

// Category is a stable semantic error class; it, not any message, is the contract.
type Category string

const (
	ErrNonCanonicalInteger         Category = "ERR_NON_CANONICAL_INTEGER"
	ErrDuplicateMapKey             Category = "ERR_DUPLICATE_MAP_KEY"
	ErrFloatProhibited             Category = "ERR_FLOAT_PROHIBITED"
	ErrIndefiniteLengthProhibited  Category = "ERR_INDEFINITE_LENGTH_PROHIBITED"
	ErrUnsortedMapKeys             Category = "ERR_UNSORTED_MAP_KEYS"
	ErrTrailingBytes               Category = "ERR_TRAILING_BYTES"
	ErrMalformedCBOR               Category = "ERR_MALFORMED_CBOR"
	ErrUnsupportedItem             Category = "ERR_UNSUPPORTED_ITEM"
	ErrLimitExceeded               Category = "ERR_LIMIT_EXCEEDED"
)

// Error carries a Category.
type Error struct{ Cat Category }

func (e *Error) Error() string { return string(e.Cat) }

func fail(c Category) error { return &Error{Cat: c} }

// CategoryOf returns the Category of err, or "" if err is not a cbor *Error.
func CategoryOf(err error) Category {
	var e *Error
	if errors.As(err, &e) {
		return e.Cat
	}
	return ""
}

type Kind int

const (
	KindInt Kind = iota
	KindBytes
	KindText
	KindArray
	KindMap
	KindBool
	KindNull
)

// Int uses CBOR's native form: value = Arg when !Neg, and -1-Arg when Neg.
type Int struct {
	Neg bool
	Arg uint64
}

type Pair struct{ Key, Val Value }

type Value struct {
	Kind  Kind
	Int   Int
	Bytes []byte
	Text  string
	Array []Value
	Map   []Pair // pair order not significant for encoding
	Bool  bool
}

// ParseInt parses a decimal string in [-2^64, 2^64-1].
func ParseInt(s string) (Int, error) {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return Int{}, fmt.Errorf("bad integer %q", s)
	}
	if b.Sign() >= 0 {
		if !b.IsUint64() {
			return Int{}, fmt.Errorf("integer out of range %q", s)
		}
		return Int{Arg: b.Uint64()}, nil
	}
	m := new(big.Int).Neg(b)
	m.Sub(m, big.NewInt(1)) // -1 - n
	if !m.IsUint64() {
		return Int{}, fmt.Errorf("integer out of range %q", s)
	}
	return Int{Neg: true, Arg: m.Uint64()}, nil
}

// ------------------------------------------------------------------ encoding

func appendHead(out []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(out, m|byte(arg))
	case arg <= 0xff:
		return append(out, m|24, byte(arg))
	case arg <= 0xffff:
		out = append(out, m|25)
		return binary.BigEndian.AppendUint16(out, uint16(arg))
	case arg <= 0xffffffff:
		out = append(out, m|26)
		return binary.BigEndian.AppendUint32(out, uint32(arg))
	default:
		out = append(out, m|27)
		return binary.BigEndian.AppendUint64(out, arg)
	}
}

func encodeInto(v Value, out []byte, depth int) ([]byte, error) {
	switch v.Kind {
	case KindNull:
		return append(out, 0xf6), nil
	case KindBool:
		if v.Bool {
			return append(out, 0xf5), nil
		}
		return append(out, 0xf4), nil
	case KindInt:
		if v.Int.Neg {
			return appendHead(out, 1, v.Int.Arg), nil
		}
		return appendHead(out, 0, v.Int.Arg), nil
	case KindBytes:
		if len(v.Bytes) > MaxBstr {
			return nil, fail(ErrLimitExceeded)
		}
		out = appendHead(out, 2, uint64(len(v.Bytes)))
		return append(out, v.Bytes...), nil
	case KindText:
		out = appendHead(out, 3, uint64(len(v.Text)))
		return append(out, v.Text...), nil
	case KindArray:
		if depth >= MaxDepth {
			return nil, fail(ErrLimitExceeded)
		}
		out = appendHead(out, 4, uint64(len(v.Array)))
		var err error
		for _, it := range v.Array {
			if out, err = encodeInto(it, out, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case KindMap:
		if depth >= MaxDepth || len(v.Map) > MaxMapEntries {
			return nil, fail(ErrLimitExceeded)
		}
		type kv struct{ k, v []byte }
		enc := make([]kv, 0, len(v.Map))
		for _, p := range v.Map {
			kb, err := encodeInto(p.Key, nil, depth+1)
			if err != nil {
				return nil, err
			}
			vb, err := encodeInto(p.Val, nil, depth+1)
			if err != nil {
				return nil, err
			}
			enc = append(enc, kv{kb, vb})
		}
		// RFC 8949 s4.2.1: bytewise lexicographic order of ENCODED keys (not length-first).
		sort.Slice(enc, func(i, j int) bool { return bytes.Compare(enc[i].k, enc[j].k) < 0 })
		for i := 1; i < len(enc); i++ {
			if bytes.Equal(enc[i-1].k, enc[i].k) {
				return nil, fail(ErrDuplicateMapKey)
			}
		}
		out = appendHead(out, 5, uint64(len(enc)))
		for _, e := range enc {
			out = append(out, e.k...)
			out = append(out, e.v...)
		}
		return out, nil
	}
	return nil, fail(ErrUnsupportedItem)
}

// EncodeCanonical encodes v to PM-CBOR-2026.
func EncodeCanonical(v Value) ([]byte, error) { return encodeInto(v, nil, 0) }

// ------------------------------------------------------------------ decoding

func take(in []byte, pos *int, n uint64) ([]byte, error) {
	if n > uint64(len(in)-*pos) {
		return nil, fail(ErrMalformedCBOR)
	}
	s := in[*pos : *pos+int(n)]
	*pos += int(n)
	return s, nil
}

func readArg(in []byte, pos *int, ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		s, err := take(in, pos, 1)
		if err != nil {
			return 0, err
		}
		if v := uint64(s[0]); v >= 24 {
			return v, nil
		}
		return 0, fail(ErrNonCanonicalInteger)
	case ai == 25:
		s, err := take(in, pos, 2)
		if err != nil {
			return 0, err
		}
		if v := uint64(binary.BigEndian.Uint16(s)); v > 0xff {
			return v, nil
		}
		return 0, fail(ErrNonCanonicalInteger)
	case ai == 26:
		s, err := take(in, pos, 4)
		if err != nil {
			return 0, err
		}
		if v := uint64(binary.BigEndian.Uint32(s)); v > 0xffff {
			return v, nil
		}
		return 0, fail(ErrNonCanonicalInteger)
	case ai == 27:
		s, err := take(in, pos, 8)
		if err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(s); v > 0xffffffff {
			return v, nil
		}
		return 0, fail(ErrNonCanonicalInteger)
	}
	return 0, fail(ErrMalformedCBOR)
}

func decodeItem(in []byte, pos *int, depth int) (Value, error) {
	hb, err := take(in, pos, 1)
	if err != nil {
		return Value{}, err
	}
	major, ai := hb[0]>>5, hb[0]&0x1f
	if ai >= 28 && ai <= 30 {
		return Value{}, fail(ErrMalformedCBOR)
	}
	if ai == 31 {
		if major >= 2 && major <= 5 {
			return Value{}, fail(ErrIndefiniteLengthProhibited)
		}
		return Value{}, fail(ErrMalformedCBOR) // includes stray break 0xff
	}
	switch major {
	case 0, 1:
		a, err := readArg(in, pos, ai)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: KindInt, Int: Int{Neg: major == 1, Arg: a}}, nil
	case 2, 3:
		n, err := readArg(in, pos, ai)
		if err != nil {
			return Value{}, err
		}
		if major == 2 && n > MaxBstr {
			return Value{}, fail(ErrLimitExceeded)
		}
		b, err := take(in, pos, n)
		if err != nil {
			return Value{}, err
		}
		if major == 2 {
			return Value{Kind: KindBytes, Bytes: append([]byte{}, b...)}, nil
		}
		if !utf8.Valid(b) {
			return Value{}, fail(ErrMalformedCBOR)
		}
		return Value{Kind: KindText, Text: string(b)}, nil
	case 4:
		if depth >= MaxDepth {
			return Value{}, fail(ErrLimitExceeded)
		}
		n, err := readArg(in, pos, ai)
		if err != nil {
			return Value{}, err
		}
		items := []Value{}
		for i := uint64(0); i < n; i++ {
			it, err := decodeItem(in, pos, depth+1)
			if err != nil {
				return Value{}, err
			}
			items = append(items, it)
		}
		return Value{Kind: KindArray, Array: items}, nil
	case 5:
		if depth >= MaxDepth {
			return Value{}, fail(ErrLimitExceeded)
		}
		n, err := readArg(in, pos, ai)
		if err != nil {
			return Value{}, err
		}
		if n > MaxMapEntries {
			return Value{}, fail(ErrLimitExceeded)
		}
		pairs := []Pair{}
		keys := [][]byte{}
		for i := uint64(0); i < n; i++ {
			start := *pos
			k, err := decodeItem(in, pos, depth+1)
			if err != nil {
				return Value{}, err
			}
			keys = append(keys, in[start:*pos])
			v, err := decodeItem(in, pos, depth+1)
			if err != nil {
				return Value{}, err
			}
			pairs = append(pairs, Pair{k, v})
		}
		// Duplicate check first (covers non-adjacent duplicates), then order.
		sorted := append([][]byte{}, keys...)
		sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
		for i := 1; i < len(sorted); i++ {
			if bytes.Equal(sorted[i-1], sorted[i]) {
				return Value{}, fail(ErrDuplicateMapKey)
			}
		}
		for i := 1; i < len(keys); i++ {
			if bytes.Compare(keys[i-1], keys[i]) > 0 {
				return Value{}, fail(ErrUnsortedMapKeys)
			}
		}
		return Value{Kind: KindMap, Map: pairs}, nil
	case 6:
		return Value{}, fail(ErrUnsupportedItem)
	}
	// major 7
	switch ai {
	case 20:
		return Value{Kind: KindBool, Bool: false}, nil
	case 21:
		return Value{Kind: KindBool, Bool: true}, nil
	case 22:
		return Value{Kind: KindNull}, nil
	case 25, 26, 27:
		return Value{}, fail(ErrFloatProhibited)
	}
	return Value{}, fail(ErrUnsupportedItem)
}

// DecodeStrict decodes exactly one item that consumes ALL of in.
func DecodeStrict(in []byte) (Value, error) {
	if len(in) > MaxWireInput {
		return Value{}, fail(ErrLimitExceeded)
	}
	pos := 0
	v, err := decodeItem(in, &pos, 0)
	if err != nil {
		return Value{}, err
	}
	if pos != len(in) {
		return Value{}, fail(ErrTrailingBytes)
	}
	return v, nil
}

// IsCanonical reports whether in is a valid PM-CBOR-2026 encoding.
func IsCanonical(in []byte) bool {
	v, err := DecodeStrict(in)
	if err != nil {
		return false
	}
	out, err := EncodeCanonical(v)
	return err == nil && bytes.Equal(out, in)
}
