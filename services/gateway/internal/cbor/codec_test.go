package cbor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const vectorPath = "../../../../test-vectors/v1/cbor_canonical_codec.json"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func parseTagged(t *testing.T, raw json.RawMessage) Value {
	t.Helper()
	var o map[string]json.RawMessage
	if err := json.Unmarshal(raw, &o); err != nil || len(o) != 1 {
		t.Fatalf("bad tagged value %s", raw)
	}
	for tag, body := range o {
		switch tag {
		case "int":
			var s string
			if err := json.Unmarshal(body, &s); err != nil {
				t.Fatal(err)
			}
			i, err := ParseInt(s)
			if err != nil {
				t.Fatal(err)
			}
			return Value{Kind: KindInt, Int: i}
		case "bytes":
			var s string
			_ = json.Unmarshal(body, &s)
			return Value{Kind: KindBytes, Bytes: mustHex(t, s)}
		case "text":
			var s string
			_ = json.Unmarshal(body, &s)
			return Value{Kind: KindText, Text: s}
		case "bool":
			var b bool
			_ = json.Unmarshal(body, &b)
			return Value{Kind: KindBool, Bool: b}
		case "null":
			return Value{Kind: KindNull}
		case "array":
			var items []json.RawMessage
			_ = json.Unmarshal(body, &items)
			out := []Value{}
			for _, it := range items {
				out = append(out, parseTagged(t, it))
			}
			return Value{Kind: KindArray, Array: out}
		case "map":
			var pairs [][2]json.RawMessage
			_ = json.Unmarshal(body, &pairs)
			out := []Pair{}
			for _, p := range pairs {
				out = append(out, Pair{parseTagged(t, p[0]), parseTagged(t, p[1])})
			}
			return Value{Kind: KindMap, Map: out}
		}
	}
	t.Fatalf("unknown tag in %s", raw)
	return Value{}
}

type vectorFile struct {
	Positive []struct {
		ID      string          `json:"id"`
		Value   json.RawMessage `json:"value"`
		CborHex string          `json:"cbor_hex"`
	} `json:"positive"`
	Negative []struct {
		ID      string `json:"id"`
		CborHex string `json:"cbor_hex"`
		Error   string `json:"error"`
	} `json:"negative"`
	Quarantined []struct {
		Value              json.RawMessage `json:"value"`
		AsWrittenHex       string          `json:"spec_s28_corrected_hex_as_written"`
		AsWrittenDecodesTo string          `json:"spec_s28_as_written_decodes_to"`
		RFCHex             string          `json:"rfc8949_hex"`
	} `json:"quarantined"`
}

func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(vectorPath))
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	parity := map[string]string{}

	for _, p := range vf.Positive {
		want := mustHex(t, p.CborHex)
		got, err := EncodeCanonical(parseTagged(t, p.Value))
		if err != nil {
			t.Fatalf("%s: encode failed: %v", p.ID, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: encode mismatch\n got %x\nwant %x", p.ID, got, want)
		}
		dec, err := DecodeStrict(want)
		if err != nil {
			t.Fatalf("%s: decode rejected: %v", p.ID, err)
		}
		again, err := EncodeCanonical(dec)
		if err != nil || !bytes.Equal(again, want) {
			t.Fatalf("%s: roundtrip mismatch", p.ID)
		}
		if !IsCanonical(want) {
			t.Fatalf("%s: IsCanonical false", p.ID)
		}
		parity["positive:"+p.ID] = hex.EncodeToString(got)
	}

	for _, n := range vf.Negative {
		in := mustHex(t, n.CborHex)
		_, err := DecodeStrict(in)
		if err == nil {
			t.Fatalf("%s: negative vector ACCEPTED", n.ID)
		}
		if got := CategoryOf(err); string(got) != n.Error {
			t.Fatalf("%s: category %q, want %q", n.ID, got, n.Error)
		}
		if IsCanonical(in) {
			t.Fatalf("%s: IsCanonical true", n.ID)
		}
		parity["negative:"+n.ID] = n.Error
	}

	for _, q := range vf.Quarantined {
		_, err := DecodeStrict(mustHex(t, q.AsWrittenHex))
		if string(CategoryOf(err)) != q.AsWrittenDecodesTo {
			t.Fatalf("quarantined as-written bytes: got %v", err)
		}
		got, err := EncodeCanonical(parseTagged(t, q.Value))
		if err != nil || !bytes.Equal(got, mustHex(t, q.RFCHex)) {
			t.Fatalf("quarantined RFC bytes mismatch")
		}
	}

	if out := os.Getenv("PM_PARITY_OUT"); out != "" {
		b, _ := json.Marshal(parity)
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDecodeNeverNormalizesInput(t *testing.T) {
	for _, h := range []string{"180a", "a201010102", "0000", "a240616218186161"} {
		if _, err := DecodeStrict(mustHex(t, h)); err == nil {
			t.Fatalf("%s accepted", h)
		}
	}
}

func TestLengthFirstRegression(t *testing.T) {
	m := Value{Kind: KindMap, Map: []Pair{
		{Value{Kind: KindBytes, Bytes: []byte{}}, Value{Kind: KindText, Text: "b"}},
		{Value{Kind: KindInt, Int: Int{Arg: 24}}, Value{Kind: KindText, Text: "a"}},
	}}
	got, err := EncodeCanonical(m)
	if err != nil || hex.EncodeToString(got) != "a218186161406162" {
		t.Fatalf("got %x err %v", got, err)
	}
}

func nested(n int) []byte {
	return append(bytes.Repeat([]byte{0x81}, n), 0x00)
}

func TestLimits(t *testing.T) {
	if _, err := DecodeStrict(nested(8)); err != nil {
		t.Fatalf("8 nested containers rejected: %v", err)
	}
	if _, err := DecodeStrict(nested(9)); CategoryOf(err) != ErrLimitExceeded {
		t.Fatalf("9 nested containers: %v", err)
	}
	ok := append([]byte{0x5a, 0x00, 0x01, 0x00, 0x10}, make([]byte, MaxBstr)...)
	if _, err := DecodeStrict(ok); err != nil {
		t.Fatalf("bstr at limit rejected: %v", err)
	}
	if _, err := DecodeStrict([]byte{0x5a, 0x00, 0x01, 0x00, 0x11}); CategoryOf(err) != ErrLimitExceeded {
		t.Fatalf("bstr over limit: %v", err)
	}
	if _, err := DecodeStrict(make([]byte, MaxWireInput+1)); CategoryOf(err) != ErrLimitExceeded {
		t.Fatalf("wire input over limit: %v", err)
	}
	mk := func(n int) Value {
		m := Value{Kind: KindMap}
		for i := 0; i < n; i++ {
			m.Map = append(m.Map, Pair{Value{Kind: KindInt, Int: Int{Arg: uint64(i)}}, Value{Kind: KindInt}})
		}
		return m
	}
	enc, err := EncodeCanonical(mk(32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict(enc); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeCanonical(mk(33)); CategoryOf(err) != ErrLimitExceeded {
		t.Fatalf("33-entry map: %v", err)
	}
}
