package typed

import (
	"encoding/hex"
	"testing"
)

type envelope struct {
	Version uint   `cbor:"1,keyasint"`
	Counter uint   `cbor:"4,keyasint"`
	Payload []byte `cbor:"6,keyasint"`
}

func TestTypedRoundTrip(t *testing.T) {
	in := envelope{Version: 1, Counter: 300, Payload: []byte{1, 2, 3}}
	b, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out envelope
	ok, err := RoundTripsExactly(b, &out)
	if err != nil || !ok {
		t.Fatalf("roundtrip failed: ok=%v err=%v bytes=%s", ok, err, hex.EncodeToString(b))
	}
}

func TestTypedRejectsNonCanonical(t *testing.T) {
	var out envelope
	// {1: 1} with non-minimal key head 18 01.
	bad, _ := hex.DecodeString("a1180101")
	if err := UnmarshalStrict(bad, &out); err == nil {
		t.Fatal("non-canonical input accepted")
	}
}

// Pins the documented contract: UnmarshalStrict accepts a canonical input with an
// unknown map key (it does not check re-encode identity), RoundTripsExactly does not.
func TestUnmarshalStrictDoesNotCheckRoundTrip(t *testing.T) {
	// {1: 1, 4: 300, 6: h'010203', 99: 5}: canonical, but key 99 is not in envelope.
	data, _ := hex.DecodeString("a401010419012c0643010203186305")
	var out envelope
	if err := UnmarshalStrict(data, &out); err != nil {
		t.Fatalf("UnmarshalStrict rejected canonical input: %v", err)
	}
	var out2 envelope
	ok, err := RoundTripsExactly(data, &out2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("RoundTripsExactly must report false when an unknown field was ignored")
	}
}
