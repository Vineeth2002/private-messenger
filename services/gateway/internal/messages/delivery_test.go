package messages

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDecodeMessageEnvelopeV1RejectsEmptyInput(t *testing.T) {
	_, err := DecodeMessageEnvelopeV1(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidMessageEnvelope) {
		t.Fatalf("error=%v, want ErrInvalidMessageEnvelope", err)
	}
}

func TestDecodeMessageEnvelopeV1RejectsInvalidCBOR(t *testing.T) {
	_, err := DecodeMessageEnvelopeV1([]byte{0xff})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidMessageEnvelope) {
		t.Fatalf("error=%v, want ErrInvalidMessageEnvelope", err)
	}
}

func TestDeliveryServiceNilDB(t *testing.T) {
	service := NewDeliveryService(nil)
	_, err := service.Enqueue(context.Background(), nil, testExpiry())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUUIDText(t *testing.T) {
	id := [16]byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55,
		0x66, 0x77,
		0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	const want = "00112233-4455-6677-8899-aabbccddeeff"
	if got := uuidText(id); got != want {
		t.Fatalf("uuidText=%q, want %q", got, want)
	}
	if got := UUIDText(id); got != want {
		t.Fatalf("UUIDText=%q, want %q", got, want)
	}
}

func testExpiry() time.Time {
	return time.Unix(0, 0).UTC()
}
