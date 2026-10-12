package devices

import (
	"testing"
	"time"
)

func TestUUIDRoundTrip(t *testing.T) {
	want := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	got, err := parseUUIDText(uuidText(want))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round-trip = %x, want %x", got, want)
	}
}

func TestParseUUIDRejectsMalformedText(t *testing.T) {
	for _, input := range []string{"", "00000000-0000-0000-0000", "zzzzzzzz-0000-0000-0000-000000000000"} {
		if _, err := parseUUIDText(input); err == nil {
			t.Fatalf("malformed UUID %q unexpectedly accepted", input)
		}
	}
}

func TestDecodeDeviceRejectsInvalidPublicKeyLengths(t *testing.T) {
	var zeros [16]byte
	if _, err := decodeDevice(uuidText(zeros), uuidText(zeros), 1, []byte{1}, make([]byte, 32), nil, false, time.Time{}); err == nil {
		t.Fatal("invalid DSK length unexpectedly accepted")
	}
}

func TestDecodeCertificateRejectsWrongDeviceOrEmptyBytes(t *testing.T) {
	deviceID := [16]byte{1}
	otherID := [16]byte{2}
	if _, err := decodeCertificate(uuidText(otherID), []byte{1}, time.Unix(1, 0), deviceID); err == nil {
		t.Fatal("certificate for wrong device unexpectedly accepted")
	}
	if _, err := decodeCertificate(uuidText(deviceID), nil, time.Unix(1, 0), deviceID); err == nil {
		t.Fatal("empty certificate unexpectedly accepted")
	}
}

func TestDecodeSignedPrekeyRejectsWrongDeviceOrLengths(t *testing.T) {
	deviceID := [16]byte{1}
	otherID := [16]byte{2}
	if _, err := decodeSignedPrekey(uuidText(otherID), 1, make([]byte, 32), make([]byte, 64), deviceID); err == nil {
		t.Fatal("prekey for wrong device unexpectedly accepted")
	}
	if _, err := decodeSignedPrekey(uuidText(deviceID), 1, []byte{1}, make([]byte, 64), deviceID); err == nil {
		t.Fatal("invalid prekey public key length unexpectedly accepted")
	}
	if _, err := decodeSignedPrekey(uuidText(deviceID), 1, make([]byte, 32), []byte{1}, deviceID); err == nil {
		t.Fatal("invalid prekey signature length unexpectedly accepted")
	}
}
