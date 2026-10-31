package deviceauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

const fixtureProofHex = "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000007000000006b49d200a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfa0df5dff74291171e1ca91e689ef8dcdc719e6851bd64f8695460e47e9d69304808eec02c3555d26e761732b5656d8f10c6700af67f01db3d4298692b80bec0b"
const fixturePublicKeyHex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

func fixture(t *testing.T) (string, ed25519.PublicKey, time.Time) {
	t.Helper()
	raw, err := hex.DecodeString(fixtureProofHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(fixturePublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return Scheme + " " + base64.RawURLEncoding.EncodeToString(raw), ed25519.PublicKey(pub), time.Unix(1_800_000_000, 0)
}

func TestRustSignedFixtureVerifiesInGo(t *testing.T) {
	header, pub, now := fixture(t)
	principal, err := VerifyAuthorizationHeader(header, pub, "POST", "/v1/candidate/messages?limit=10", []byte(`{"ciphertext":"fixture"}`), now)
	if err != nil {
		t.Fatalf("Rust fixture did not verify: %v", err)
	}
	if principal.Epoch != 7 || principal.Timestamp != 1_800_000_000 || principal.AccountID[15] != 15 || principal.DeviceID[0] != 16 {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestRequestBindingRejectsMethodTargetAndBodyChanges(t *testing.T) {
	header, pub, now := fixture(t)
	cases := []struct{ name, method, target, body string }{
		{"method", "GET", "/v1/candidate/messages?limit=10", `{"ciphertext":"fixture"}`},
		{"target", "POST", "/v1/candidate/messages?limit=11", `{"ciphertext":"fixture"}`},
		{"body", "POST", "/v1/candidate/messages?limit=10", `{"ciphertext":"changed"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyAuthorizationHeader(header, pub, tc.method, tc.target, []byte(tc.body), now); !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("error=%v, want ErrInvalidProof", err)
			}
		})
	}
}

func TestTimestampWindowIsFiveMinutes(t *testing.T) {
	header, pub, now := fixture(t)
	if _, err := VerifyAuthorizationHeader(header, pub, "POST", "/v1/candidate/messages?limit=10", []byte(`{"ciphertext":"fixture"}`), now.Add(5*time.Minute)); err != nil {
		t.Fatalf("exact boundary rejected: %v", err)
	}
	if _, err := VerifyAuthorizationHeader(header, pub, "POST", "/v1/candidate/messages?limit=10", []byte(`{"ciphertext":"fixture"}`), now.Add(5*time.Minute+time.Second)); !errors.Is(err, ErrExpiredProof) {
		t.Fatalf("error=%v, want ErrExpiredProof", err)
	}
}

func TestParserRejectsNonCanonicalOrMalformedHeaders(t *testing.T) {
	header, _, _ := fixture(t)
	cases := []string{
		"Bearer " + header,
		header + "=",
		Scheme + "  " + header[len(Scheme)+1:],
		Scheme + " " + base64.RawURLEncoding.EncodeToString([]byte("short")),
	}
	for _, candidate := range cases {
		if _, err := ParseAuthorizationHeader(candidate); !errors.Is(err, ErrMalformedProof) {
			t.Errorf("header %q: error=%v, want ErrMalformedProof", candidate, err)
		}
	}
}

func TestInvalidSignatureAndTimestampAreRejected(t *testing.T) {
	header, pub, now := fixture(t)
	raw, _ := base64.RawURLEncoding.DecodeString(header[len(Scheme)+1:])
	raw[len(raw)-1] ^= 1
	altered := Scheme + " " + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := VerifyAuthorizationHeader(altered, pub, "POST", "/v1/candidate/messages?limit=10", []byte(`{"ciphertext":"fixture"}`), now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("altered signature error=%v, want ErrInvalidProof", err)
	}
	if _, err := VerifyAuthorizationHeader(header, pub, "POST", "/v1/candidate/messages?limit=10", []byte(`{"ciphertext":"fixture"}`), now.Add(-5*time.Minute-time.Second)); !errors.Is(err, ErrExpiredProof) {
		t.Fatalf("stale proof error=%v, want ErrExpiredProof", err)
	}
}
