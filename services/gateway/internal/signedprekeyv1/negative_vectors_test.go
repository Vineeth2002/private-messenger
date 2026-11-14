package signedprekeyv1

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type sharedNegativeVectorDocument struct {
	Contract     string                 `json:"contract"`
	DSKPublicHex string                 `json:"dsk_public_hex"`
	Cases        []sharedNegativeVector `json:"cases"`
}

type sharedNegativeVector struct {
	Name        string `json:"name"`
	WireHex     string `json:"wire_hex"`
	ParseError  string `json:"parse_error"`
	VerifyError string `json:"verify_error"`
}

func TestRustGoSharedNegativeVectors(t *testing.T) {
	// Run from services/gateway/internal/signedprekeyv1; the vectors are
	// intentionally stored once under native/crypto-core/testdata and read by
	// both language suites.
	const vectorPath = "../../../../native/crypto-core/testdata/signed_prekey_v1_negative_vectors.json"
	rawDocument, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read shared negative vectors: %v", err)
	}
	var document sharedNegativeVectorDocument
	if err := json.Unmarshal(rawDocument, &document); err != nil {
		t.Fatalf("decode shared negative vectors: %v", err)
	}
	if document.Contract != "PM-V1-SIGNED-PREKEY-v1-negative-vectors-candidate" {
		t.Fatalf("unexpected vector contract %q", document.Contract)
	}
	dsk, err := hex.DecodeString(document.DSKPublicHex)
	if err != nil {
		t.Fatalf("decode vector DSK: %v", err)
	}

	for _, vector := range document.Cases {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(vector.WireHex)
			if err != nil {
				t.Fatalf("decode wire hex: %v", err)
			}
			parsed, parseErr := Parse(wire)
			if vector.ParseError != "" {
				if !errors.Is(parseErr, goErrorForName(vector.ParseError)) {
					t.Fatalf("Parse error=%v, want %s", parseErr, vector.ParseError)
				}
				return
			}
			if parseErr != nil {
				t.Fatalf("Parse unexpectedly failed: %v", parseErr)
			}
			if vector.VerifyError != "" {
				if err := parsed.Verify(dsk); !errors.Is(err, goErrorForName(vector.VerifyError)) {
					t.Fatalf("Verify error=%v, want %s", err, vector.VerifyError)
				}
				return
			}
			if err := parsed.Verify(dsk); err != nil {
				t.Fatalf("Verify unexpectedly failed: %v", err)
			}
		})
	}
}

func goErrorForName(name string) error {
	switch name {
	case "InvalidCbor":
		return ErrInvalidCBOR
	case "InvalidShape":
		return ErrInvalidShape
	case "UnsupportedVersion":
		return ErrUnsupportedVersion
	case "InvalidField":
		return ErrInvalidField
	case "InvalidX25519PublicKey":
		return ErrInvalidX25519Public
	case "InvalidSignature":
		return ErrInvalidSignature
	default:
		return errors.New("unknown expected signed-prekey error: " + name)
	}
}
