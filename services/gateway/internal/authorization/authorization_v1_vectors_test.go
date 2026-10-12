package authorization

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type authorizationVectorFile struct {
	Protocol string `json:"protocol"`
	Recovery struct {
		PublicKeyHex string `json:"public_key_hex"`
		CommitmentHex string `json:"commitment_hex"`
	} `json:"recovery"`
	Enrollment struct {
		ID string `json:"id"`
		Version uint64 `json:"version"`
		AccountIDHex string `json:"account_id_hex"`
		Epoch uint64 `json:"epoch"`
		DeviceIDHex string `json:"device_id_hex"`
		DSKPubHex string `json:"dsk_pub_hex"`
		DDHKPubHex string `json:"ddhk_pub_hex"`
		DomainHex string `json:"domain_hex"`
		CoreCBORHex string `json:"core_cbor_hex"`
		SignatureHex string `json:"signature_hex"`
		CertificateCBORHex string `json:"certificate_cbor_hex"`
	} `json:"enrollment"`
	Transitions []struct {
		ID string `json:"id"`
		Version uint64 `json:"version"`
		AccountIDHex string `json:"account_id_hex"`
		OldEpoch uint64 `json:"old_epoch"`
		NewEpoch uint64 `json:"new_epoch"`
		Action uint64 `json:"action"`
		DeviceIDHex string `json:"device_id_hex"`
		DomainHex string `json:"domain_hex"`
		CoreCBORHex string `json:"core_cbor_hex"`
		SignatureHex string `json:"signature_hex"`
		CertificateCBORHex string `json:"certificate_cbor_hex"`
	} `json:"transitions"`
	Negative []struct {
		ID string `json:"id"`
		Type string `json:"type"`
		CertificateCBORHex string `json:"certificate_cbor_hex"`
	} `json:"negative"`
}

func loadAuthorizationVectors(t *testing.T) authorizationVectorFile {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..", "test-vectors", "v1", "authorization_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var vectors authorizationVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func decodeVectorHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixed16Vector(t *testing.T, s string) [16]byte {
	t.Helper()
	var out [16]byte
	copy(out[:], decodeVectorHex(t, s))
	return out
}

func fixed32Vector(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], decodeVectorHex(t, s))
	return out
}

func TestAuthorizationV1SharedVectors(t *testing.T) {
	v := loadAuthorizationVectors(t)

	if v.Protocol != "authorization-v1" {
		t.Fatalf("protocol = %q", v.Protocol)
	}

	recoveryPub := fixed32Vector(t, v.Recovery.PublicKeyHex)
	commitment := fixed32Vector(t, v.Recovery.CommitmentHex)
	if got := RecoveryCommitment(recoveryPub); got != commitment {
		t.Fatalf("recovery commitment mismatch: got %x want %x", got, commitment)
	}

	enrollment := v.Enrollment
	rawEnrollment := decodeVectorHex(t, enrollment.CertificateCBORHex)
	cert, err := ParseDeviceEnrollmentAuthorizationV1(rawEnrollment)
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.Verify(recoveryPub); err != nil {
		t.Fatalf("enrollment verify: %v", err)
	}
	if !bytes.Equal(cert.Raw, rawEnrollment) {
		t.Fatal("enrollment raw bytes changed during parse")
	}
	if cert.AccountID != fixed16Vector(t, enrollment.AccountIDHex) {
		t.Fatal("enrollment account ID mismatch")
	}
	if cert.Epoch != enrollment.Epoch {
		t.Fatalf("enrollment epoch = %d want %d", cert.Epoch, enrollment.Epoch)
	}
	if cert.DeviceID != fixed16Vector(t, enrollment.DeviceIDHex) {
		t.Fatal("enrollment device ID mismatch")
	}
	if cert.DSKPub != fixed32Vector(t, enrollment.DSKPubHex) {
		t.Fatal("enrollment DSK mismatch")
	}
	if cert.DDHKPub != fixed32Vector(t, enrollment.DDHKPubHex) {
		t.Fatal("enrollment DDHK mismatch")
	}
	if got := hex.EncodeToString(cert.Signature[:]); got != enrollment.SignatureHex {
		t.Fatalf("enrollment signature = %s want %s", got, enrollment.SignatureHex)
	}
	core, err := cert.canonicalCore()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(core); got != enrollment.CoreCBORHex {
		t.Fatalf("enrollment core = %s want %s", got, enrollment.CoreCBORHex)
	}
	if enrollment.DomainHex != hex.EncodeToString([]byte(DeviceEnrollmentDomain)) {
		t.Fatalf("enrollment domain mismatch")
	}

	if len(v.Transitions) != 2 {
		t.Fatalf("transition count = %d want 2", len(v.Transitions))
	}

	for _, tv := range v.Transitions {
		raw := decodeVectorHex(t, tv.CertificateCBORHex)
		cert, err := ParseEpochTransitionAuthorizationV1(raw)
		if err != nil {
			t.Fatalf("%s parse: %v", tv.ID, err)
		}
		if err := cert.Verify(recoveryPub); err != nil {
			t.Fatalf("%s verify: %v", tv.ID, err)
		}
		if cert.AccountID != fixed16Vector(t, tv.AccountIDHex) {
			t.Fatalf("%s account ID mismatch", tv.ID)
		}
		if cert.OldEpoch != tv.OldEpoch || cert.NewEpoch != tv.NewEpoch {
			t.Fatalf("%s epoch mismatch", tv.ID)
		}
		if uint64(cert.Action) != tv.Action {
			t.Fatalf("%s action mismatch", tv.ID)
		}

		expectedDevice := fixed16Vector(t, tv.DeviceIDHex)
		if cert.DeviceID != expectedDevice {
			t.Fatalf("%s device ID mismatch", tv.ID)
		}

		if got := hex.EncodeToString(cert.Signature[:]); got != tv.SignatureHex {
			t.Fatalf("%s signature = %s want %s", tv.ID, got, tv.SignatureHex)
		}
		core, err := cert.canonicalCore()
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(core); got != tv.CoreCBORHex {
			t.Fatalf("%s core = %s want %s", tv.ID, got, tv.CoreCBORHex)
		}
		if tv.DomainHex != hex.EncodeToString([]byte(EpochTransitionDomain)) {
			t.Fatalf("%s domain mismatch", tv.ID)
		}
	}
}

func TestAuthorizationV1NegativeSignatureTamperVectors(t *testing.T) {
	v := loadAuthorizationVectors(t)
	recoveryPub := fixed32Vector(t, v.Recovery.PublicKeyHex)

	for _, n := range v.Negative {
		raw := decodeVectorHex(t, n.CertificateCBORHex)

		switch n.ID {
		case "enrollment-basic-signature-tamper":
			cert, err := ParseDeviceEnrollmentAuthorizationV1(raw)
			if err != nil {
				t.Fatalf("%s parse: %v", n.ID, err)
			}
			if err := cert.Verify(recoveryPub); err == nil {
				t.Fatalf("%s was accepted", n.ID)
			}
		case "revoke-device-signature-tamper", "recovery-reset-signature-tamper":
			cert, err := ParseEpochTransitionAuthorizationV1(raw)
			if err != nil {
				t.Fatalf("%s parse: %v", n.ID, err)
			}
			if err := cert.Verify(recoveryPub); err == nil {
				t.Fatalf("%s was accepted", n.ID)
			}
		default:
			t.Fatalf("unexpected negative vector %q", n.ID)
		}
	}
}

