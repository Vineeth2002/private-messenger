package deviceauth

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestAndroidGeneratedRequestProofFixture verifies a proof exported by the Android
// instrumentation test. Set PM_ANDROID_PROOF_FIXTURE to the pulled JSON fixture path.
// The fixture contains a short-lived signed request and public key only, never a private key.
func TestAndroidGeneratedRequestProofFixture(t *testing.T) {
	path := os.Getenv("PM_ANDROID_PROOF_FIXTURE")
	if path == "" {
		t.Skip("PM_ANDROID_PROOF_FIXTURE is not set; Android runtime fixture not supplied")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Android proof fixture: %v", err)
	}
	var fixture struct {
		AuthorizationHeader string `json:"authorization_header"`
		PublicKeyHex        string `json:"public_key_hex"`
		Method              string `json:"method"`
		RequestTarget       string `json:"request_target"`
		BodyBase64          string `json:"body_base64"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode Android proof fixture: %v", err)
	}
	publicKey, err := hex.DecodeString(fixture.PublicKeyHex)
	if err != nil || len(publicKey) != 32 {
		t.Fatalf("invalid Android DSK public key: len=%d err=%v", len(publicKey), err)
	}
	body, err := base64.StdEncoding.DecodeString(fixture.BodyBase64)
	if err != nil {
		t.Fatalf("decode Android request body: %v", err)
	}

	principal, err := VerifyAuthorizationHeader(
		fixture.AuthorizationHeader,
		publicKey,
		fixture.Method,
		fixture.RequestTarget,
		body,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("Android-generated request proof did not verify: %v", err)
	}
	if principal.Epoch == 0 || principal.Timestamp == 0 {
		t.Fatalf("Android proof returned invalid principal: %+v", principal)
	}
	t.Logf("verified Android-generated request proof: account=%x device=%x epoch=%d", principal.AccountID, principal.DeviceID, principal.Epoch)
}
