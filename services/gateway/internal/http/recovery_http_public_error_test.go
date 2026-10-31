package gwhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

func TestRecoveryAPIHidesAccountExistenceForRecoveryKeyMismatch(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "unknown account", err: authorization.ErrAccountNotFound},
		{name: "recovery key mismatch", err: authorization.ErrAuthorizationConflict},
	}

	var firstStatus int
	var firstCode string
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeRecoveryServiceError(response, tt.err)

			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
			}

			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if body["error"] != "ERR_RECOVERY_CONFLICT" {
				t.Fatalf("error code = %q, want ERR_RECOVERY_CONFLICT", body["error"])
			}

			if i == 0 {
				firstStatus = response.Code
				firstCode = body["error"]
				return
			}
			if response.Code != firstStatus || body["error"] != firstCode {
				t.Fatalf("public response differs from unknown-account response: status=%d code=%q; want status=%d code=%q", response.Code, body["error"], firstStatus, firstCode)
			}
		})
	}
}

func TestRecoveryAPIPreservesNotFoundForUnknownRecoveryRequest(t *testing.T) {
	response := httptest.NewRecorder()
	writeRecoveryServiceError(response, authorization.ErrRecoveryRequestNotFound)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body["error"] != "ERR_RECOVERY_NOT_FOUND" {
		t.Fatalf("error code = %q, want ERR_RECOVERY_NOT_FOUND", body["error"])
	}
}
