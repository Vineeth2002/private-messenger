package gwhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

func TestWriteCandidateEnrollmentServiceErrorAdoptionRequired(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeCandidateEnrollmentServiceError(recorder, authorization.ErrAccountAdoptionRequired)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}

	var body map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body["error"] != "ERR_ACCOUNT_ADOPTION_REQUIRED" {
		t.Fatalf("error code = %q, want ERR_ACCOUNT_ADOPTION_REQUIRED", body["error"])
	}
}
