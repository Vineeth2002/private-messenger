package gwhttp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

func TestCandidateEnrollmentHandlerMapsRecoveryPending(t *testing.T) {
	recoveryKey := bytes.Repeat([]byte{0x44}, 32)
	certificate := []byte{0xa7, 0x01}
	proof := []byte{0xa8, 0x01}

	challengeBody, err := json.Marshal(candidateEnrollmentChallengeRequest{
		EnrollmentCertificateHex: hex.EncodeToString(certificate),
		RecoveryPublicKeyHex:     hex.EncodeToString(recoveryKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	activationBody, err := json.Marshal(candidateEnrollmentActivateRequest{
		EnrollmentCertificateHex: hex.EncodeToString(certificate),
		ProofHex:                 hex.EncodeToString(proof),
		RecoveryPublicKeyHex:     hex.EncodeToString(recoveryKey),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name               string
		path               string
		body               []byte
		setRecoveryPending func(*candidateEnrollmentServiceStub)
		wantIssueCalls     int
		wantActivateCalls  int
	}{
		{
			name: "challenge issuance",
			path: candidateEnrollmentChallengeURL,
			body: challengeBody,
			setRecoveryPending: func(service *candidateEnrollmentServiceStub) {
				service.issueErr = authorization.ErrRecoveryPending
			},
			wantIssueCalls: 1,
		},
		{
			name: "activation",
			path: candidateEnrollmentActivateURL,
			body: activationBody,
			setRecoveryPending: func(service *candidateEnrollmentServiceStub) {
				service.activateErr = authorization.ErrRecoveryPending
			},
			wantActivateCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &candidateEnrollmentServiceStub{}
			test.setRecoveryPending(service)
			handler := NewHandlerWithCandidateEnrollment(http.NotFoundHandler(), service)

			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}

			var payload map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(payload) != 1 || payload["error"] != "ERR_RECOVERY_PENDING" {
				t.Fatalf("response payload=%v, want only ERR_RECOVERY_PENDING", payload)
			}
			if service.issueCalls != test.wantIssueCalls || service.activateCalls != test.wantActivateCalls {
				t.Fatalf("service calls issue=%d activate=%d, want issue=%d activate=%d",
					service.issueCalls, service.activateCalls, test.wantIssueCalls, test.wantActivateCalls)
			}
		})
	}
}
