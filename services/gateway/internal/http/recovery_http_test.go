package gwhttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

type recoveryAPIServiceStub struct {
	beginState   authorization.RecoveryRequestState
	abortState   authorization.RecoveryRequestState
	challenge    authorization.EnrollmentChallenge
	beginErr     error
	abortErr     error
	challengeErr error
	activateErr  error

	beginRequestRaw []byte
	beginCertRaw    []byte
	beginRecovery   [32]byte
	abortRaw        []byte
	challengeID     [16]byte
	challengeCert   []byte
	challengeKey    [32]byte
	activateID      [16]byte
	activateCert    []byte
	activateProof   []byte
	activateKey     [32]byte
	beginCalls      int
	abortCalls      int
	challengeCalls  int
	activateCalls   int
}

func (s *recoveryAPIServiceStub) BeginRecovery(_ context.Context, requestRaw, certificateRaw []byte, recoveryPublicKey [32]byte) (authorization.RecoveryRequestState, error) {
	s.beginCalls++
	s.beginRequestRaw = append([]byte(nil), requestRaw...)
	s.beginCertRaw = append([]byte(nil), certificateRaw...)
	s.beginRecovery = recoveryPublicKey
	return s.beginState, s.beginErr
}

func (s *recoveryAPIServiceStub) AbortRecovery(_ context.Context, abortRaw []byte) (authorization.RecoveryRequestState, error) {
	s.abortCalls++
	s.abortRaw = append([]byte(nil), abortRaw...)
	return s.abortState, s.abortErr
}

func (s *recoveryAPIServiceStub) IssueRecoveryEnrollmentChallenge(_ context.Context, requestID [16]byte, certificateRaw []byte, recoveryPublicKey [32]byte) (authorization.EnrollmentChallenge, error) {
	s.challengeCalls++
	s.challengeID = requestID
	s.challengeCert = append([]byte(nil), certificateRaw...)
	s.challengeKey = recoveryPublicKey
	return s.challenge, s.challengeErr
}

func (s *recoveryAPIServiceStub) ActivateRecoveryEnrollment(_ context.Context, requestID [16]byte, certificateRaw, proofRaw []byte, recoveryPublicKey [32]byte) error {
	s.activateCalls++
	s.activateID = requestID
	s.activateCert = append([]byte(nil), certificateRaw...)
	s.activateProof = append([]byte(nil), proofRaw...)
	s.activateKey = recoveryPublicKey
	return s.activateErr
}

func recoveryJSONRequest(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRecoveryAPIHandlerBeginRecoveryPassesExactWireBytes(t *testing.T) {
	var state authorization.RecoveryRequestState
	state.RequestID[0] = 0x11
	state.RequestDigest[0] = 0x22
	state.Status = authorization.RecoveryRequestPending
	state.AcceptedAt = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	state.FinalizeAfter = state.AcceptedAt.Add(48 * time.Hour)
	service := &recoveryAPIServiceStub{beginState: state}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)

	requestRaw := []byte{0xa1, 0x01, 0x02}
	certificateRaw := []byte{0xa1, 0x03, 0x04}
	recoveryPublic := make([]byte, 32)
	recoveryPublic[0] = 0x55
	response := recoveryJSONRequest(t, handler, recoveryBeginURL, map[string]string{
		"recovery_request_cbor_hex":  hex.EncodeToString(requestRaw),
		"enrollment_certificate_hex": hex.EncodeToString(certificateRaw),
		"recovery_public_key_hex":    hex.EncodeToString(recoveryPublic),
	})

	if response.Code != http.StatusOK {
		t.Fatalf("begin status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.beginCalls != 1 || string(service.beginRequestRaw) != string(requestRaw) || string(service.beginCertRaw) != string(certificateRaw) {
		t.Fatalf("begin service did not receive exact wire bytes: calls=%d request=%x cert=%x", service.beginCalls, service.beginRequestRaw, service.beginCertRaw)
	}
	if service.beginRecovery[0] != 0x55 {
		t.Fatalf("recovery public key was not passed intact")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	var got recoveryRequestStateHTTPResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != string(authorization.RecoveryRequestPending) || got.RequestIDHex != hex.EncodeToString(state.RequestID[:]) || got.FinalizeAfter != state.FinalizeAfter.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected recovery state response: %+v", got)
	}
}

func TestRecoveryAPIHandlerAbortPassesExactSignedAbort(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)
	abortRaw := []byte{0xa1, 0x01, 0x09}
	response := recoveryJSONRequest(t, handler, recoveryAbortURL, map[string]string{
		"recovery_abort_cbor_hex": hex.EncodeToString(abortRaw),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("abort status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.abortCalls != 1 || string(service.abortRaw) != string(abortRaw) {
		t.Fatalf("abort service did not receive exact bytes: calls=%d raw=%x", service.abortCalls, service.abortRaw)
	}
}

func TestRecoveryAPIHandlerIssuesBoundReplacementChallenge(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	service.challenge.ID[0] = 0x31
	service.challenge.Nonce[0] = 0x42
	service.challenge.ExpiresAt = time.Date(2026, 10, 31, 11, 5, 0, 0, time.UTC)
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)
	requestID := make([]byte, 16)
	requestID[0] = 0x10
	certificate := []byte{0xa1, 0x01, 0x02}
	publicKey := make([]byte, 32)
	publicKey[0] = 0x77
	response := recoveryJSONRequest(t, handler, recoveryEnrollmentChallengeURL, map[string]string{
		"request_id_hex":             hex.EncodeToString(requestID),
		"enrollment_certificate_hex": hex.EncodeToString(certificate),
		"recovery_public_key_hex":    hex.EncodeToString(publicKey),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.challengeCalls != 1 || service.challengeID[0] != 0x10 || string(service.challengeCert) != string(certificate) || service.challengeKey[0] != 0x77 {
		t.Fatalf("challenge service received incorrect arguments")
	}
	var got recoveryEnrollmentChallengeHTTPResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ChallengeIDHex != hex.EncodeToString(service.challenge.ID[:]) || got.ChallengeNonceHex != hex.EncodeToString(service.challenge.Nonce[:]) {
		t.Fatalf("unexpected challenge response: %+v", got)
	}
}

func TestRecoveryAPIHandlerActivatesBoundReplacement(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)
	requestID := make([]byte, 16)
	requestID[0] = 0x20
	certificate := []byte{0xa1, 0x01, 0x03}
	proof := []byte{0xa1, 0x01, 0x04}
	publicKey := make([]byte, 32)
	publicKey[0] = 0x88
	response := recoveryJSONRequest(t, handler, recoveryEnrollmentActivateURL, map[string]string{
		"request_id_hex":             hex.EncodeToString(requestID),
		"enrollment_certificate_hex": hex.EncodeToString(certificate),
		"proof_hex":                  hex.EncodeToString(proof),
		"recovery_public_key_hex":    hex.EncodeToString(publicKey),
	})
	if response.Code != http.StatusNoContent {
		t.Fatalf("activate status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.activateCalls != 1 || service.activateID[0] != 0x20 || string(service.activateCert) != string(certificate) || string(service.activateProof) != string(proof) || service.activateKey[0] != 0x88 {
		t.Fatalf("activation service received incorrect arguments")
	}
}

func TestRecoveryAPIHandlerRejectsUnknownIdentityFields(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)
	response := recoveryJSONRequest(t, handler, recoveryAbortURL, map[string]string{
		"recovery_abort_cbor_hex": hex.EncodeToString([]byte{0xa0}),
		"account_id":              "00112233445566778899aabbccddeeff",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", response.Code, response.Body.String())
	}
	if service.abortCalls != 0 {
		t.Fatalf("service called for request containing an unsupported identity field")
	}
}

func TestRecoveryAPIHandlerMapsLifecycleErrorsAndRejectsWrongMethod(t *testing.T) {
	service := &recoveryAPIServiceStub{beginErr: authorization.ErrRecoveryNotReady}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)

	wrongMethod := httptest.NewRequest(http.MethodGet, recoveryBeginURL, nil)
	wrongMethodResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethodResponse, wrongMethod)
	if wrongMethodResponse.Code != http.StatusMethodNotAllowed || wrongMethodResponse.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("wrong method response: status=%d allow=%q", wrongMethodResponse.Code, wrongMethodResponse.Header().Get("Allow"))
	}

	publicKey := make([]byte, 32)
	response := recoveryJSONRequest(t, handler, recoveryBeginURL, map[string]string{
		"recovery_request_cbor_hex":  "a0",
		"enrollment_certificate_hex": "a0",
		"recovery_public_key_hex":    hex.EncodeToString(publicKey),
	})
	if response.Code != http.StatusTooEarly {
		t.Fatalf("recovery-not-ready status = %d, want 425; body = %s", response.Code, response.Body.String())
	}
}

func TestRecoveryAPIHandlerRejectsUnknownRouteAndUnavailableService(t *testing.T) {
	unknown := httptest.NewRecorder()
	NewHandlerWithRecoveryAPI(http.NotFoundHandler(), &recoveryAPIServiceStub{}).ServeHTTP(
		unknown, httptest.NewRequest(http.MethodPost, "/v1/recovery/unknown", strings.NewReader("{}")),
	)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", unknown.Code)
	}

	unavailable := httptest.NewRecorder()
	NewHandlerWithRecoveryAPI(http.NotFoundHandler(), nil).ServeHTTP(
		unavailable, httptest.NewRequest(http.MethodPost, recoveryBeginURL, strings.NewReader("{}")),
	)
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil service status = %d, want 503", unavailable.Code)
	}
}

func TestRecoveryAPIHandlerHidesInternalServiceErrors(t *testing.T) {
	service := &recoveryAPIServiceStub{beginErr: errors.New("database password must not leak")}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)
	publicKey := make([]byte, 32)
	response := recoveryJSONRequest(t, handler, recoveryBeginURL, map[string]string{
		"recovery_request_cbor_hex":  "a0",
		"enrollment_certificate_hex": "a0",
		"recovery_public_key_hex":    hex.EncodeToString(publicKey),
	})
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "database password") {
		t.Fatalf("internal error leaked or mapped incorrectly: status=%d body=%s", response.Code, response.Body.String())
	}
}
