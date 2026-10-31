package gwhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

type candidateEnrollmentServiceStub struct {
	challenge      authorization.EnrollmentChallenge
	issueErr       error
	activateErr    error
	issueCalls     int
	activateCalls  int
	issuedCert     []byte
	activatedCert  []byte
	activatedProof []byte
	recoveryKey    [32]byte
}

func (s *candidateEnrollmentServiceStub) IssueCandidateEnrollmentChallenge(_ context.Context, cert []byte, key [32]byte) (authorization.EnrollmentChallenge, error) {
	s.issueCalls++
	s.issuedCert = append([]byte(nil), cert...)
	s.recoveryKey = key
	return s.challenge, s.issueErr
}

func (s *candidateEnrollmentServiceStub) ActivateCandidateEnrollment(_ context.Context, cert, proof []byte, key [32]byte) error {
	s.activateCalls++
	s.activatedCert = append([]byte(nil), cert...)
	s.activatedProof = append([]byte(nil), proof...)
	s.recoveryKey = key
	return s.activateErr
}

func TestCandidateEnrollmentHandlerChallengeAndActivation(t *testing.T) {
	var challenge authorization.EnrollmentChallenge
	challenge.ID[0] = 1
	challenge.Nonce[0] = 2
	challenge.ExpiresAt = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	service := &candidateEnrollmentServiceStub{challenge: challenge}
	base := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	handler := NewHandlerWithCandidateEnrollment(base, service)

	cert := []byte{0xa7, 0x01}
	recoveryKey := bytes.Repeat([]byte{0x44}, 32)
	challengeBody, _ := json.Marshal(candidateEnrollmentChallengeRequest{
		EnrollmentCertificateHex: hex.EncodeToString(cert),
		RecoveryPublicKeyHex:     hex.EncodeToString(recoveryKey),
	})
	req := httptest.NewRequest(http.MethodPost, candidateEnrollmentChallengeURL, bytes.NewReader(challengeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("challenge response must not be cached")
	}
	if service.issueCalls != 1 || !bytes.Equal(service.issuedCert, cert) {
		t.Fatal("challenge request did not reach the enrollment service with exact certificate bytes")
	}
	var challengeResponse candidateEnrollmentChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeResponse); err != nil {
		t.Fatal(err)
	}
	if challengeResponse.ChallengeIDHex != hex.EncodeToString(challenge.ID[:]) ||
		challengeResponse.ChallengeNonceHex != hex.EncodeToString(challenge.Nonce[:]) {
		t.Fatal("challenge response fields differ from service result")
	}

	proof := []byte{0xa8, 0x01}
	activateBody, _ := json.Marshal(candidateEnrollmentActivateRequest{
		EnrollmentCertificateHex: hex.EncodeToString(cert),
		ProofHex:                 hex.EncodeToString(proof),
		RecoveryPublicKeyHex:     hex.EncodeToString(recoveryKey),
	})
	req = httptest.NewRequest(http.MethodPost, candidateEnrollmentActivateURL, bytes.NewReader(activateBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("activation status=%d body=%s", rec.Code, rec.Body.String())
	}
	if service.activateCalls != 1 || !bytes.Equal(service.activatedCert, cert) || !bytes.Equal(service.activatedProof, proof) {
		t.Fatal("activation request did not reach service with exact certificate/proof bytes")
	}

	req = httptest.NewRequest(http.MethodGet, candidateEnrollmentChallengeURL, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET challenge status=%d, want 405", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("non-candidate route should be delegated to base handler, got %d", rec.Code)
	}
}

func TestCandidateEnrollmentHandlerRejectsNonJSONMediaType(t *testing.T) {
	service := &candidateEnrollmentServiceStub{}
	handler := NewHandlerWithCandidateEnrollment(http.NotFoundHandler(), service)
	body := `{"enrollment_certificate_hex":"a701","recovery_public_key_hex":"` +
		hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)) + `"}`
	req := httptest.NewRequest(http.MethodPost, candidateEnrollmentChallengeURL, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/jsonp")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid media-type status=%d, want 400", rec.Code)
	}
	if service.issueCalls != 0 {
		t.Fatal("invalid media type must not call the enrollment service")
	}
}
func TestCandidateEnrollmentHandlerRejectsUnknownJSONFields(t *testing.T) {
	service := &candidateEnrollmentServiceStub{}
	handler := NewHandlerWithCandidateEnrollment(http.NotFoundHandler(), service)
	body := `{"enrollment_certificate_hex":"a701","recovery_public_key_hex":"` +
		hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)) + `","unexpected":true}`
	req := httptest.NewRequest(http.MethodPost, candidateEnrollmentChallengeURL, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field status=%d, want 400", rec.Code)
	}
	if service.issueCalls != 0 {
		t.Fatal("malformed request must not call the enrollment service")
	}
}
func TestRemoteKeyUsesPeerIPWithoutPortOrForwardedHeader(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{
			name:       "IPv4 source port is ignored",
			remoteAddr: "192.0.2.10:41001",
			forwarded:  "198.51.100.99",
			want:       "192.0.2.10",
		},
		{
			name:       "same IPv4 with a different source port has same key",
			remoteAddr: "192.0.2.10:52002",
			forwarded:  "203.0.113.77",
			want:       "192.0.2.10",
		},
		{
			name:       "IPv6 source port is ignored",
			remoteAddr: "[2001:db8::10]:41001",
			forwarded:  "2001:db8::99",
			want:       "2001:db8::10",
		},
		{
			name:       "malformed peer address fails closed",
			remoteAddr: "not-an-ip-address",
			forwarded:  "198.51.100.99",
			want:       "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, candidateEnrollmentChallengeURL, nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("X-Forwarded-For", test.forwarded)

			if got := remoteKey(request); got != test.want {
				t.Fatalf("remoteKey(%q) = %q, want %q", test.remoteAddr, got, test.want)
			}
		})
	}
}
func TestDemoMessageLimiterBoundsEntriesAndReclaimsExpiredKeys(t *testing.T) {
	limiter := newDemoMessageLimiter(2, time.Minute)
	for i := 0; i < demoMessageLimiterMaxEntries; i++ {
		if !limiter.Allow("client-" + strconv.Itoa(i)) {
			t.Fatalf("limiter rejected unique peer %d before reaching the configured cap", i)
		}
	}
	if got := len(limiter.entries); got != demoMessageLimiterMaxEntries {
		t.Fatalf("limiter entries=%d, want cap %d", got, demoMessageLimiterMaxEntries)
	}
	if limiter.Allow("overflow-client") {
		t.Fatal("limiter accepted a new peer while at the entry cap")
	}
	if got := len(limiter.entries); got > demoMessageLimiterMaxEntries {
		t.Fatalf("limiter entries=%d exceeds cap %d", got, demoMessageLimiterMaxEntries)
	}

	limiter.mu.Lock()
	expired := time.Now().Add(-2 * time.Minute)
	for key, entry := range limiter.entries {
		entry.started = expired
		limiter.entries[key] = entry
	}
	limiter.lastSweep = time.Time{}
	limiter.mu.Unlock()

	if !limiter.Allow("fresh-client") {
		t.Fatal("limiter should reclaim expired entries and admit a fresh peer")
	}
	if got := len(limiter.entries); got != 1 {
		t.Fatalf("limiter entries after expiry cleanup=%d, want 1", got)
	}
}
