package gwhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

type initialBootstrapServiceStub struct {
	challengeCalls, activateCalls int
	activateErr                   error
}

func (s *initialBootstrapServiceStub) IssueInitialAccountBootstrapChallenge(_ context.Context, cert []byte, key [32]byte) (authorization.EnrollmentChallenge, error) {
	s.challengeCalls++
	var c authorization.EnrollmentChallenge
	for i := range c.ID {
		c.ID[i] = byte(i + 1)
	}
	for i := range c.Nonce {
		c.Nonce[i] = byte(i + 2)
	}
	c.ExpiresAt = time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	return c, nil
}
func (s *initialBootstrapServiceStub) ActivateInitialAccountBootstrap(_ context.Context, cert, proof []byte, key [32]byte) error {
	s.activateCalls++
	return s.activateErr
}
func TestInitialAccountBootstrapChallengeRoute(t *testing.T) {
	svc := &initialBootstrapServiceStub{}
	h := NewHandlerWithInitialAccountBootstrap(NewHandler(), svc)
	body := `{"enrollment_certificate_hex":"01","recovery_public_key_hex":"` + strings.Repeat("11", 32) + `"}`
	req := httptest.NewRequest(http.MethodPost, initialBootstrapChallengeURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if svc.challengeCalls != 1 {
		t.Fatalf("challenge calls=%d", svc.challengeCalls)
	}
	var got candidateEnrollmentChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.ChallengeIDHex) != 32 || len(got.ChallengeNonceHex) != 64 || got.ExpiresAt == "" {
		t.Fatalf("bad response: %+v", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
}
func TestInitialAccountBootstrapActivateRoute(t *testing.T) {
	svc := &initialBootstrapServiceStub{}
	h := NewHandlerWithInitialAccountBootstrap(NewHandler(), svc)
	body := `{"enrollment_certificate_hex":"01","recovery_public_key_hex":"` + strings.Repeat("22", 32) + `","proof_hex":"02"}`
	req := httptest.NewRequest(http.MethodPost, initialBootstrapActivateURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if svc.activateCalls != 1 {
		t.Fatalf("activate calls=%d", svc.activateCalls)
	}
}
func TestInitialAccountBootstrapRejectsUnknownJSONFields(t *testing.T) {
	h := NewHandlerWithInitialAccountBootstrap(NewHandler(), &initialBootstrapServiceStub{})
	req := httptest.NewRequest(http.MethodPost, initialBootstrapChallengeURL, strings.NewReader(`{"unexpected":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}
