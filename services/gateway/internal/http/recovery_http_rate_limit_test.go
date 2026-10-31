package gwhttp

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type failingRecoveryAPIRateLimiter struct{}

func (failingRecoveryAPIRateLimiter) Allow(context.Context, string) (bool, time.Duration, error) {
	return false, 0, errors.New("database unavailable")
}

func TestRecoveryAPIHandlerFailsClosedWhenRateLimiterUnavailable(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPIAndLimiter(
		http.NotFoundHandler(), service, failingRecoveryAPIRateLimiter{},
	)
	response := recoveryHardeningRequest(
		handler, recoveryAbortURL, `{"recovery_abort_cbor_hex":"00"}`,
		"application/json", "192.0.2.40:43120",
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if service.abortCalls != 0 {
		t.Fatalf("service called %d times after rate-limiter failure", service.abortCalls)
	}
}
