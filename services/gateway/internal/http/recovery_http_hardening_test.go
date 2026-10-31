package gwhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func recoveryHardeningRequest(handler http.Handler, path, body, contentType, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRecoveryAPIHandlerReturns413ForOversizedJSON(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)
	body := `{"recovery_abort_cbor_hex":"` + strings.Repeat("a", candidateEnrollmentBodyLimit) + `"}`
	response := recoveryHardeningRequest(handler, recoveryAbortURL, body, "application/json", "192.0.2.10:43120")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want 413; body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("oversized request missing Cache-Control: %q", response.Header().Get("Cache-Control"))
	}
	var got map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode oversized request error: %v", err)
	}
	if got["error"] != "ERR_BODY_TOO_LARGE" {
		t.Fatalf("oversized request error = %q, want ERR_BODY_TOO_LARGE", got["error"])
	}
	if service.abortCalls != 0 {
		t.Fatalf("service called %d times for oversized request", service.abortCalls)
	}
}

func TestRecoveryAPIHandlerRejectsMissingContentTypeAndTrailingJSON(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)

	missingContentType := recoveryHardeningRequest(
		handler, recoveryAbortURL,
		`{"recovery_abort_cbor_hex":"00"}`, "", "192.0.2.11:43120",
	)
	if missingContentType.Code != http.StatusBadRequest {
		t.Fatalf("missing content type status = %d, want 400", missingContentType.Code)
	}

	trailingJSON := recoveryHardeningRequest(
		handler, recoveryAbortURL,
		`{"recovery_abort_cbor_hex":"00"} {"unexpected":true}`,
		"application/json", "192.0.2.12:43120",
	)
	if trailingJSON.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON status = %d, want 400; body=%s", trailingJSON.Code, trailingJSON.Body.String())
	}
	if service.abortCalls != 0 {
		t.Fatalf("service called %d times for malformed JSON requests", service.abortCalls)
	}
}

func TestRecoveryAPIHandlerRateLimitsByRemotePeer(t *testing.T) {
	service := &recoveryAPIServiceStub{}
	handler := NewHandlerWithRecoveryAPI(http.NotFoundHandler(), service)

	for i := 0; i < recoveryAPIRequestLimit; i++ {
		response := recoveryHardeningRequest(
			handler, "/v1/recovery/unknown", `{}`,
			"application/json", "203.0.113.25:43120",
		)
		if response.Code != http.StatusNotFound {
			t.Fatalf("request %d status = %d, want 404 before rate limit", i+1, response.Code)
		}
	}

	limited := recoveryHardeningRequest(
		handler, "/v1/recovery/unknown", `{}`,
		"application/json", "203.0.113.25:43121",
	)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("request after rate limit status = %d, want 429", limited.Code)
	}
	if limited.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", limited.Header().Get("Retry-After"))
	}
	if limited.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("rate-limit response missing Cache-Control: %q", limited.Header().Get("Cache-Control"))
	}
}
