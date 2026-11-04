package gwhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

type initialBootstrapSecurityServiceStub struct {
	challengeCalls int
	activateCalls  int
	challengeErr   error
	activateErr    error
}

func (s *initialBootstrapSecurityServiceStub) IssueInitialAccountBootstrapChallenge(
	_ context.Context,
	_ []byte,
	_ [32]byte,
) (authorization.EnrollmentChallenge, error) {
	s.challengeCalls++
	return authorization.EnrollmentChallenge{}, s.challengeErr
}

func (s *initialBootstrapSecurityServiceStub) ActivateInitialAccountBootstrap(
	_ context.Context,
	_, _ []byte,
	_ [32]byte,
) error {
	s.activateCalls++
	return s.activateErr
}

func initialBootstrapSecurityChallengeBody() string {
	return `{"enrollment_certificate_hex":"01","recovery_public_key_hex":"` +
		strings.Repeat("11", 32) + `"}`
}

func initialBootstrapSecurityActivationBody() string {
	return `{"enrollment_certificate_hex":"01","proof_hex":"02","recovery_public_key_hex":"` +
		strings.Repeat("22", 32) + `"}`
}

func initialBootstrapSecurityRequest(
	method, path, body, contentType string,
) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.50:12345"

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req
}

func assertInitialBootstrapSecurityError(
	t *testing.T,
	rec *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()

	if rec.Code != status {
		t.Fatalf("status=%d, want=%d, body=%s", rec.Code, status, rec.Body.String())
	}

	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected Content-Type: %q", rec.Header().Get("Content-Type"))
	}

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("error response is missing Cache-Control: no-store")
	}

	var payload struct {
		Error string `json:"error"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	if payload.Error != code {
		t.Fatalf("error code=%q, want=%q", payload.Error, code)
	}
}

func TestInitialAccountBootstrapRejectsMalformedRequests(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
	}{
		{
			name:        "malformed JSON",
			body:        `{"enrollment_certificate_hex":`,
			contentType: "application/json",
		},
		{
			name:        "empty body",
			body:        "",
			contentType: "application/json",
		},
		{
			name:        "missing recovery key",
			body:        `{"enrollment_certificate_hex":"01"}`,
			contentType: "application/json",
		},
		{
			name:        "wrong content type",
			body:        initialBootstrapSecurityChallengeBody(),
			contentType: "text/plain",
		},
		{
			name: "invalid certificate hex",
			body: `{"enrollment_certificate_hex":"zz","recovery_public_key_hex":"` +
				strings.Repeat("11", 32) + `"}`,
			contentType: "application/json",
		},
		{
			name: "incorrect recovery key length",
			body: `{"enrollment_certificate_hex":"01","recovery_public_key_hex":"` +
				strings.Repeat("11", 31) + `"}`,
			contentType: "application/json",
		},
		{
			name:        "multiple JSON values",
			body:        initialBootstrapSecurityChallengeBody() + ` {}`,
			contentType: "application/json",
		},
		{
			name:        "oversized body",
			body:        strings.Repeat(" ", candidateEnrollmentBodyLimit+1),
			contentType: "application/json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &initialBootstrapSecurityServiceStub{}
			handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), service)

			req := initialBootstrapSecurityRequest(
				http.MethodPost,
				initialBootstrapChallengeURL,
				tc.body,
				tc.contentType,
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assertInitialBootstrapSecurityError(
				t, rec, http.StatusBadRequest, "ERR_INVALID_REQUEST",
			)

			if service.challengeCalls != 0 || service.activateCalls != 0 {
				t.Fatalf(
					"malformed request reached service: challenge=%d activation=%d",
					service.challengeCalls,
					service.activateCalls,
				)
			}
		})
	}
}

func TestInitialAccountBootstrapRejectsUnsupportedMethods(t *testing.T) {
	for _, method := range []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
	} {
		t.Run(method, func(t *testing.T) {
			service := &initialBootstrapSecurityServiceStub{}
			handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), service)

			req := initialBootstrapSecurityRequest(
				method,
				initialBootstrapChallengeURL,
				"",
				"",
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assertInitialBootstrapSecurityError(
				t, rec, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED",
			)

			if rec.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow=%q, want POST", rec.Header().Get("Allow"))
			}

			if service.challengeCalls != 0 || service.activateCalls != 0 {
				t.Fatal("unsupported method reached bootstrap service")
			}
		})
	}
}

func TestInitialAccountBootstrapRejectsUnknownRoute(t *testing.T) {
	service := &initialBootstrapSecurityServiceStub{}
	handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), service)

	req := initialBootstrapSecurityRequest(
		http.MethodPost,
		initialBootstrapPrefix+"unknown",
		initialBootstrapSecurityChallengeBody(),
		"application/json",
	)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertInitialBootstrapSecurityError(
		t, rec, http.StatusNotFound, "ERR_NOT_FOUND",
	)

	if service.challengeCalls != 0 || service.activateCalls != 0 {
		t.Fatal("unknown route reached bootstrap service")
	}
}

func TestInitialAccountBootstrapUnavailableService(t *testing.T) {
	handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), nil)

	req := initialBootstrapSecurityRequest(
		http.MethodPost,
		initialBootstrapChallengeURL,
		initialBootstrapSecurityChallengeBody(),
		"application/json",
	)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertInitialBootstrapSecurityError(
		t, rec, http.StatusServiceUnavailable, "ERR_BOOTSTRAP_UNAVAILABLE",
	)
}

func TestInitialAccountBootstrapMapsServiceErrors(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		body   string
		err    error
		status int
		code   string
	}{
		{
			name:   "challenge expired",
			path:   initialBootstrapChallengeURL,
			body:   initialBootstrapSecurityChallengeBody(),
			err:    authorization.ErrEnrollmentChallengeExpired,
			status: http.StatusGone,
			code:   "ERR_CHALLENGE_EXPIRED",
		},
		{
			name:   "account exists",
			path:   initialBootstrapActivateURL,
			body:   initialBootstrapSecurityActivationBody(),
			err:    authorization.ErrAccountExists,
			status: http.StatusConflict,
			code:   "ERR_ACCOUNT_OR_DEVICE_EXISTS",
		},
		{
			name:   "device exists",
			path:   initialBootstrapActivateURL,
			body:   initialBootstrapSecurityActivationBody(),
			err:    authorization.ErrDeviceExists,
			status: http.StatusConflict,
			code:   "ERR_ACCOUNT_OR_DEVICE_EXISTS",
		},
		{
			name:   "challenge already consumed",
			path:   initialBootstrapActivateURL,
			body:   initialBootstrapSecurityActivationBody(),
			err:    authorization.ErrEnrollmentChallengeConsumed,
			status: http.StatusConflict,
			code:   "ERR_ACCOUNT_OR_DEVICE_EXISTS",
		},
		{
			name:   "authorization conflict",
			path:   initialBootstrapActivateURL,
			body:   initialBootstrapSecurityActivationBody(),
			err:    authorization.ErrAuthorizationConflict,
			status: http.StatusConflict,
			code:   "ERR_ACCOUNT_OR_DEVICE_EXISTS",
		},
		{
			name:   "invalid authorization",
			path:   initialBootstrapChallengeURL,
			body:   initialBootstrapSecurityChallengeBody(),
			err:    authorization.ErrInvalidAuthorization,
			status: http.StatusBadRequest,
			code:   "ERR_BOOTSTRAP_REJECTED",
		},
		{
			name:   "invalid epoch",
			path:   initialBootstrapChallengeURL,
			body:   initialBootstrapSecurityChallengeBody(),
			err:    authorization.ErrInvalidEpoch,
			status: http.StatusBadRequest,
			code:   "ERR_BOOTSTRAP_REJECTED",
		},
		{
			name:   "challenge not found",
			path:   initialBootstrapActivateURL,
			body:   initialBootstrapSecurityActivationBody(),
			err:    authorization.ErrEnrollmentChallengeNotFound,
			status: http.StatusBadRequest,
			code:   "ERR_BOOTSTRAP_REJECTED",
		},
		{
			name:   "internal service error",
			path:   initialBootstrapActivateURL,
			body:   initialBootstrapSecurityActivationBody(),
			err:    errors.New("internal database failure"),
			status: http.StatusInternalServerError,
			code:   "ERR_BOOTSTRAP_INTERNAL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &initialBootstrapSecurityServiceStub{
				challengeErr: tc.err,
				activateErr:  tc.err,
			}

			handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), service)

			req := initialBootstrapSecurityRequest(
				http.MethodPost,
				tc.path,
				tc.body,
				"application/json",
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assertInitialBootstrapSecurityError(t, rec, tc.status, tc.code)

			if tc.path == initialBootstrapChallengeURL {
				if service.challengeCalls != 1 || service.activateCalls != 0 {
					t.Fatalf(
						"unexpected service calls: challenge=%d activation=%d",
						service.challengeCalls,
						service.activateCalls,
					)
				}
			} else if service.activateCalls != 1 || service.challengeCalls != 0 {
				t.Fatalf(
					"unexpected service calls: challenge=%d activation=%d",
					service.challengeCalls,
					service.activateCalls,
				)
			}
		})
	}
}

func TestInitialAccountBootstrapRateLimitsByRemoteIP(t *testing.T) {
	service := &initialBootstrapSecurityServiceStub{}
	handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), service)

	for i := 0; i < 10; i++ {
		req := initialBootstrapSecurityRequest(
			http.MethodPost,
			initialBootstrapChallengeURL,
			initialBootstrapSecurityChallengeBody(),
			"application/json",
		)

		// A changing forwarding header must not bypass the server-observed IP key.
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status=%d, want=200, body=%s", i+1, rec.Code, rec.Body.String())
		}
	}

	req := initialBootstrapSecurityRequest(
		http.MethodPost,
		initialBootstrapChallengeURL,
		initialBootstrapSecurityChallengeBody(),
		"application/json",
	)
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertInitialBootstrapSecurityError(
		t, rec, http.StatusTooManyRequests, "ERR_RATE_LIMITED",
	)

	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After=%q, want 60", rec.Header().Get("Retry-After"))
	}

	if service.challengeCalls != 10 {
		t.Fatalf("challenge service calls=%d, want 10", service.challengeCalls)
	}
}

func TestInitialAccountBootstrapRejectsMalformedActivationRequests(t *testing.T) {
	recoveryKey := strings.Repeat("22", 32)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed JSON",
			body: `{"enrollment_certificate_hex":`,
		},
		{
			name: "missing proof",
			body: `{"enrollment_certificate_hex":"01","recovery_public_key_hex":"` + recoveryKey + `"}`,
		},
		{
			name: "empty proof",
			body: `{"enrollment_certificate_hex":"01","proof_hex":"","recovery_public_key_hex":"` + recoveryKey + `"}`,
		},
		{
			name: "odd-length proof hex",
			body: `{"enrollment_certificate_hex":"01","proof_hex":"0","recovery_public_key_hex":"` + recoveryKey + `"}`,
		},
		{
			name: "non-hex proof",
			body: `{"enrollment_certificate_hex":"01","proof_hex":"zz","recovery_public_key_hex":"` + recoveryKey + `"}`,
		},
		{
			name: "proof exceeds 2048 bytes",
			body: `{"enrollment_certificate_hex":"01","proof_hex":"` + strings.Repeat("ab", 2049) + `","recovery_public_key_hex":"` + recoveryKey + `"}`,
		},
		{
			name: "invalid certificate hex",
			body: `{"enrollment_certificate_hex":"zz","proof_hex":"02","recovery_public_key_hex":"` + recoveryKey + `"}`,
		},
		{
			name: "incorrect recovery key length",
			body: `{"enrollment_certificate_hex":"01","proof_hex":"02","recovery_public_key_hex":"` + strings.Repeat("22", 31) + `"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &initialBootstrapSecurityServiceStub{}
			handler := NewHandlerWithInitialAccountBootstrap(NewHandler(), service)

			req := initialBootstrapSecurityRequest(
				http.MethodPost,
				initialBootstrapActivateURL,
				tc.body,
				"application/json",
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assertInitialBootstrapSecurityError(
				t, rec, http.StatusBadRequest, "ERR_INVALID_REQUEST",
			)

			if service.challengeCalls != 0 || service.activateCalls != 0 {
				t.Fatalf(
					"malformed activation request reached service: challenge=%d activation=%d",
					service.challengeCalls,
					service.activateCalls,
				)
			}
		})
	}
}
