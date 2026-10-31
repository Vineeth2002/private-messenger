package gwhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
)

type fakeDeviceRequestAuthenticator struct {
	principal deviceauth.Principal
	err       error
	header    string
	method    string
	target    string
	body      []byte
	calls     int
}

func (f *fakeDeviceRequestAuthenticator) Authenticate(_ context.Context, header, method, target string, body []byte, _ time.Time) (deviceauth.Principal, error) {
	f.calls++
	f.header = header
	f.method = method
	f.target = target
	f.body = append([]byte(nil), body...)
	return f.principal, f.err
}

func TestDeviceRequestAuthMiddlewareUsesExactRequestBytes(t *testing.T) {
	fake := &fakeDeviceRequestAuthenticator{}
	fake.principal.AccountID[0] = 1
	fake.principal.DeviceID[0] = 2
	fake.principal.Epoch = 4
	seenBody := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read restored request body: %v", err)
		}
		seenBody = string(body)
		if principal, ok := devicePrincipalFromContext(r.Context()); !ok || principal.DeviceID != fake.principal.DeviceID {
			t.Fatal("authenticated principal was not attached to request context")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/demo/messages?mode=fast", strings.NewReader("exact-body-bytes"))
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	rr := httptest.NewRecorder()
	deviceRequestAuthMiddleware(fake, next).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fake.calls != 1 || fake.header != "PM-Device-V1 fixture" || fake.method != http.MethodPost || fake.target != "/v1/demo/messages?mode=fast" || string(fake.body) != "exact-body-bytes" {
		t.Fatalf("authenticator received unexpected request: calls=%d method=%q target=%q body=%q", fake.calls, fake.method, fake.target, fake.body)
	}
	if seenBody != "exact-body-bytes" {
		t.Fatalf("downstream body=%q; want exact body", seenBody)
	}
}

func TestDeviceRequestAuthMiddlewareRejectsDuplicateAuthorizationHeaders(t *testing.T) {
	fake := &fakeDeviceRequestAuthenticator{}
	nextCalled := false
	req := httptest.NewRequest(http.MethodGet, "/v1/demo/messages/00112233-4455-6677-8899-aabbccddeeff", nil)
	req.Header.Add("Authorization", "PM-Device-V1 one")
	req.Header.Add("Authorization", "PM-Device-V1 two")
	rr := httptest.NewRecorder()
	deviceRequestAuthMiddleware(fake, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || fake.calls != 0 || nextCalled {
		t.Fatalf("status=%d auth calls=%d nextCalled=%v", rr.Code, fake.calls, nextCalled)
	}
}

func TestDeviceRequestAuthMiddlewareFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{name: "replay", err: deviceauth.ErrRequestReplay, want: http.StatusUnauthorized},
		{name: "inactive account", err: deviceauth.ErrAccountInactive, want: http.StatusForbidden},
		{name: "inactive device", err: deviceauth.ErrDeviceInactive, want: http.StatusForbidden},
		{name: "persisted key mismatch", err: deviceauth.ErrDeviceStateInvalid, want: http.StatusServiceUnavailable},
		{name: "database failure", err: errors.New("database unavailable"), want: http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeDeviceRequestAuthenticator{err: tc.err}
			nextCalled := false
			req := httptest.NewRequest(http.MethodGet, "/v1/demo/messages/00112233-4455-6677-8899-aabbccddeeff", nil)
			req.Header.Set("Authorization", "PM-Device-V1 fixture")
			rr := httptest.NewRecorder()
			deviceRequestAuthMiddleware(fake, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)
			if rr.Code != tc.want || nextCalled {
				t.Fatalf("status=%d want=%d nextCalled=%v body=%s", rr.Code, tc.want, nextCalled, rr.Body.String())
			}
		})
	}
}
