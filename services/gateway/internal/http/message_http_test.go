package gwhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
)

type fakeMessageDelivery struct {
	enqueueFn func(context.Context, []byte, time.Time) (messages.MessageEnvelopeV1, error)
	fetchFn   func(context.Context, [16]byte, int) ([]messages.StoredEnvelope, error)
	ackFn     func(context.Context, [16]byte, [16]byte) error
}

func (f *fakeMessageDelivery) Enqueue(ctx context.Context, raw []byte, expiresAt time.Time) (messages.MessageEnvelopeV1, error) {
	return f.enqueueFn(ctx, raw, expiresAt)
}

func (f *fakeMessageDelivery) Fetch(ctx context.Context, deviceID [16]byte, limit int) ([]messages.StoredEnvelope, error) {
	return f.fetchFn(ctx, deviceID, limit)
}

func (f *fakeMessageDelivery) Ack(ctx context.Context, deviceID, envelopeID [16]byte) error {
	return f.ackFn(ctx, deviceID, envelopeID)
}

func TestDemoMessageRoutesRequireDelivery(t *testing.T) {
	h := NewHandlerWithSTHAndDevicesAndMessages(nil, nil, nil, "demo-token")
	req := httptest.NewRequest(http.MethodPost, "/v1/demo/messages", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer demo-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestDemoMessageRoutesSupportBearerGuard(t *testing.T) {
	h := NewHandlerWithSTHAndDevicesAndMessages(nil, nil, &fakeMessageDelivery{}, "demo-token")
	req := httptest.NewRequest(http.MethodGet, "/v1/demo/messages/00112233-4455-6677-8899-aabbccddeeff", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestDemoMessageSendUsesDelivery(t *testing.T) {
	called := false
	fake := &fakeMessageDelivery{
		enqueueFn: func(_ context.Context, raw []byte, expiresAt time.Time) (messages.MessageEnvelopeV1, error) {
			called = true
			if string(raw) != "opaque-envelope" {
				t.Fatalf("raw=%q, want opaque-envelope", raw)
			}
			if !expiresAt.After(time.Now()) {
				t.Fatal("expiry is not in the future")
			}
			var id [16]byte
			id[0] = 9
			return messages.MessageEnvelopeV1{EnvelopeID: id, RecipientDeviceID: id}, nil
		},
		fetchFn: func(context.Context, [16]byte, int) ([]messages.StoredEnvelope, error) { return nil, nil },
		ackFn:   func(context.Context, [16]byte, [16]byte) error { return nil },
	}
	h := NewHandlerWithSTHAndDevicesAndMessages(nil, nil, fake, "demo-token")
	req := httptest.NewRequest(http.MethodPost, "/v1/demo/messages", strings.NewReader("opaque-envelope"))
	req.Header.Set("Authorization", "Bearer demo-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d, want %d; body=%s", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if !called {
		t.Fatal("delivery Enqueue was not called")
	}
}

func TestDemoMessageAckUsesDelivery(t *testing.T) {
	called := false
	fake := &fakeMessageDelivery{
		enqueueFn: func(context.Context, []byte, time.Time) (messages.MessageEnvelopeV1, error) {
			return messages.MessageEnvelopeV1{}, nil
		},
		fetchFn: func(context.Context, [16]byte, int) ([]messages.StoredEnvelope, error) { return nil, nil },
		ackFn: func(_ context.Context, deviceID, envelopeID [16]byte) error {
			called = true
			if deviceID[0] != 1 || envelopeID[0] != 2 {
				t.Fatalf("unexpected IDs")
			}
			return nil
		},
	}
	h := NewHandlerWithSTHAndDevicesAndMessages(nil, nil, fake, "demo-token")
	req := httptest.NewRequest(http.MethodPost, "/v1/demo/messages/01000000-0000-0000-0000-000000000000/02000000-0000-0000-0000-000000000000/ack", nil)
	req.Header.Set("Authorization", "Bearer demo-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNoContent)
	}
	if !called {
		t.Fatal("delivery Ack was not called")
	}
}

func TestDemoMessageFetchUsesDelivery(t *testing.T) {
	var gotDevice [16]byte
	gotDevice[0] = 1
	called := false
	fake := &fakeMessageDelivery{
		enqueueFn: func(context.Context, []byte, time.Time) (messages.MessageEnvelopeV1, error) {
			return messages.MessageEnvelopeV1{}, errors.New("not used")
		},
		fetchFn: func(_ context.Context, deviceID [16]byte, limit int) ([]messages.StoredEnvelope, error) {
			called = true
			gotDevice = deviceID
			if limit != 50 {
				t.Fatalf("limit=%d, want 50", limit)
			}
			return nil, nil
		},
		ackFn: func(context.Context, [16]byte, [16]byte) error { return nil },
	}
	h := NewHandlerWithSTHAndDevicesAndMessages(nil, nil, fake, "demo-token")
	req := httptest.NewRequest(http.MethodGet, "/v1/demo/messages/01000000-0000-0000-0000-000000000000", nil)
	req.Header.Set("Authorization", "Bearer demo-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !called || gotDevice[0] != 1 {
		t.Fatal("delivery Fetch was not called with expected device")
	}
}

func TestDemoMessageRoutesRejectEmptyBearerConfiguration(t *testing.T) {
	h := NewHandlerWithSTHAndDevicesAndMessages(
		nil,
		nil,
		&fakeMessageDelivery{},
		"",
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/v1/demo/messages/00112233-4455-6677-8899-aabbccddeeff",
		nil,
	)
	req.Header.Set("Authorization", "Bearer demo-token")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusUnauthorized)
	}
}
