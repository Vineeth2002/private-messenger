package gwhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
)

type authenticatedDeliveryStub struct {
	authEnqueueCalls int
	authFetchCalls   int
	authAckCalls     int
	gotPrincipal     messages.AuthenticatedDevice
	gotDeviceID      [16]byte
	gotEnvelopeID    [16]byte
	gotLimit         int
}

func (*authenticatedDeliveryStub) Enqueue(context.Context, []byte, time.Time) (messages.MessageEnvelopeV1, error) {
	return messages.MessageEnvelopeV1{}, nil
}
func (*authenticatedDeliveryStub) Fetch(context.Context, [16]byte, int) ([]messages.StoredEnvelope, error) {
	return nil, nil
}
func (*authenticatedDeliveryStub) Ack(context.Context, [16]byte, [16]byte) error { return nil }

func (f *authenticatedDeliveryStub) EnqueueAuthenticated(_ context.Context, _ []byte, _ time.Time, principal messages.AuthenticatedDevice) (messages.MessageEnvelopeV1, error) {
	f.authEnqueueCalls++
	f.gotPrincipal = principal
	return messages.MessageEnvelopeV1{}, nil
}
func (f *authenticatedDeliveryStub) FetchAuthenticated(_ context.Context, principal messages.AuthenticatedDevice, limit int) ([]messages.StoredEnvelope, error) {
	f.authFetchCalls++
	f.gotPrincipal = principal
	f.gotDeviceID = principal.DeviceID
	f.gotLimit = limit
	return nil, nil
}
func (f *authenticatedDeliveryStub) AckAuthenticated(_ context.Context, principal messages.AuthenticatedDevice, envelopeID [16]byte) error {
	f.authAckCalls++
	f.gotPrincipal = principal
	f.gotDeviceID = principal.DeviceID
	f.gotEnvelopeID = envelopeID
	return nil
}

func fixedPrincipal() deviceauth.Principal {
	var p deviceauth.Principal
	p.AccountID[0] = 0xA1
	p.DeviceID[0] = 0xB2
	p.Epoch = 7
	return p
}

func TestDeviceAuthenticatedFetchUsesPrincipalNotPathIdentity(t *testing.T) {
	principal := fixedPrincipal()
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	delivery := &authenticatedDeliveryStub{}
	h := NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth(nil, nil, delivery, auth)

	req := httptest.NewRequest(http.MethodGet, "/v1/demo/messages/"+messages.UUIDText(principal.DeviceID)+"?limit=17", nil)
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if delivery.authFetchCalls != 1 || delivery.gotPrincipal.AccountID != principal.AccountID || delivery.gotDeviceID != principal.DeviceID || delivery.gotPrincipal.Epoch != principal.Epoch || delivery.gotLimit != 17 {
		t.Fatalf("authenticated fetch received wrong identity: %+v limit=%d calls=%d", delivery.gotPrincipal, delivery.gotLimit, delivery.authFetchCalls)
	}
}

func TestDeviceAuthenticatedFetchRejectsDifferentPathDevice(t *testing.T) {
	principal := fixedPrincipal()
	other := principal.DeviceID
	other[0]++
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	delivery := &authenticatedDeliveryStub{}
	h := NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth(nil, nil, delivery, auth)

	req := httptest.NewRequest(http.MethodGet, "/v1/demo/messages/"+messages.UUIDText(other), nil)
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden || delivery.authFetchCalls != 0 {
		t.Fatalf("status=%d fetchCalls=%d body=%s", rr.Code, delivery.authFetchCalls, rr.Body.String())
	}
}

func TestDeviceAuthenticatedAckPassesBoundIdentity(t *testing.T) {
	principal := fixedPrincipal()
	var envelopeID [16]byte
	envelopeID[0] = 0xCC
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	delivery := &authenticatedDeliveryStub{}
	h := NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth(nil, nil, delivery, auth)

	path := "/v1/demo/messages/" + messages.UUIDText(principal.DeviceID) + "/" + messages.UUIDText(envelopeID) + "/ack"
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent || delivery.authAckCalls != 1 || delivery.gotPrincipal != (messages.AuthenticatedDevice{AccountID: principal.AccountID, DeviceID: principal.DeviceID, Epoch: principal.Epoch}) || delivery.gotEnvelopeID != envelopeID {
		t.Fatalf("status=%d ackCalls=%d principal=%+v envelope=%x body=%s", rr.Code, delivery.authAckCalls, delivery.gotPrincipal, delivery.gotEnvelopeID, rr.Body.String())
	}
}
