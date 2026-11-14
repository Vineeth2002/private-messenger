package gwhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/signedprekeyv1"
)

type candidateSignedPrekeyStub struct {
	publishCalls int
	listCalls    int
	principal    deviceauth.Principal
	published    []byte
	accountID    [16]byte
	deviceID     [16]byte
	list         [][]byte
	err          error
}

func (s *candidateSignedPrekeyStub) Publish(_ context.Context, principal deviceauth.Principal, raw []byte) error {
	s.publishCalls++
	s.principal = principal
	s.published = append([]byte(nil), raw...)
	return s.err
}
func (s *candidateSignedPrekeyStub) List(_ context.Context, accountID, deviceID [16]byte) ([][]byte, error) {
	s.listCalls++
	s.accountID, s.deviceID = accountID, deviceID
	return s.list, s.err
}

func TestCandidateSignedPrekeyPublishRequiresDeviceAuthenticationAndExactBody(t *testing.T) {
	principal := fixedPrincipal()
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	service := &candidateSignedPrekeyStub{}
	h := NewHandlerWithCandidateSignedPrekeys(NewHandler(), service, auth)
	body := []byte{0xa0, 0x01, 0x02}
	req := httptest.NewRequest(http.MethodPost, candidateSignedPrekeyPublishURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	req.Header.Set("Content-Type", "application/cbor")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || service.publishCalls != 1 || auth.calls != 1 {
		t.Fatalf("status=%d publish=%d auth=%d body=%s", rr.Code, service.publishCalls, auth.calls, rr.Body.String())
	}
	if service.principal.AccountID != principal.AccountID || service.principal.DeviceID != principal.DeviceID || service.principal.Epoch != principal.Epoch || !bytes.Equal(service.published, body) || !bytes.Equal(auth.body, body) {
		t.Fatal("published candidate or authenticated principal did not match exact request")
	}
}

func TestCandidateSignedPrekeyPublishRejectsAuthAndContentTypeFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		authErr     error
		contentType string
		want        int
	}{
		{name: "missing auth", want: http.StatusUnauthorized},
		{name: "auth backend unavailable", authErr: errors.New("db unavailable"), contentType: "application/cbor", want: http.StatusServiceUnavailable},
		{name: "wrong content type", contentType: "application/json", want: http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &fakeDeviceRequestAuthenticator{err: tc.authErr}
			service := &candidateSignedPrekeyStub{}
			h := NewHandlerWithCandidateSignedPrekeys(NewHandler(), service, auth)
			req := httptest.NewRequest(http.MethodPost, candidateSignedPrekeyPublishURL, bytes.NewReader([]byte{0xa0}))
			if tc.name != "missing auth" {
				req.Header.Set("Authorization", "PM-Device-V1 fixture")
			}
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want || service.publishCalls != 0 {
				t.Fatalf("status=%d publish=%d body=%s", rr.Code, service.publishCalls, rr.Body.String())
			}
		})
	}
}

func TestCandidateSignedPrekeyListFailsClosedWhenKTKeyHasNoStoredRecord(t *testing.T) {
	service := &candidateSignedPrekeyStub{err: signedprekeyv1.ErrSPKNotPublished}
	h := NewHandlerWithCandidateSignedPrekeys(NewHandler(), service, nil)
	path := "/v1/candidate/devices/01000000-0000-0000-0000-000000000000/02000000-0000-0000-0000-000000000000/signed-prekeys/v1"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusPreconditionFailed, rr.Body.String())
	}
}

func TestCandidateSignedPrekeyListReturnsArrayOfExactObjects(t *testing.T) {
	var accountID, deviceID [16]byte
	accountID[0], deviceID[0] = 1, 2
	service := &candidateSignedPrekeyStub{list: [][]byte{{0xa0}, {0xa1, 0x01, 0x02}}}
	h := NewHandlerWithCandidateSignedPrekeys(NewHandler(), service, nil)
	path := "/v1/candidate/devices/01000000-0000-0000-0000-000000000000/02000000-0000-0000-0000-000000000000/signed-prekeys/v1"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/cbor" {
		t.Fatalf("status=%d content-type=%q body=%x", rr.Code, rr.Header().Get("Content-Type"), rr.Body.Bytes())
	}
	want := []byte{0x82, 0xa0, 0xa1, 0x01, 0x02}
	if !bytes.Equal(rr.Body.Bytes(), want) {
		t.Fatalf("body=%x want=%x", rr.Body.Bytes(), want)
	}
	if service.listCalls != 1 || service.accountID != accountID || service.deviceID != deviceID {
		t.Fatal("wrong account/device passed to list service")
	}
}
