package gwhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

type fakeSTHSource struct {
	raw    []byte
	err    error
	called bool
}

func (f *fakeSTHSource) Latest(context.Context) (kt.SignedTreeHeadV1, []byte, time.Time, error) {
	f.called = true
	return kt.SignedTreeHeadV1{TreeSize: 32}, append([]byte(nil), f.raw...), time.Unix(1700101234, 0).UTC(), f.err
}

func do(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	NewHandler().ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	if rr := do(t, http.MethodGet, "/healthz", nil); rr.Code != 200 {
		t.Fatalf("code %d", rr.Code)
	}
	if rr := do(t, http.MethodPost, "/healthz", nil); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestValidateCanonicalAccepted(t *testing.T) {
	if rr := do(t, http.MethodPost, "/v1/cbor/validate", []byte{0x0a}); rr.Code != http.StatusNoContent {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestValidateRejectsWithCategory(t *testing.T) {
	cases := map[string][]byte{
		"ERR_NON_CANONICAL_INTEGER": {0x18, 0x0a},
		"ERR_TRAILING_BYTES":        {0x00, 0x00},
		"ERR_FLOAT_PROHIBITED":      {0xfa, 0x3f, 0x80, 0, 0},
	}
	for want, in := range cases {
		rr := do(t, http.MethodPost, "/v1/cbor/validate", in)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("%s: code %d body %q", want, rr.Code, rr.Body.String())
		}
	}
}

func TestSTHRetrievalReturnsExactCBORBytes(t *testing.T) {
	want := []byte{0xa7, 0x01, 0x01, 0x02, 0x01, 0x03, 0x41, 0x00}
	source := &fakeSTHSource{raw: want}
	h := NewHandlerWithSTH(source)
	req := httptest.NewRequest(http.MethodGet, "/v1/kt/sth", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/cbor" {
		t.Fatalf("content type = %q", rr.Header().Get("Content-Type"))
	}
	if !bytes.Equal(rr.Body.Bytes(), want) {
		t.Fatalf("body changed: got %x want %x", rr.Body.Bytes(), want)
	}
	if !source.called {
		t.Fatal("STH source was not called")
	}
}

func TestSTHRetrievalUnavailableWithoutPersistence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/kt/sth", nil)
	rr := httptest.NewRecorder()
	NewHandlerWithSTH(nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestSTHRetrievalNotFound(t *testing.T) {
	source := &fakeSTHSource{err: kt.ErrSTHNotFound}
	req := httptest.NewRequest(http.MethodGet, "/v1/kt/sth", nil)
	rr := httptest.NewRecorder()
	NewHandlerWithSTH(source).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestSTHRetrievalMapsStoreFailure(t *testing.T) {
	source := &fakeSTHSource{err: errors.New("store failure")}
	req := httptest.NewRequest(http.MethodGet, "/v1/kt/sth", nil)
	rr := httptest.NewRecorder()
	NewHandlerWithSTH(source).ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestSTHRetrievalMethodGuard(t *testing.T) {
	source := &fakeSTHSource{raw: []byte{0xa0}}
	req := httptest.NewRequest(http.MethodPost, "/v1/kt/sth", nil)
	rr := httptest.NewRecorder()
	NewHandlerWithSTH(source).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code %d", rr.Code)
	}
}
