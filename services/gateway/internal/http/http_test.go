package gwhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
