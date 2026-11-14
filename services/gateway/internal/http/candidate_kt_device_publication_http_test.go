package gwhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

type candidateKTSequenceStub struct {
	sequence uint64
	err      error
}

func (s candidateKTSequenceStub) NextHistorySequence(context.Context) (uint64, error) {
	return s.sequence, s.err
}

type candidateKTPublicationStub struct {
	calls     int
	principal kt.DeviceLeafPrincipal
	sequence  uint64
	leafRaw   []byte
	snapshot  kt.PublishedTransparencySnapshot
	err       error
}

func (s *candidateKTPublicationStub) PublishDeviceLeaf(_ context.Context, principal kt.DeviceLeafPrincipal, sequence uint64, leafRaw []byte) (kt.PublishedTransparencySnapshot, error) {
	s.calls++
	s.principal = principal
	s.sequence = sequence
	s.leafRaw = append([]byte(nil), leafRaw...)
	return s.snapshot, s.err
}

func TestCandidateKTSequenceReturnsCanonicalCBORAndNoStore(t *testing.T) {
	principal := fixedPrincipal()
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	service := &candidateKTPublicationStub{}
	handler := NewHandlerWithCandidateKTDevicePublication(NewHandler(), service, candidateKTSequenceStub{sequence: 19}, auth)
	req := httptest.NewRequest(http.MethodGet, candidateKTNextSequenceURL, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/cbor" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%x", rr.Code, rr.Header(), rr.Body.Bytes())
	}
	if string(rr.Body.Bytes()) != string([]byte{0x13}) {
		t.Fatalf("sequence body=%x want=13", rr.Body.Bytes())
	}
}

func TestCandidateKTDeviceLeafPublicationBindsPrincipalAndBuildsHistoryEntry(t *testing.T) {
	principal := fixedPrincipal()
	leafRaw := signedKTLeafForHandlerTest(t, principal)
	body := candidateKTRequestBody(t, 19, leafRaw)
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	service := &candidateKTPublicationStub{snapshot: kt.PublishedTransparencySnapshot{SignedBytes: []byte{0xa0}}}
	handler := NewHandlerWithCandidateKTDevicePublication(NewHandler(), service, candidateKTSequenceStub{sequence: 19}, auth)

	req := httptest.NewRequest(http.MethodPost, candidateKTDeviceLeafURL, bytesReader(body))
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	req.Header.Set("Content-Type", "application/cbor")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/cbor" || string(rr.Body.Bytes()) != string([]byte{0xa0}) {
		t.Fatalf("status=%d headers=%v body=%x", rr.Code, rr.Header(), rr.Body.Bytes())
	}
	if auth.calls != 1 || service.calls != 1 || string(auth.body) != string(body) {
		t.Fatalf("auth calls=%d service calls=%d", auth.calls, service.calls)
	}
	wantPrincipal := kt.DeviceLeafPrincipal{AccountID: principal.AccountID, DeviceID: principal.DeviceID, Epoch: principal.Epoch}
	if service.principal != wantPrincipal || service.sequence != 19 || !bytes.Equal(service.leafRaw, leafRaw) {
		t.Fatal("publication service received an unexpected authenticated principal, sequence, or leaf")
	}
}

func TestCandidateKTDeviceLeafPublicationRejectsPrincipalMismatch(t *testing.T) {
	principal := fixedPrincipal()
	other := principal
	other.DeviceID[0] ^= 0x01
	leafRaw := signedKTLeafForHandlerTest(t, other)
	body := candidateKTRequestBody(t, 19, leafRaw)
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	service := &candidateKTPublicationStub{}
	handler := NewHandlerWithCandidateKTDevicePublication(NewHandler(), service, candidateKTSequenceStub{sequence: 19}, auth)
	req := httptest.NewRequest(http.MethodPost, candidateKTDeviceLeafURL, bytesReader(body))
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	req.Header.Set("Content-Type", "application/cbor")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || service.calls != 0 {
		t.Fatalf("status=%d service calls=%d body=%s", rr.Code, service.calls, rr.Body.String())
	}
}

func TestCandidateKTDeviceLeafPublicationMapsSequenceConflict(t *testing.T) {
	principal := fixedPrincipal()
	leafRaw := signedKTLeafForHandlerTest(t, principal)
	body := candidateKTRequestBody(t, 19, leafRaw)
	auth := &fakeDeviceRequestAuthenticator{principal: principal}
	service := &candidateKTPublicationStub{err: kt.ErrTransparencyHistoryGap}
	handler := NewHandlerWithCandidateKTDevicePublication(NewHandler(), service, candidateKTSequenceStub{sequence: 19}, auth)
	req := httptest.NewRequest(http.MethodPost, candidateKTDeviceLeafURL, bytesReader(body))
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	req.Header.Set("Content-Type", "application/cbor")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCandidateKTDeviceLeafRequestRejectsUnknownOrMissingFields(t *testing.T) {
	cases := [][]byte{
		{0xa1, 0x01, 0x01},
		{0xa2, 0x01, 0x01, 0x03, 0x40},
		{0xa2, 0x01, 0x00, 0x02, 0x40},
	}
	for _, raw := range cases {
		if _, _, err := parseCandidateKTDeviceLeafRequest(raw); err == nil {
			t.Fatalf("invalid request accepted: %x", raw)
		}
	}
}

func TestCandidateKTDevicePublicationRequiresAuthentication(t *testing.T) {
	principal := fixedPrincipal()
	body := candidateKTRequestBody(t, 19, signedKTLeafForHandlerTest(t, principal))
	auth := &fakeDeviceRequestAuthenticator{err: errors.New("auth unavailable")}
	service := &candidateKTPublicationStub{}
	handler := NewHandlerWithCandidateKTDevicePublication(NewHandler(), service, candidateKTSequenceStub{sequence: 19}, auth)
	req := httptest.NewRequest(http.MethodPost, candidateKTDeviceLeafURL, bytesReader(body))
	req.Header.Set("Authorization", "PM-Device-V1 fixture")
	req.Header.Set("Content-Type", "application/cbor")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || service.calls != 0 {
		t.Fatalf("status=%d service calls=%d", rr.Code, service.calls)
	}
}

func signedKTLeafForHandlerTest(t *testing.T, principal deviceauth.Principal) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := kt.TransparencyLeafV1{AccountID: principal.AccountID, Epoch: principal.Epoch, DeviceID: principal.DeviceID}
	copy(leaf.DSKPub[:], public)
	for i := range leaf.DDHKPub {
		leaf.DDHKPub[i] = byte(i + 1)
	}
	for i := range leaf.CertDH {
		leaf.CertDH[i] = byte(i + 3)
	}
	for i := range leaf.SPKPub {
		leaf.SPKPub[i] = byte(i + 5)
	}
	for i := range leaf.PushPK {
		leaf.PushPK[i] = byte(i + 7)
	}
	core := cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		{Key: cborInt(1), Val: cborBytes(leaf.AccountID[:])},
		{Key: cborInt(2), Val: cborUint(leaf.Epoch)},
		{Key: cborInt(3), Val: cborBytes(leaf.DeviceID[:])},
		{Key: cborInt(4), Val: cborBytes(leaf.DSKPub[:])},
		{Key: cborInt(5), Val: cborBytes(leaf.DDHKPub[:])},
		{Key: cborInt(6), Val: cborBytes(leaf.CertDH[:])},
		{Key: cborInt(7), Val: cborBytes(leaf.SPKPub[:])},
		{Key: cborInt(8), Val: cborBytes(leaf.PushPK[:])},
	}}
	coreRaw, err := cbor.EncodeCanonical(core)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("PM-V1-KT-LEAF-SIGN-v1"), coreRaw...)
	signature := ed25519.Sign(private, message)
	full := core
	full.Map = append(full.Map, cbor.Pair{Key: cborInt(9), Val: cborBytes(signature)})
	raw, err := cbor.EncodeCanonical(full)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func candidateKTRequestBody(t *testing.T, sequence uint64, leafRaw []byte) []byte {
	t.Helper()
	value := cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		{Key: cborInt(1), Val: cborUint(sequence)},
		{Key: cborInt(2), Val: cborBytes(leafRaw)},
	}}
	raw, err := cbor.EncodeCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func cborInt(value uint64) cbor.Value {
	return cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}}
}
func cborUint(value uint64) cbor.Value  { return cborInt(value) }
func cborBytes(value []byte) cbor.Value { return cbor.Value{Kind: cbor.KindBytes, Bytes: value} }

// bytesReader keeps the tests independent of JSON/text conversions.
func bytesReader(raw []byte) *bytes.Reader { return bytes.NewReader(raw) }
