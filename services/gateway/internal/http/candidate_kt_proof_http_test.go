package gwhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

type candidateKTProofStub struct {
	current        kt.CurrentStateProofBundle
	consistency    kt.HistoryConsistencyProofBundle
	currentErr     error
	consistencyErr error
	key            [32]byte
	oldSize        uint64
}

func (s *candidateKTProofStub) CurrentStateProof(_ context.Context, key [32]byte) (kt.CurrentStateProofBundle, error) {
	s.key = key
	return s.current, s.currentErr
}
func (s *candidateKTProofStub) HistoryConsistencyProof(_ context.Context, old uint64) (kt.HistoryConsistencyProofBundle, error) {
	s.oldSize = old
	return s.consistency, s.consistencyErr
}

func TestCandidateKTCurrentProofReturnsCanonicalCBOR(t *testing.T) {
	var key, leafHash, root [32]byte
	var account [16]byte
	var device [16]byte
	account[15] = 1
	device[15] = 2
	key = kt.SMTKey(account, device)
	leafHash[0] = 3
	root[0] = 4
	siblings := make([][32]byte, 256)
	stub := &candidateKTProofStub{current: kt.CurrentStateProofBundle{
		LeafCBOR: []byte{0xa0}, SMTKey: key, LeafHash: leafHash, SMTRoot: root,
		SMTSiblings: siblings, HistorySequence: 1, HistoryRoot: root,
		HistoryIndex: 0, HistoryEntry: []byte{0xa0}, SignedTreeHead: []byte{0xa0}, TreeSize: 1,
	}}
	h := NewHandlerWithCandidateKTProofs(http.NotFoundHandler(), stub)
	path := "/v1/candidate/kt/proof/v1/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002"
	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != deviceCBORContentType {
		t.Fatalf("content type=%q", w.Header().Get("Content-Type"))
	}
	if !strings.EqualFold(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("cache-control=%q", w.Header().Get("Cache-Control"))
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatal("empty proof body")
	}
	if stub.key != key {
		t.Fatalf("requested SMT key=%x want=%x", stub.key, key)
	}
}

func TestCandidateKTCurrentProofRejectsMissingLeafBytes(t *testing.T) {
	stub := &candidateKTProofStub{current: kt.CurrentStateProofBundle{SignedTreeHead: []byte{1}, SMTSiblings: make([][32]byte, 256), HistoryEntry: []byte{1}}}
	h := NewHandlerWithCandidateKTProofs(http.NotFoundHandler(), stub)
	path := "/v1/candidate/kt/proof/v1/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCandidateKTConsistencyProofParsesOldSize(t *testing.T) {
	var root [32]byte
	root[0] = 1
	stub := &candidateKTProofStub{consistency: kt.HistoryConsistencyProofBundle{OldSize: 1, NewSize: 2, OldRoot: root, NewRoot: root, SignedTreeHead: []byte{1}}}
	h := NewHandlerWithCandidateKTProofs(http.NotFoundHandler(), stub)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, candidateKTConsistencyURL+"?old_size=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if stub.oldSize != 1 {
		t.Fatalf("old size=%d", stub.oldSize)
	}
}

func TestCandidateKTConsistencyProofRejectsInvalidQuery(t *testing.T) {
	for _, path := range []string{candidateKTConsistencyURL, candidateKTConsistencyURL + "?old_size=0", candidateKTConsistencyURL + "?old_size=-1", candidateKTConsistencyURL + "?old_size=1&x=2"} {
		h := NewHandlerWithCandidateKTProofs(http.NotFoundHandler(), &candidateKTProofStub{})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("path=%s status=%d", path, w.Code)
		}
	}
}
