package gwhttp

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

const (
	candidateKTProofPathPrefix = "/v1/candidate/kt/proof/v1/"
	candidateKTConsistencyURL  = "/v1/candidate/kt/consistency/v1"
)

// CandidateKTProofReader returns self-checked current-state and history proofs.
// The response does not include witness statements because this gateway build
// has no persisted witness-statement source. Clients MUST treat the absence of
// quorum evidence as degraded and must not elevate it to production trust.
type CandidateKTProofReader interface {
	CurrentStateProof(context.Context, [32]byte) (kt.CurrentStateProofBundle, error)
	HistoryConsistencyProof(context.Context, uint64) (kt.HistoryConsistencyProofBundle, error)
}

// NewHandlerWithCandidateKTProofs installs read-only proof endpoints behind an
// explicit deployment flag. This handler does not claim a witness quorum.
func NewHandlerWithCandidateKTProofs(base http.Handler, proofs CandidateKTProofReader) http.Handler {
	limiter := newDemoMessageLimiter(30, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != candidateKTConsistencyURL && !strings.HasPrefix(r.URL.Path, candidateKTProofPathPrefix) {
			base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeDeviceError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		if proofs == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PROOF_UNAVAILABLE")
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return
		}
		if r.URL.Path == candidateKTConsistencyURL {
			serveCandidateKTConsistencyProof(w, r, proofs)
			return
		}
		serveCandidateKTCurrentStateProof(w, r, proofs)
	})
}

func serveCandidateKTCurrentStateProof(w http.ResponseWriter, r *http.Request, proofs CandidateKTProofReader) {
	parts := splitPath(r.URL.Path)
	if len(parts) != 7 || parts[0] != "v1" || parts[1] != "candidate" || parts[2] != "kt" || parts[3] != "proof" || parts[4] != "v1" {
		writeDeviceError(w, http.StatusNotFound, "ERR_NOT_FOUND")
		return
	}
	accountID, ok := parseUUIDPath(parts[5])
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_ACCOUNT_ID")
		return
	}
	deviceID, ok := parseUUIDPath(parts[6])
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
		return
	}
	if r.URL.RawQuery != "" {
		writeDeviceError(w, http.StatusBadRequest, "ERR_UNEXPECTED_QUERY")
		return
	}
	key := kt.SMTKey(accountID, deviceID)
	bundle, err := proofs.CurrentStateProof(r.Context(), key)
	if err != nil {
		writeCandidateKTProofError(w, err)
		return
	}
	if len(bundle.LeafCBOR) == 0 || len(bundle.SignedTreeHead) == 0 || len(bundle.SMTSiblings) != 256 || len(bundle.HistoryEntry) == 0 {
		writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PROOF_INCOMPLETE")
		return
	}
	raw, err := encodeCandidateKTCurrentProof(bundle)
	if err != nil {
		writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
		return
	}
	writeCBOR(w, raw)
}

func serveCandidateKTConsistencyProof(w http.ResponseWriter, r *http.Request, proofs CandidateKTProofReader) {
	values := r.URL.Query()
	if len(values) != 1 || len(values["old_size"]) != 1 {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_HISTORY_SIZE")
		return
	}
	oldSize, err := strconv.ParseUint(values.Get("old_size"), 10, 64)
	if err != nil || oldSize == 0 || oldSize > math.MaxInt64 {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_HISTORY_SIZE")
		return
	}
	bundle, err := proofs.HistoryConsistencyProof(r.Context(), oldSize)
	if err != nil {
		writeCandidateKTProofError(w, err)
		return
	}
	if len(bundle.SignedTreeHead) == 0 || bundle.OldSize != oldSize || bundle.NewSize <= bundle.OldSize {
		writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PROOF_INCOMPLETE")
		return
	}
	raw, err := encodeCandidateKTConsistencyProof(bundle)
	if err != nil {
		writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
		return
	}
	writeCBOR(w, raw)
}

func writeCandidateKTProofError(w http.ResponseWriter, err error) {
	if errors.Is(err, kt.ErrTransparencyStateNotFound) {
		writeDeviceError(w, http.StatusNotFound, "ERR_KT_LEAF_NOT_FOUND")
		return
	}
	writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PROOF_UNAVAILABLE")
}

// Current-state proof response: canonical PM-CBOR map with integer keys.
// 1 version, 2 leaf CBOR, 3 SMT key, 4 leaf hash, 5 SMT root,
// 6 SMT siblings root-to-leaf, 7 history sequence, 8 history root,
// 9 history index, 10 history entry, 11 history siblings, 12 signed STH,
// 13 tree size, 14 witness statements (currently an empty array).
func encodeCandidateKTCurrentProof(p kt.CurrentStateProofBundle) ([]byte, error) {
	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		ktIntPair(1, kt.ProtocolVersion),
		ktBytesPair(2, p.LeafCBOR),
		ktBytesPair(3, p.SMTKey[:]),
		ktBytesPair(4, p.LeafHash[:]),
		ktBytesPair(5, p.SMTRoot[:]),
		ktArrayPair(6, hashArray(p.SMTSiblings)),
		ktIntPair(7, p.HistorySequence),
		ktBytesPair(8, p.HistoryRoot[:]),
		ktIntPair(9, uint64(p.HistoryIndex)),
		ktBytesPair(10, p.HistoryEntry),
		ktArrayPair(11, hashArray(p.HistoryProof)),
		ktBytesPair(12, p.SignedTreeHead),
		ktIntPair(13, p.TreeSize),
		{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: 14}}, Val: cbor.Value{Kind: cbor.KindArray, Array: []cbor.Value{}}},
	}})
}

// Consistency response: canonical PM-CBOR map with integer keys.
// 1 version, 2 old size, 3 new size, 4 old root, 5 new root,
// 6 RFC-6962 proof nodes, 7 signed STH.
func encodeCandidateKTConsistencyProof(p kt.HistoryConsistencyProofBundle) ([]byte, error) {
	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		ktIntPair(1, kt.ProtocolVersion),
		ktIntPair(2, p.OldSize),
		ktIntPair(3, p.NewSize),
		ktBytesPair(4, p.OldRoot[:]),
		ktBytesPair(5, p.NewRoot[:]),
		ktArrayPair(6, hashArray(p.Proof)),
		ktBytesPair(7, p.SignedTreeHead),
	}})
}

func hashArray(nodes [][32]byte) []cbor.Value {
	out := make([]cbor.Value, len(nodes))
	for i := range nodes {
		out[i] = cbor.Value{Kind: cbor.KindBytes, Bytes: nodes[i][:]}
	}
	return out
}

func ktIntPair(key, value uint64) cbor.Pair {
	return cbor.Pair{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}}, Val: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}}}
}

func ktBytesPair(key uint64, value []byte) cbor.Pair {
	return cbor.Pair{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}}, Val: cbor.Value{Kind: cbor.KindBytes, Bytes: append([]byte(nil), value...)}}
}

func ktArrayPair(key uint64, value []cbor.Value) cbor.Pair {
	return cbor.Pair{Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}}, Val: cbor.Value{Kind: cbor.KindArray, Array: value}}
}
