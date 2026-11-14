package gwhttp

import (
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

const (
	candidateKTNextSequenceURL = "/v1/candidate/kt/next-sequence/v1"
	candidateKTDeviceLeafURL   = "/v1/candidate/kt/device-leaf/v1"
	candidateKTMaxBodyBytes    = 8 * 1024
	candidateKTMaxLeafBytes    = 1024
)

// CandidateKTDevicePublicationService is the device-authorization-bound KT
// publication boundary. Implementations must validate the leaf against active
// persisted device and authorization state before committing it.
type CandidateKTDevicePublicationService interface {
	PublishDeviceLeaf(context.Context, kt.DeviceLeafPrincipal, uint64, []byte) (kt.PublishedTransparencySnapshot, error)
}

type CandidateKTSequenceReader interface {
	NextHistorySequence(context.Context) (uint64, error)
}

// NewHandlerWithCandidateKTDevicePublication adds opt-in device-bound KT
// publication routes. The sequence endpoint is advisory; the publication
// transaction is authoritative and rejects stale sequence values.
func NewHandlerWithCandidateKTDevicePublication(
	base http.Handler,
	service CandidateKTDevicePublicationService,
	sequences CandidateKTSequenceReader,
	authenticator DeviceRequestAuthenticator,
) http.Handler {
	publish := deviceRequestAuthMiddleware(authenticator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveCandidateKTDeviceLeafPublish(w, r, service)
	}))
	limiter := newDemoMessageLimiter(20, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != candidateKTNextSequenceURL && r.URL.Path != candidateKTDeviceLeafURL {
			base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeDeviceError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		if service == nil || sequences == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PUBLICATION_UNAVAILABLE")
			return
		}
		switch r.URL.Path {
		case candidateKTNextSequenceURL:
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
				return
			}
			sequence, err := sequences.NextHistorySequence(r.Context())
			if err != nil || sequence == 0 || sequence > math.MaxInt64 {
				writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PUBLICATION_UNAVAILABLE")
				return
			}
			raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: sequence}})
			if err != nil {
				writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
				return
			}
			writeCBOR(w, raw)
		case candidateKTDeviceLeafURL:
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
				return
			}
			publish.ServeHTTP(w, r)
		}
	})
}

// Request wire object: canonical PM-CBOR map {1: expected_sequence, 2: leaf_cbor}.
// The server derives the SMT key and leaf hash and constructs the history entry.
// This avoids relying on clients to implement KT hash domains or history encoding.
func serveCandidateKTDeviceLeafPublish(w http.ResponseWriter, r *http.Request, service CandidateKTDevicePublicationService) {
	principal, ok := devicePrincipalFromContext(r.Context())
	if !ok {
		writeDeviceError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != deviceCBORContentType {
		writeDeviceError(w, http.StatusUnsupportedMediaType, "ERR_EXPECTED_CBOR")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, candidateKTMaxBodyBytes))
	if err != nil {
		writeDeviceError(w, http.StatusRequestEntityTooLarge, "ERR_BODY_TOO_LARGE")
		return
	}
	sequence, leafRaw, err := parseCandidateKTDeviceLeafRequest(raw)
	if err != nil {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_KT_PUBLICATION")
		return
	}
	leaf, _, err := kt.VerifyTransparencyLeafV1(leafRaw)
	if err != nil || leaf.AccountID != principal.AccountID || leaf.DeviceID != principal.DeviceID || leaf.Epoch != principal.Epoch {
		writeDeviceError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
		return
	}
	snapshot, err := service.PublishDeviceLeaf(r.Context(), kt.DeviceLeafPrincipal{
		AccountID: principal.AccountID,
		DeviceID:  principal.DeviceID,
		Epoch:     principal.Epoch,
	}, sequence, leafRaw)
	if err != nil {
		writeCandidateKTServiceError(w, err)
		return
	}
	if len(snapshot.SignedBytes) == 0 {
		writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PUBLICATION_UNAVAILABLE")
		return
	}
	writeCBOR(w, snapshot.SignedBytes)
}

func parseCandidateKTDeviceLeafRequest(raw []byte) (uint64, []byte, error) {
	if len(raw) == 0 || len(raw) > candidateKTMaxBodyBytes {
		return 0, nil, errors.New("invalid request size")
	}
	value, err := cbor.DecodeStrict(raw)
	if err != nil || value.Kind != cbor.KindMap || len(value.Map) != 2 {
		return 0, nil, errors.New("invalid candidate KT publication map")
	}
	var sequence uint64
	var leafRaw []byte
	seenSequence, seenLeaf := false, false
	for _, pair := range value.Map {
		if pair.Key.Kind != cbor.KindInt || pair.Key.Int.Neg {
			return 0, nil, errors.New("invalid candidate KT publication key")
		}
		switch pair.Key.Int.Arg {
		case 1:
			if seenSequence || pair.Val.Kind != cbor.KindInt || pair.Val.Int.Neg || pair.Val.Int.Arg == 0 || pair.Val.Int.Arg > math.MaxInt64 {
				return 0, nil, errors.New("invalid expected sequence")
			}
			sequence, seenSequence = pair.Val.Int.Arg, true
		case 2:
			if seenLeaf || pair.Val.Kind != cbor.KindBytes || len(pair.Val.Bytes) == 0 || len(pair.Val.Bytes) > candidateKTMaxLeafBytes {
				return 0, nil, errors.New("invalid transparency leaf bytes")
			}
			leafRaw, seenLeaf = append([]byte(nil), pair.Val.Bytes...), true
		default:
			return 0, nil, errors.New("unknown candidate KT publication field")
		}
	}
	if !seenSequence || !seenLeaf {
		return 0, nil, errors.New("missing candidate KT publication field")
	}
	return sequence, leafRaw, nil
}

func writeCandidateKTServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, kt.ErrTransparencyHistoryGap), errors.Is(err, kt.ErrTransparencyHistoryConflict), errors.Is(err, kt.ErrTransparencyHistoryRollback):
		writeDeviceError(w, http.StatusConflict, "ERR_KT_SEQUENCE_CONFLICT")
	case errors.Is(err, kt.ErrDeviceRevoked), errors.Is(err, kt.ErrDeviceAuthorizationRejected), errors.Is(err, kt.ErrPendingRecovery):
		writeDeviceError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
	case errors.Is(err, kt.ErrDeviceStateMismatch):
		writeDeviceError(w, http.StatusConflict, "ERR_KT_DEVICE_STATE_CONFLICT")
	default:
		// Avoid returning internal authorization, key or database details.
		writeDeviceError(w, http.StatusServiceUnavailable, "ERR_KT_PUBLICATION_UNAVAILABLE")
	}
}
