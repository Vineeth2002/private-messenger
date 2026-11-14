package gwhttp

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/signedprekeyv1"
)

const (
	candidateSignedPrekeyPublishURL = "/v1/candidate/signed-prekeys/v1"
	candidateSignedPrekeyPrefix     = "/v1/candidate/signed-prekeys/"
	candidateSignedPrekeyMaxBody    = signedprekeyv1.MaxWireBytes
)

type CandidateSignedPrekeyService interface {
	Publish(context.Context, deviceauth.Principal, []byte) error
	List(context.Context, [16]byte, [16]byte) ([][]byte, error)
}

// NewHandlerWithCandidateSignedPrekeys adds an explicitly opt-in candidate
// API. POST is protected by per-device request authentication; GET returns only
// current-epoch SPKs bound to the device's current signed KT leaf. The contract
// is not frozen and this handler must remain behind its deployment flag.
func NewHandlerWithCandidateSignedPrekeys(base http.Handler, service CandidateSignedPrekeyService, authenticator DeviceRequestAuthenticator) http.Handler {
	post := deviceRequestAuthMiddleware(authenticator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveCandidateSignedPrekeyPublish(w, r, service)
	}))
	limiter := newDemoMessageLimiter(30, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != candidateSignedPrekeyPublishURL && !strings.HasPrefix(r.URL.Path, "/v1/candidate/devices/") {
			base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeDeviceError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		if service == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_SIGNED_PREKEY_UNAVAILABLE")
			return
		}
		if r.URL.Path == candidateSignedPrekeyPublishURL {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
				return
			}
			post.ServeHTTP(w, r)
			return
		}
		serveCandidateSignedPrekeyList(w, r, service)
	})
}

func serveCandidateSignedPrekeyPublish(w http.ResponseWriter, r *http.Request, service CandidateSignedPrekeyService) {
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
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, candidateSignedPrekeyMaxBody))
	if err != nil {
		writeDeviceError(w, http.StatusRequestEntityTooLarge, "ERR_BODY_TOO_LARGE")
		return
	}
	if len(raw) == 0 {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_SIGNED_PREKEY")
		return
	}
	if err := service.Publish(r.Context(), principal, raw); err != nil {
		writeCandidateSignedPrekeyServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func serveCandidateSignedPrekeyList(w http.ResponseWriter, r *http.Request, service CandidateSignedPrekeyService) {
	parts := splitPath(r.URL.Path)
	if len(parts) != 7 || parts[0] != "v1" || parts[1] != "candidate" || parts[2] != "devices" || parts[5] != "signed-prekeys" || parts[6] != "v1" {
		writeDeviceError(w, http.StatusNotFound, "ERR_NOT_FOUND")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
		return
	}
	accountID, ok := parseUUIDPath(parts[3])
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_ACCOUNT_ID")
		return
	}
	deviceID, ok := parseUUIDPath(parts[4])
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
		return
	}
	list, err := service.List(r.Context(), accountID, deviceID)
	if err != nil {
		writeCandidateSignedPrekeyServiceError(w, err)
		return
	}
	out := appendArrayHeader(nil, len(list))
	for _, raw := range list {
		out = append(out, raw...)
	}
	writeCBOR(w, out)
}

func writeCandidateSignedPrekeyServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, signedprekeyv1.ErrInvalidCandidate):
		writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_SIGNED_PREKEY")
	case errors.Is(err, signedprekeyv1.ErrPrincipalMismatch):
		writeDeviceError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
	case errors.Is(err, signedprekeyv1.ErrAccountInactive), errors.Is(err, signedprekeyv1.ErrDeviceInactive), errors.Is(err, signedprekeyv1.ErrPendingRecovery):
		writeDeviceError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
	case errors.Is(err, signedprekeyv1.ErrEpochMismatch), errors.Is(err, signedprekeyv1.ErrTransparencyMismatch), errors.Is(err, signedprekeyv1.ErrSPKConflict):
		writeDeviceError(w, http.StatusConflict, "ERR_SIGNED_PREKEY_CONFLICT")
	case errors.Is(err, signedprekeyv1.ErrTransparencyMissing):
		writeDeviceError(w, http.StatusPreconditionFailed, "ERR_TRANSPARENCY_NOT_PUBLISHED")
	case errors.Is(err, signedprekeyv1.ErrSPKNotPublished):
		writeDeviceError(w, http.StatusPreconditionFailed, "ERR_SIGNED_PREKEY_NOT_PUBLISHED")
	case errors.Is(err, signedprekeyv1.ErrDeviceStateMismatch), errors.Is(err, signedprekeyv1.ErrStoreUnavailable):
		writeDeviceError(w, http.StatusServiceUnavailable, "ERR_SIGNED_PREKEY_UNAVAILABLE")
	default:
		writeDeviceError(w, http.StatusServiceUnavailable, "ERR_SIGNED_PREKEY_UNAVAILABLE")
	}
}
