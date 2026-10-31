package gwhttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

const (
	recoveryAPIPrefix              = "/v1/recovery/"
	recoveryBeginURL               = "/v1/recovery/requests"
	recoveryAbortURL               = "/v1/recovery/abort"
	recoveryEnrollmentChallengeURL = "/v1/recovery/enrollment/challenges"
	recoveryEnrollmentActivateURL  = "/v1/recovery/enrollment/activate"
	recoveryAPIRequestLimit        = 10
	recoveryAPIRequestWindow       = time.Minute
)

// RecoveryAPIService is the persistence-backed recovery boundary. The HTTP
// layer transports signed wire objects; authorization and lifecycle decisions
// remain in PostgresAuthorizer.
type RecoveryAPIService interface {
	BeginRecovery(context.Context, []byte, []byte, [32]byte) (authorization.RecoveryRequestState, error)
	AbortRecovery(context.Context, []byte) (authorization.RecoveryRequestState, error)
	IssueRecoveryEnrollmentChallenge(context.Context, [16]byte, []byte, [32]byte) (authorization.EnrollmentChallenge, error)
	ActivateRecoveryEnrollment(context.Context, [16]byte, []byte, []byte, [32]byte) error
}

type recoveryBeginHTTPRequest struct {
	RecoveryRequestCBORHex   string `json:"recovery_request_cbor_hex"`
	EnrollmentCertificateHex string `json:"enrollment_certificate_hex"`
	RecoveryPublicKeyHex     string `json:"recovery_public_key_hex"`
}

type recoveryAbortHTTPRequest struct {
	RecoveryAbortCBORHex string `json:"recovery_abort_cbor_hex"`
}

type recoveryEnrollmentChallengeHTTPRequest struct {
	RequestIDHex             string `json:"request_id_hex"`
	EnrollmentCertificateHex string `json:"enrollment_certificate_hex"`
	RecoveryPublicKeyHex     string `json:"recovery_public_key_hex"`
}

type recoveryEnrollmentActivateHTTPRequest struct {
	RequestIDHex             string `json:"request_id_hex"`
	EnrollmentCertificateHex string `json:"enrollment_certificate_hex"`
	ProofHex                 string `json:"proof_hex"`
	RecoveryPublicKeyHex     string `json:"recovery_public_key_hex"`
}

type recoveryRequestStateHTTPResponse struct {
	RequestIDHex        string `json:"request_id_hex"`
	RequestDigestHex    string `json:"request_digest_hex"`
	Status              string `json:"status"`
	AcceptedAt          string `json:"accepted_at"`
	FinalizeAfter       string `json:"finalize_after"`
	AbortedAt           string `json:"aborted_at,omitempty"`
	AbortingDeviceIDHex string `json:"aborting_device_id_hex,omitempty"`
	FinalizedAt         string `json:"finalized_at,omitempty"`
}

type recoveryEnrollmentChallengeHTTPResponse struct {
	ChallengeIDHex    string `json:"challenge_id_hex"`
	ChallengeNonceHex string `json:"challenge_nonce_hex"`
	ExpiresAt         string `json:"expires_at"`
}

// NewHandlerWithRecoveryAPI adds separately gated recovery routes. It does not
// expose a finalization endpoint: the standalone recovery-finalizer worker is
// the only automatic finalization entry point.
type RecoveryAPIRateLimiter interface {
	Allow(context.Context, string) (bool, time.Duration, error)
}

type processLocalRecoveryAPIRateLimiter struct {
	limiter *demoMessageLimiter
}

func (l *processLocalRecoveryAPIRateLimiter) Allow(_ context.Context, peer string) (bool, time.Duration, error) {
	if l.limiter.Allow(peer) {
		return true, 0, nil
	}
	return false, recoveryAPIRequestWindow, nil
}

func NewHandlerWithRecoveryAPI(base http.Handler, service RecoveryAPIService) http.Handler {
	return NewHandlerWithRecoveryAPIAndLimiter(base, service, &processLocalRecoveryAPIRateLimiter{
		limiter: newDemoMessageLimiter(recoveryAPIRequestLimit, recoveryAPIRequestWindow),
	})
}

// NewHandlerWithRecoveryAPIAndLimiter permits production to inject a shared,
// database-backed limiter. A limiter failure is fail-closed and never bypasses
// recovery API throttling.
func NewHandlerWithRecoveryAPIAndLimiter(base http.Handler, service RecoveryAPIService, limiter RecoveryAPIRateLimiter) http.Handler {
	if base == nil {
		base = http.NotFoundHandler()
	}
	if limiter == nil {
		limiter = &processLocalRecoveryAPIRateLimiter{
			limiter: newDemoMessageLimiter(recoveryAPIRequestLimit, recoveryAPIRequestWindow),
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, recoveryAPIPrefix) {
			base.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		allowed, retryAfter, err := limiter.Allow(r.Context(), remoteKey(r))
		if err != nil {
			writeRecoveryAPIError(w, http.StatusServiceUnavailable, "ERR_RATE_LIMIT_UNAVAILABLE")
			return
		}
		if !allowed {
			retryAfterSeconds := int(math.Ceil(retryAfter.Seconds()))
			if retryAfterSeconds < 1 {
				retryAfterSeconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
			writeRecoveryAPIError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		if service == nil {
			writeRecoveryAPIError(w, http.StatusServiceUnavailable, "ERR_RECOVERY_UNAVAILABLE")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeRecoveryAPIError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return
		}

		switch r.URL.Path {
		case recoveryBeginURL:
			serveRecoveryBegin(w, r, service)
		case recoveryAbortURL:
			serveRecoveryAbort(w, r, service)
		case recoveryEnrollmentChallengeURL:
			serveRecoveryEnrollmentChallenge(w, r, service)
		case recoveryEnrollmentActivateURL:
			serveRecoveryEnrollmentActivate(w, r, service)
		default:
			writeRecoveryAPIError(w, http.StatusNotFound, "ERR_NOT_FOUND")
		}
	})
}

func serveRecoveryBegin(w http.ResponseWriter, r *http.Request, service RecoveryAPIService) {
	var request recoveryBeginHTTPRequest
	if !decodeRecoveryAPIJSON(w, r, &request) {
		return
	}
	recoveryRequest, err := decodeCandidateHex(request.RecoveryRequestCBORHex, 1, 4096)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	certificate, err := decodeCandidateHex(request.EnrollmentCertificateHex, 1, 4096)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	recoveryPublicKey, err := decodeRecoveryPublicKey(request.RecoveryPublicKeyHex)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}

	state, err := service.BeginRecovery(r.Context(), recoveryRequest, certificate, recoveryPublicKey)
	if err != nil {
		writeRecoveryServiceError(w, err)
		return
	}
	writeRecoveryRequestState(w, state)
}

func serveRecoveryAbort(w http.ResponseWriter, r *http.Request, service RecoveryAPIService) {
	var request recoveryAbortHTTPRequest
	if !decodeRecoveryAPIJSON(w, r, &request) {
		return
	}
	abort, err := decodeCandidateHex(request.RecoveryAbortCBORHex, 1, 4096)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}

	state, err := service.AbortRecovery(r.Context(), abort)
	if err != nil {
		writeRecoveryServiceError(w, err)
		return
	}
	writeRecoveryRequestState(w, state)
}

func serveRecoveryEnrollmentChallenge(w http.ResponseWriter, r *http.Request, service RecoveryAPIService) {
	var request recoveryEnrollmentChallengeHTTPRequest
	if !decodeRecoveryAPIJSON(w, r, &request) {
		return
	}
	requestIDBytes, err := decodeCandidateHex(request.RequestIDHex, 16, 16)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	var requestID [16]byte
	copy(requestID[:], requestIDBytes)
	certificate, err := decodeCandidateHex(request.EnrollmentCertificateHex, 1, 4096)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	recoveryPublicKey, err := decodeRecoveryPublicKey(request.RecoveryPublicKeyHex)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}

	challenge, err := service.IssueRecoveryEnrollmentChallenge(r.Context(), requestID, certificate, recoveryPublicKey)
	if err != nil {
		writeRecoveryServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(recoveryEnrollmentChallengeHTTPResponse{
		ChallengeIDHex:    hex.EncodeToString(challenge.ID[:]),
		ChallengeNonceHex: hex.EncodeToString(challenge.Nonce[:]),
		ExpiresAt:         challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func serveRecoveryEnrollmentActivate(w http.ResponseWriter, r *http.Request, service RecoveryAPIService) {
	var request recoveryEnrollmentActivateHTTPRequest
	if !decodeRecoveryAPIJSON(w, r, &request) {
		return
	}
	requestIDBytes, err := decodeCandidateHex(request.RequestIDHex, 16, 16)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	var requestID [16]byte
	copy(requestID[:], requestIDBytes)
	certificate, err := decodeCandidateHex(request.EnrollmentCertificateHex, 1, 4096)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	proof, err := decodeCandidateHex(request.ProofHex, 1, 2048)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}
	recoveryPublicKey, err := decodeRecoveryPublicKey(request.RecoveryPublicKeyHex)
	if err != nil {
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		return
	}

	if err := service.ActivateRecoveryEnrollment(r.Context(), requestID, certificate, proof, recoveryPublicKey); err != nil {
		writeRecoveryServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeRecoveryPublicKey(value string) ([32]byte, error) {
	var out [32]byte
	decoded, err := decodeCandidateHex(value, 32, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], decoded)
	return out, nil
}

func writeRecoveryRequestState(w http.ResponseWriter, state authorization.RecoveryRequestState) {
	response := recoveryRequestStateHTTPResponse{
		RequestIDHex:     hex.EncodeToString(state.RequestID[:]),
		RequestDigestHex: hex.EncodeToString(state.RequestDigest[:]),
		Status:           string(state.Status),
		AcceptedAt:       state.AcceptedAt.UTC().Format(time.RFC3339Nano),
		FinalizeAfter:    state.FinalizeAfter.UTC().Format(time.RFC3339Nano),
	}
	if state.AbortedAt != nil {
		response.AbortedAt = state.AbortedAt.UTC().Format(time.RFC3339Nano)
	}
	if state.AbortingDeviceID != [16]byte{} {
		response.AbortingDeviceIDHex = hex.EncodeToString(state.AbortingDeviceID[:])
	}
	if state.FinalizedAt != nil {
		response.FinalizedAt = state.FinalizedAt.UTC().Format(time.RFC3339Nano)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func writeRecoveryServiceError(w http.ResponseWriter, err error) {
	switch {
	// Do not let the public API distinguish an unknown account from an
	// existing account whose recovery key does not match. Both outcomes use
	// the same external response; the underlying service errors stay distinct.
	case errors.Is(err, authorization.ErrAccountNotFound):
		writeRecoveryAPIError(w, http.StatusConflict, "ERR_RECOVERY_CONFLICT")
	case errors.Is(err, authorization.ErrRecoveryRequestNotFound),
		errors.Is(err, authorization.ErrEnrollmentChallengeNotFound):
		writeRecoveryAPIError(w, http.StatusNotFound, "ERR_RECOVERY_NOT_FOUND")
	case errors.Is(err, authorization.ErrAccountLocked):
		writeRecoveryAPIError(w, http.StatusLocked, "ERR_ACCOUNT_LOCKED")
	case errors.Is(err, authorization.ErrRecoveryNotReady):
		writeRecoveryAPIError(w, http.StatusTooEarly, "ERR_RECOVERY_NOT_READY")
	case errors.Is(err, authorization.ErrRecoveryAbortWindowClosed),
		errors.Is(err, authorization.ErrEnrollmentChallengeExpired):
		writeRecoveryAPIError(w, http.StatusGone, "ERR_RECOVERY_WINDOW_CLOSED")
	case errors.Is(err, authorization.ErrRecoveryPending),
		errors.Is(err, authorization.ErrRecoveryAborted),
		errors.Is(err, authorization.ErrRecoveryFinalized),
		errors.Is(err, authorization.ErrAuthorizationConflict),
		errors.Is(err, authorization.ErrDeviceExists),
		errors.Is(err, authorization.ErrEnrollmentChallengeConsumed):
		writeRecoveryAPIError(w, http.StatusConflict, "ERR_RECOVERY_CONFLICT")
	case errors.Is(err, authorization.ErrInvalidAuthorization),
		errors.Is(err, authorization.ErrInvalidEpoch):
		writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_RECOVERY_REJECTED")
	case errors.Is(err, authorization.ErrDeviceNotFound),
		errors.Is(err, authorization.ErrDeviceRevoked):
		writeRecoveryAPIError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
	default:
		writeRecoveryAPIError(w, http.StatusInternalServerError, "ERR_RECOVERY_INTERNAL")
	}
}

func writeRecoveryAPIError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
