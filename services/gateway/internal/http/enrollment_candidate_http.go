package gwhttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

const (
	candidateEnrollmentPrefix       = "/v1/candidate/enrollment/"
	candidateEnrollmentChallengeURL = "/v1/candidate/enrollment/challenges"
	candidateEnrollmentActivateURL  = "/v1/candidate/enrollment/activate"
	candidateEnrollmentBodyLimit    = 16 * 1024
)

// CandidateEnrollmentService is intentionally named as a candidate boundary:
// the route payloads and recovery workflow are not frozen for production.
type CandidateEnrollmentService interface {
	IssueCandidateEnrollmentChallenge(context.Context, []byte, [32]byte) (authorization.EnrollmentChallenge, error)
	ActivateCandidateEnrollment(context.Context, []byte, []byte, [32]byte) error
}

// NewHandlerWithCandidateEnrollment adds explicitly opt-in candidate enrollment
// routes. The gateway does not enable these routes unless the operator sets
// GATEWAY_ENABLE_CANDIDATE_ENROLLMENT=1. They are not a complete recovery flow.
func NewHandlerWithCandidateEnrollment(base http.Handler, service CandidateEnrollmentService) http.Handler {
	limiter := newDemoMessageLimiter(10, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, candidateEnrollmentPrefix) {
			base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeCandidateEnrollmentError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		if service == nil {
			writeCandidateEnrollmentError(w, http.StatusServiceUnavailable, "ERR_ENROLLMENT_UNAVAILABLE")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeCandidateEnrollmentError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return
		}

		switch r.URL.Path {
		case candidateEnrollmentChallengeURL:
			var request candidateEnrollmentChallengeRequest
			if err := decodeCandidateEnrollmentJSON(w, r, &request); err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			certificate, err := decodeCandidateHex(request.EnrollmentCertificateHex, 1, 4096)
			if err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			recoveryKeyBytes, err := decodeCandidateHex(request.RecoveryPublicKeyHex, 32, 32)
			if err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			var recoveryKey [32]byte
			copy(recoveryKey[:], recoveryKeyBytes)
			challenge, err := service.IssueCandidateEnrollmentChallenge(r.Context(), certificate, recoveryKey)
			if err != nil {
				writeCandidateEnrollmentServiceError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(candidateEnrollmentChallengeResponse{
				ChallengeIDHex:    hex.EncodeToString(challenge.ID[:]),
				ChallengeNonceHex: hex.EncodeToString(challenge.Nonce[:]),
				ExpiresAt:         challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
			})
			return

		case candidateEnrollmentActivateURL:
			var request candidateEnrollmentActivateRequest
			if err := decodeCandidateEnrollmentJSON(w, r, &request); err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			certificate, err := decodeCandidateHex(request.EnrollmentCertificateHex, 1, 4096)
			if err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			proof, err := decodeCandidateHex(request.ProofHex, 1, 2048)
			if err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			recoveryKeyBytes, err := decodeCandidateHex(request.RecoveryPublicKeyHex, 32, 32)
			if err != nil {
				writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
				return
			}
			var recoveryKey [32]byte
			copy(recoveryKey[:], recoveryKeyBytes)
			if err := service.ActivateCandidateEnrollment(r.Context(), certificate, proof, recoveryKey); err != nil {
				writeCandidateEnrollmentServiceError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return

		default:
			writeCandidateEnrollmentError(w, http.StatusNotFound, "ERR_NOT_FOUND")
			return
		}
	})
}

type candidateEnrollmentChallengeRequest struct {
	EnrollmentCertificateHex string `json:"enrollment_certificate_hex"`
	RecoveryPublicKeyHex     string `json:"recovery_public_key_hex"`
}

type candidateEnrollmentActivateRequest struct {
	EnrollmentCertificateHex string `json:"enrollment_certificate_hex"`
	ProofHex                 string `json:"proof_hex"`
	RecoveryPublicKeyHex     string `json:"recovery_public_key_hex"`
}

type candidateEnrollmentChallengeResponse struct {
	ChallengeIDHex    string `json:"challenge_id_hex"`
	ChallengeNonceHex string `json:"challenge_nonce_hex"`
	ExpiresAt         string `json:"expires_at"`
}

func decodeCandidateEnrollmentJSON(w http.ResponseWriter, r *http.Request, out any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("candidate enrollment requires application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, candidateEnrollmentBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeCandidateHex(value string, minBytes, maxBytes int) ([]byte, error) {
	if len(value)%2 != 0 || len(value)/2 < minBytes || len(value)/2 > maxBytes {
		return nil, errors.New("invalid hex field length")
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("invalid hex field")
	}
	return out, nil
}

func writeCandidateEnrollmentServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authorization.ErrEnrollmentChallengeExpired):
		writeCandidateEnrollmentError(w, http.StatusGone, "ERR_CHALLENGE_EXPIRED")
	case errors.Is(err, authorization.ErrEnrollmentChallengeConsumed),
		errors.Is(err, authorization.ErrDeviceExists),
		errors.Is(err, authorization.ErrAuthorizationConflict):
		writeCandidateEnrollmentError(w, http.StatusConflict, "ERR_ENROLLMENT_CONFLICT")
	case errors.Is(err, authorization.ErrAccountNotFound):
		writeCandidateEnrollmentError(w, http.StatusNotFound, "ERR_ACCOUNT_NOT_FOUND")
	case errors.Is(err, authorization.ErrAccountLocked):
		writeCandidateEnrollmentError(w, http.StatusLocked, "ERR_ACCOUNT_LOCKED")
	case errors.Is(err, authorization.ErrInvalidAuthorization),
		errors.Is(err, authorization.ErrInvalidEpoch),
		errors.Is(err, authorization.ErrEnrollmentChallengeNotFound):
		writeCandidateEnrollmentError(w, http.StatusBadRequest, "ERR_ENROLLMENT_REJECTED")
	default:
		writeCandidateEnrollmentError(w, http.StatusInternalServerError, "ERR_ENROLLMENT_INTERNAL")
	}
}

func writeCandidateEnrollmentError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
