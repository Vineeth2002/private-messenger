package gwhttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
	"net/http"
	"strings"
	"time"
)

const (
	initialBootstrapPrefix       = "/v1/bootstrap/initial-account/"
	initialBootstrapChallengeURL = "/v1/bootstrap/initial-account/challenges"
	initialBootstrapActivateURL  = "/v1/bootstrap/initial-account/activate"
)

type InitialAccountBootstrapService interface {
	IssueInitialAccountBootstrapChallenge(context.Context, []byte, [32]byte) (authorization.EnrollmentChallenge, error)
	ActivateInitialAccountBootstrap(context.Context, []byte, []byte, [32]byte) error
}

func NewHandlerWithInitialAccountBootstrap(base http.Handler, service InitialAccountBootstrapService) http.Handler {
	limiter := newDemoMessageLimiter(10, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, initialBootstrapPrefix) {
			base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeInitialBootstrapError(w, 429, "ERR_RATE_LIMITED")
			return
		}
		if service == nil {
			writeInitialBootstrapError(w, 503, "ERR_BOOTSTRAP_UNAVAILABLE")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeInitialBootstrapError(w, 405, "ERR_METHOD_NOT_ALLOWED")
			return
		}
		var req struct {
			Certificate string `json:"enrollment_certificate_hex"`
			RecoveryKey string `json:"recovery_public_key_hex"`
			Proof       string `json:"proof_hex"`
		}
		if err := decodeCandidateEnrollmentJSON(w, r, &req); err != nil {
			writeInitialBootstrapError(w, 400, "ERR_INVALID_REQUEST")
			return
		}
		cert, err := decodeCandidateHex(req.Certificate, 1, 4096)
		if err != nil {
			writeInitialBootstrapError(w, 400, "ERR_INVALID_REQUEST")
			return
		}
		key, err := decodeCandidateHex(req.RecoveryKey, 32, 32)
		if err != nil {
			writeInitialBootstrapError(w, 400, "ERR_INVALID_REQUEST")
			return
		}
		var recovery [32]byte
		copy(recovery[:], key)
		switch r.URL.Path {
		case initialBootstrapChallengeURL:
			challenge, e := service.IssueInitialAccountBootstrapChallenge(r.Context(), cert, recovery)
			if e != nil {
				writeInitialBootstrapServiceError(w, e)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(candidateEnrollmentChallengeResponse{ChallengeIDHex: hex.EncodeToString(challenge.ID[:]), ChallengeNonceHex: hex.EncodeToString(challenge.Nonce[:]), ExpiresAt: challenge.ExpiresAt.UTC().Format(time.RFC3339Nano)})
		case initialBootstrapActivateURL:
			proof, e := decodeCandidateHex(req.Proof, 1, 2048)
			if e != nil {
				writeInitialBootstrapError(w, 400, "ERR_INVALID_REQUEST")
				return
			}
			if e = service.ActivateInitialAccountBootstrap(r.Context(), cert, proof, recovery); e != nil {
				writeInitialBootstrapServiceError(w, e)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeInitialBootstrapError(w, 404, "ERR_NOT_FOUND")
		}
	})
}
func writeInitialBootstrapServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authorization.ErrEnrollmentChallengeExpired):
		writeInitialBootstrapError(w, 410, "ERR_CHALLENGE_EXPIRED")
	case errors.Is(err, authorization.ErrAccountExists), errors.Is(err, authorization.ErrDeviceExists), errors.Is(err, authorization.ErrEnrollmentChallengeConsumed), errors.Is(err, authorization.ErrAuthorizationConflict):
		writeInitialBootstrapError(w, 409, "ERR_ACCOUNT_OR_DEVICE_EXISTS")
	case errors.Is(err, authorization.ErrInvalidAuthorization), errors.Is(err, authorization.ErrInvalidEpoch), errors.Is(err, authorization.ErrEnrollmentChallengeNotFound):
		writeInitialBootstrapError(w, 400, "ERR_BOOTSTRAP_REJECTED")
	default:
		writeInitialBootstrapError(w, 500, "ERR_BOOTSTRAP_INTERNAL")
	}
}
func writeInitialBootstrapError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
