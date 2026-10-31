package gwhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
)

type DeviceRequestAuthenticator interface {
	Authenticate(ctx context.Context, authorizationHeader, method, requestTarget string, body []byte, now time.Time) (deviceauth.Principal, error)
}

type devicePrincipalContextKey struct{}

func devicePrincipalFromContext(ctx context.Context) (deviceauth.Principal, bool) {
	principal, ok := ctx.Value(devicePrincipalContextKey{}).(deviceauth.Principal)
	return principal, ok
}

func deviceRequestAuthMiddleware(authenticator DeviceRequestAuthenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if authenticator == nil {
			writeMessageError(w, http.StatusServiceUnavailable, "ERR_DEVICE_AUTH_UNAVAILABLE")
			return
		}

		authorizationHeaders := r.Header.Values("Authorization")
		if len(authorizationHeaders) != 1 {
			writeMessageError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
			return
		}

		requestBody := r.Body
		if requestBody == nil {
			requestBody = http.NoBody
		}
		limitedBody := http.MaxBytesReader(w, requestBody, MaxBodyBytes)
		body, err := io.ReadAll(limitedBody)
		_ = limitedBody.Close()
		if err != nil {
			writeMessageError(w, http.StatusRequestEntityTooLarge, "ERR_BODY_TOO_LARGE")
			return
		}
		// The verifier and the downstream handler must see the exact same bytes.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		requestTarget := r.RequestURI
		if requestTarget == "" && r.URL != nil {
			requestTarget = r.URL.RequestURI()
		}
		principal, err := authenticator.Authenticate(
			r.Context(),
			authorizationHeaders[0],
			r.Method,
			requestTarget,
			body,
			time.Now().UTC(),
		)
		if err != nil {
			switch {
			case errors.Is(err, deviceauth.ErrAccountInactive), errors.Is(err, deviceauth.ErrDeviceInactive):
				writeMessageError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
			case errors.Is(err, deviceauth.ErrMalformedProof),
				errors.Is(err, deviceauth.ErrInvalidProof),
				errors.Is(err, deviceauth.ErrExpiredProof),
				errors.Is(err, deviceauth.ErrRequestReplay),
				errors.Is(err, deviceauth.ErrDeviceNotFound),
				errors.Is(err, deviceauth.ErrEpochMismatch):
				writeMessageError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
			case errors.Is(err, deviceauth.ErrDeviceStateInvalid):
				writeMessageError(w, http.StatusServiceUnavailable, "ERR_DEVICE_STATE_UNAVAILABLE")
			default:
				// Database and infrastructure failures fail closed but are not
				// misreported as invalid client credentials.
				writeMessageError(w, http.StatusServiceUnavailable, "ERR_DEVICE_AUTH_UNAVAILABLE")
			}
			return
		}

		ctx := context.WithValue(r.Context(), devicePrincipalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
