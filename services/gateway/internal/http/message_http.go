package gwhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/devices"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
)

// Demo message routes are intentionally isolated from the frozen Phase A
// surface. They provide a real end-to-end relay path for the live demo while
// leaving the final message HTTP contract open for later ratification.
const (
	demoMessagePrefix   = "/v1/demo/messages"
	demoMessageRate     = 60
	demoMessageWindow   = time.Minute
	demoMessageTTL      = 15 * time.Minute
	demoMessageMaxFetch = 100
)

type MessageDelivery interface {
	Enqueue(context.Context, []byte, time.Time) (messages.MessageEnvelopeV1, error)
	Fetch(context.Context, [16]byte, int) ([]messages.StoredEnvelope, error)
	Ack(context.Context, [16]byte, [16]byte) error
}

// AuthenticatedMessageDelivery rechecks the authenticated device's current
// account/device lifecycle state in the same database transaction as each
// message operation. The legacy methods remain for the explicitly demo-only
// shared-bearer path.
type AuthenticatedMessageDelivery interface {
	EnqueueAuthenticated(context.Context, []byte, time.Time, messages.AuthenticatedDevice) (messages.MessageEnvelopeV1, error)
	FetchAuthenticated(context.Context, messages.AuthenticatedDevice, int) ([]messages.StoredEnvelope, error)
	AckAuthenticated(context.Context, messages.AuthenticatedDevice, [16]byte) error
}

// NewHandlerWithSTHAndDevicesAndMessages adds the live demo message relay to
// the existing health/CBOR/KT/device handler.
func NewHandlerWithSTHAndDevicesAndMessages(
	sthSource STHSource,
	directory devices.Directory,
	delivery MessageDelivery,
	authToken string,
) http.Handler {
	base := NewHandlerWithSTHAndDevices(sthSource, directory)
	limiter := newDemoMessageLimiter(demoMessageRate, demoMessageWindow)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, demoMessagePrefix) {
			base.ServeHTTP(w, r)
			return
		}
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeMessageError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		if authToken == "" || !validBearer(r.Header.Get("Authorization"), authToken) {
			writeMessageError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
			return
		}
		serveDemoMessages(w, r, delivery)
	})
}

// NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth enables the same demo
// relay behind per-device request authentication. Unlike the shared-bearer
// constructor, this path binds send/fetch/ack operations to the authenticated
// device identity and requires persistent nonce consumption.
func NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth(
	sthSource STHSource,
	directory devices.Directory,
	delivery MessageDelivery,
	authenticator DeviceRequestAuthenticator,
) http.Handler {
	base := NewHandlerWithSTHAndDevices(sthSource, directory)
	limiter := newDemoMessageLimiter(demoMessageRate, demoMessageWindow)
	messageHandler := deviceRequestAuthMiddleware(authenticator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveDemoMessages(w, r, delivery)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, demoMessagePrefix) {
			base.ServeHTTP(w, r)
			return
		}
		if !limiter.Allow(remoteKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeMessageError(w, http.StatusTooManyRequests, "ERR_RATE_LIMITED")
			return
		}
		messageHandler.ServeHTTP(w, r)
	})
}

func serveDemoMessages(w http.ResponseWriter, r *http.Request, delivery MessageDelivery) {
	principal, deviceAuthenticated := devicePrincipalFromContext(r.Context())
	if delivery == nil {
		writeMessageError(w, http.StatusServiceUnavailable, "ERR_MESSAGE_DELIVERY_UNAVAILABLE")
		return
	}

	parts := splitPath(r.URL.Path)
	switch {
	case len(parts) == 3 && parts[0] == "v1" && parts[1] == "demo" && parts[2] == "messages":
		if r.Method != http.MethodPost {
			writeMessageError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return
		}
		serveDemoMessageSend(w, r, delivery, principal, deviceAuthenticated)
		return

	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "demo" && parts[2] == "messages":
		if r.Method != http.MethodGet {
			writeMessageError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return
		}
		deviceID, ok := parseUUIDPath(parts[3])
		if !ok {
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
			return
		}
		serveDemoMessageFetch(w, r, delivery, deviceID, principal, deviceAuthenticated)
		return

	case len(parts) == 6 && parts[0] == "v1" && parts[1] == "demo" && parts[2] == "messages" && parts[5] == "ack":
		if r.Method != http.MethodPost {
			writeMessageError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return
		}
		deviceID, ok := parseUUIDPath(parts[3])
		if !ok {
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
			return
		}
		envelopeID, ok := parseUUIDPath(parts[4])
		if !ok {
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_ENVELOPE_ID")
			return
		}
		serveDemoMessageAck(w, r, delivery, deviceID, envelopeID, principal, deviceAuthenticated)
		return
	}

	writeMessageError(w, http.StatusNotFound, "ERR_MESSAGE_ROUTE_NOT_FOUND")
}

func serveDemoMessageSend(w http.ResponseWriter, r *http.Request, delivery MessageDelivery, principal deviceauth.Principal, deviceAuthenticated bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		writeMessageError(w, http.StatusRequestEntityTooLarge, "ERR_BODY_TOO_LARGE")
		return
	}
	if len(body) == 0 {
		writeMessageError(w, http.StatusBadRequest, "ERR_EMPTY_MESSAGE_ENVELOPE")
		return
	}
	if deviceAuthenticated {
		parsedEnvelope, err := messages.DecodeMessageEnvelopeV1(body)
		if err != nil {
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ENVELOPE")
			return
		}
		if parsedEnvelope.SenderDeviceID != principal.DeviceID {
			writeMessageError(w, http.StatusForbidden, "ERR_SENDER_DEVICE_IDENTITY_MISMATCH")
			return
		}
	}

	expiresAt := time.Now().UTC().Add(demoMessageTTL)
	if raw := strings.TrimSpace(r.Header.Get("X-Message-Expires-At")); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_EXPIRES_AT")
			return
		}
		expiresAt = parsed.UTC()
	}
	if !expiresAt.After(time.Now().UTC()) {
		writeMessageError(w, http.StatusBadRequest, "ERR_EXPIRED_MESSAGE")
		return
	}

	var envelope messages.MessageEnvelopeV1
	if deviceAuthenticated {
		authenticatedDelivery, ok := delivery.(AuthenticatedMessageDelivery)
		if !ok {
			writeMessageError(w, http.StatusServiceUnavailable, "ERR_AUTHENTICATED_DELIVERY_UNAVAILABLE")
			return
		}
		envelope, err = authenticatedDelivery.EnqueueAuthenticated(
			r.Context(), body, expiresAt, authenticatedMessageDevice(principal),
		)
	} else {
		envelope, err = delivery.Enqueue(r.Context(), body, expiresAt)
	}
	if err != nil {
		switch {
		case errors.Is(err, messages.ErrSenderNotFound), errors.Is(err, messages.ErrRecipientNotFound):
			writeMessageError(w, http.StatusNotFound, messageErrorCode(err))
		case errors.Is(err, messages.ErrSenderRevoked), errors.Is(err, messages.ErrRecipientRevoked),
			errors.Is(err, messages.ErrAuthenticatedAccountInactive), errors.Is(err, messages.ErrAuthenticatedDeviceInactive),
			errors.Is(err, messages.ErrAuthenticatedDeviceNotFound):
			writeMessageError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
		case errors.Is(err, messages.ErrAuthenticatedEpochMismatch):
			writeMessageError(w, http.StatusConflict, "ERR_DEVICE_EPOCH_MISMATCH")
		case errors.Is(err, messages.ErrAuthenticatedDeviceState):
			writeMessageError(w, http.StatusServiceUnavailable, "ERR_DEVICE_STATE_UNAVAILABLE")
		case errors.Is(err, messages.ErrSenderIdentityMismatch):
			writeMessageError(w, http.StatusForbidden, "ERR_SENDER_DEVICE_IDENTITY_MISMATCH")
		case errors.Is(err, messages.ErrRecipientEpochMismatch):
			writeMessageError(w, http.StatusConflict, "ERR_RECIPIENT_EPOCH_MISMATCH")
		case errors.Is(err, messages.ErrInvalidMessageEnvelope), errors.Is(err, messages.ErrInvalidMessageEnvelopeField), errors.Is(err, messages.ErrNonCanonicalMessageEnvelope):
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ENVELOPE")
		default:
			writeMessageError(w, http.StatusInternalServerError, "ERR_MESSAGE_DELIVERY")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"envelope_id":         envelopeIDString(envelope.EnvelopeID),
		"recipient_device_id": envelopeIDString(envelope.RecipientDeviceID),
		"expires_at":          expiresAt.Format(time.RFC3339Nano),
	})
}

func serveDemoMessageFetch(w http.ResponseWriter, r *http.Request, delivery MessageDelivery, deviceID [16]byte, principal deviceauth.Principal, deviceAuthenticated bool) {
	if deviceAuthenticated && deviceID != principal.DeviceID {
		writeMessageError(w, http.StatusForbidden, "ERR_DEVICE_IDENTITY_MISMATCH")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > demoMessageMaxFetch {
			writeMessageError(w, http.StatusBadRequest, "ERR_INVALID_LIMIT")
			return
		}
		limit = n
	}

	var envelopes []messages.StoredEnvelope
	var err error
	if deviceAuthenticated {
		authenticatedDelivery, ok := delivery.(AuthenticatedMessageDelivery)
		if !ok {
			writeMessageError(w, http.StatusServiceUnavailable, "ERR_AUTHENTICATED_DELIVERY_UNAVAILABLE")
			return
		}
		envelopes, err = authenticatedDelivery.FetchAuthenticated(r.Context(), authenticatedMessageDevice(principal), limit)
	} else {
		envelopes, err = delivery.Fetch(r.Context(), deviceID, limit)
	}
	if err != nil {
		writeAuthenticatedDeliveryError(w, err, "ERR_MESSAGE_FETCH")
		return
	}

	type item struct {
		EnvelopeID string `json:"envelope_id"`
		Envelope   string `json:"envelope_cbor_base64"`
		CreatedAt  string `json:"created_at"`
		ExpiresAt  string `json:"expires_at"`
	}
	out := make([]item, 0, len(envelopes))
	for _, envelope := range envelopes {
		out = append(out, item{
			EnvelopeID: envelopeIDString(envelope.EnvelopeID),
			Envelope:   base64.StdEncoding.EncodeToString(envelope.Raw),
			CreatedAt:  envelope.CreatedAt.UTC().Format(time.RFC3339Nano),
			ExpiresAt:  envelope.ExpiresAt.UTC().Format(time.RFC3339Nano),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"messages": out})
}

func serveDemoMessageAck(w http.ResponseWriter, r *http.Request, delivery MessageDelivery, deviceID, envelopeID [16]byte, principal deviceauth.Principal, deviceAuthenticated bool) {
	if deviceAuthenticated && deviceID != principal.DeviceID {
		writeMessageError(w, http.StatusForbidden, "ERR_DEVICE_IDENTITY_MISMATCH")
		return
	}
	var err error
	if deviceAuthenticated {
		authenticatedDelivery, ok := delivery.(AuthenticatedMessageDelivery)
		if !ok {
			writeMessageError(w, http.StatusServiceUnavailable, "ERR_AUTHENTICATED_DELIVERY_UNAVAILABLE")
			return
		}
		err = authenticatedDelivery.AckAuthenticated(r.Context(), authenticatedMessageDevice(principal), envelopeID)
	} else {
		err = delivery.Ack(r.Context(), deviceID, envelopeID)
	}
	if err != nil {
		if errors.Is(err, messages.ErrEnvelopeNotFound) {
			writeMessageError(w, http.StatusNotFound, "ERR_MESSAGE_NOT_FOUND")
			return
		}
		writeAuthenticatedDeliveryError(w, err, "ERR_MESSAGE_ACK")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func authenticatedMessageDevice(principal deviceauth.Principal) messages.AuthenticatedDevice {
	return messages.AuthenticatedDevice{
		AccountID: principal.AccountID,
		DeviceID:  principal.DeviceID,
		Epoch:     principal.Epoch,
	}
}

func writeAuthenticatedDeliveryError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, messages.ErrAuthenticatedAccountInactive),
		errors.Is(err, messages.ErrAuthenticatedDeviceInactive),
		errors.Is(err, messages.ErrAuthenticatedDeviceNotFound):
		writeMessageError(w, http.StatusForbidden, "ERR_DEVICE_NOT_AUTHORIZED")
	case errors.Is(err, messages.ErrAuthenticatedEpochMismatch):
		writeMessageError(w, http.StatusConflict, "ERR_DEVICE_EPOCH_MISMATCH")
	case errors.Is(err, messages.ErrAuthenticatedDeviceState):
		writeMessageError(w, http.StatusServiceUnavailable, "ERR_DEVICE_STATE_UNAVAILABLE")
	default:
		writeMessageError(w, http.StatusInternalServerError, fallback)
	}
}

func messageErrorCode(err error) string {
	switch {
	case errors.Is(err, messages.ErrSenderNotFound):
		return "ERR_SENDER_DEVICE_NOT_FOUND"
	case errors.Is(err, messages.ErrSenderRevoked):
		return "ERR_SENDER_DEVICE_REVOKED"
	case errors.Is(err, messages.ErrRecipientNotFound):
		return "ERR_RECIPIENT_DEVICE_NOT_FOUND"
	case errors.Is(err, messages.ErrRecipientRevoked):
		return "ERR_RECIPIENT_DEVICE_REVOKED"
	default:
		return "ERR_MESSAGE_DELIVERY"
	}
}

func writeMessageError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func validBearer(header, expected string) bool {
	const prefix = "Bearer "
	return strings.HasPrefix(header, prefix) && strings.TrimSpace(strings.TrimPrefix(header, prefix)) == expected
}

func remoteKey(r *http.Request) string {
	// RemoteAddr is supplied by the HTTP server. Do not trust client-controlled
	// forwarding headers here, and do not include the ephemeral source port.
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return "unknown"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return ip.String()
}

func envelopeIDString(id [16]byte) string {
	return messages.UUIDText(id)
}

const demoMessageLimiterMaxEntries = 4096

type demoMessageLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	entries   map[string]demoLimitEntry
	lastSweep time.Time
}

type demoLimitEntry struct {
	started time.Time
	count   int
}

func newDemoMessageLimiter(limit int, window time.Duration) *demoMessageLimiter {
	return &demoMessageLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]demoLimitEntry),
	}
}

func (l *demoMessageLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Bound memory if many distinct peers appear. Sweep periodically rather than
	// scanning the whole map for every new peer while at capacity.
	sweepInterval := l.window / 4
	if sweepInterval <= 0 {
		sweepInterval = time.Second
	}
	if sweepInterval > 15*time.Second {
		sweepInterval = 15 * time.Second
	}
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= sweepInterval {
		for candidate, candidateEntry := range l.entries {
			if candidateEntry.started.IsZero() || now.Sub(candidateEntry.started) >= l.window {
				delete(l.entries, candidate)
			}
		}
		l.lastSweep = now
	}

	if l.entries == nil {
		l.entries = make(map[string]demoLimitEntry)
	}
	entry, exists := l.entries[key]
	if !exists {
		if len(l.entries) >= demoMessageLimiterMaxEntries {
			return false
		}
		l.entries[key] = demoLimitEntry{started: now, count: 1}
		return true
	}
	if entry.started.IsZero() || now.Sub(entry.started) >= l.window {
		l.entries[key] = demoLimitEntry{started: now, count: 1}
		return true
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}
