package recoveryratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	minimumHMACKeyBytes = 32
)

// Limiter stores one database-time fixed-window counter per anonymized peer
// prefix. Multiple gateway processes sharing PostgreSQL and the same HMAC key
// therefore share one quota without storing raw client IP addresses.
type Limiter struct {
	db            *sql.DB
	hmacKey       []byte
	limit         int
	window        time.Duration
	windowSeconds float64
}

func NewPostgres(db *sql.DB, hmacKey []byte, limit int, window time.Duration) (*Limiter, error) {
	if db == nil {
		return nil, errors.New("recovery rate limiter: nil database")
	}
	if len(hmacKey) < minimumHMACKeyBytes {
		return nil, fmt.Errorf("recovery rate limiter: HMAC key must be at least %d bytes", minimumHMACKeyBytes)
	}
	if limit < 1 || limit >= int(^uint(0)>>1) {
		return nil, errors.New("recovery rate limiter: limit must be positive and bounded")
	}
	if window < time.Second || window%time.Second != 0 || window > 24*time.Hour {
		return nil, errors.New("recovery rate limiter: window must be a whole number of seconds between 1 second and 24 hours")
	}
	return &Limiter{
		db:            db,
		hmacKey:       append([]byte(nil), hmacKey...),
		limit:         limit,
		window:        window,
		windowSeconds: window.Seconds(),
	}, nil
}

// Allow atomically consumes one quota unit using PostgreSQL time. It fails
// closed: database errors are returned to the HTTP layer and must not allow
// the request through.
func (l *Limiter) Allow(ctx context.Context, peer string) (bool, time.Duration, error) {
	if l == nil || l.db == nil {
		return false, 0, errors.New("recovery rate limiter: unavailable")
	}
	keyHash := clientKeyHash(l.hmacKey, peer)
	const query = `
WITH database_clock AS (
    SELECT clock_timestamp() AS now
), bucket AS (
    SELECT now,
           date_bin(
               make_interval(secs => $2::double precision),
               now,
               TIMESTAMPTZ 'epoch'
           ) AS window_started_at
    FROM database_clock
), applied AS (
    INSERT INTO recovery_api_rate_limits (
        client_key_hash, window_started_at, request_count, updated_at
    )
    SELECT $1, window_started_at, 1, now
    FROM bucket
    ON CONFLICT (client_key_hash) DO UPDATE
    SET window_started_at = CASE
            WHEN recovery_api_rate_limits.window_started_at < EXCLUDED.window_started_at
            THEN EXCLUDED.window_started_at
            ELSE recovery_api_rate_limits.window_started_at
        END,
        request_count = CASE
            WHEN recovery_api_rate_limits.window_started_at < EXCLUDED.window_started_at
            THEN 1
            ELSE LEAST(recovery_api_rate_limits.request_count + 1, $3)
        END,
        updated_at = EXCLUDED.updated_at
    RETURNING window_started_at, request_count
)
SELECT request_count,
       GREATEST(
           1,
           CEIL(EXTRACT(EPOCH FROM (
               window_started_at
               + make_interval(secs => $2::double precision)
               - clock_timestamp()
           )))
       )::integer
FROM applied
`
	var count, retryAfterSeconds int
	err := l.db.QueryRowContext(ctx, query, keyHash[:], l.windowSeconds, l.limit+1).Scan(&count, &retryAfterSeconds)
	if err != nil {
		return false, 0, fmt.Errorf("recovery rate limiter database operation: %w", err)
	}
	if count <= l.limit {
		return true, 0, nil
	}
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	return false, time.Duration(retryAfterSeconds) * time.Second, nil
}

// PruneExpired deletes anonymized counters that have not been used in 24h.
// The gateway runs this periodically; the updated_at index keeps the cleanup
// bounded to stale entries instead of scanning the full table.
func (l *Limiter) PruneExpired(ctx context.Context) error {
	if l == nil || l.db == nil {
		return errors.New("recovery rate limiter: unavailable")
	}
	if _, err := l.db.ExecContext(ctx, `
DELETE FROM recovery_api_rate_limits
WHERE updated_at < clock_timestamp() - INTERVAL '24 hours'
`); err != nil {
		return fmt.Errorf("prune recovery rate limit counters: %w", err)
	}
	return nil
}

func clientKeyHash(hmacKey []byte, peer string) [32]byte {
	mac := hmac.New(sha256.New, hmacKey)
	_, _ = mac.Write([]byte("private-messenger/recovery-rate-limit/v1\x00"))
	_, _ = mac.Write([]byte(normalizePeer(peer)))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// normalizePeer groups IPv6 privacy addresses within a /64. IPv4 addresses
// remain individual /32 peers. Forwarding headers are intentionally not read;
// the caller must pass the transport peer derived from RemoteAddr.
func normalizePeer(peer string) string {
	peer = strings.TrimSpace(peer)
	ip := net.ParseIP(peer)
	if ip == nil {
		return "unknown"
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String() + "/32"
	}
	mask := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}
