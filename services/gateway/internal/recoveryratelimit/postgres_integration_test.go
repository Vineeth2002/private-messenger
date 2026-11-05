package recoveryratelimit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	integrationDSNEnv = "PM_ENROLLMENT_TEST_DATABASE_URL"
	integrationDBName = "pm_enrollment_test_20261030"
)

func openRateLimitIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(integrationDSNEnv))
	if dsn == "" {
		t.Skip("set PM_ENROLLMENT_TEST_DATABASE_URL to run PostgreSQL rate-limit integration tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open rate-limit integration database: %v", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping rate-limit integration database: %v", err)
	}
	var databaseName, serverAddress, schemaName string
	var serverPort int
	var inRecovery bool
	if err := db.QueryRowContext(ctx, `
SELECT current_database(), COALESCE(host(inet_server_addr()), ''),
       COALESCE(inet_server_port(), 0), current_schema(), pg_is_in_recovery()
`).Scan(&databaseName, &serverAddress, &serverPort, &schemaName, &inRecovery); err != nil {
		t.Fatalf("inspect rate-limit integration connection: %v", err)
	}
	if databaseName != integrationDBName || serverAddress != "127.0.0.1" || serverPort != 5432 || schemaName != "public" || inRecovery {
		t.Fatalf("safety stop: expected local primary PostgreSQL at 127.0.0.1:5432, database %q, schema public; got database=%q address=%q port=%d schema=%q in_recovery=%v", integrationDBName, databaseName, serverAddress, serverPort, schemaName, inRecovery)
	}
	var ready bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.recovery_api_rate_limits') IS NOT NULL`).Scan(&ready); err != nil {
		t.Fatalf("inspect rate-limit schema: %v", err)
	}
	if !ready {
		t.Fatal("migration 0009 is not installed in the dedicated integration database")
	}
	return db
}

func TestPostgresLimiterSharesQuotaAcrossInstancesIntegration(t *testing.T) {
	db1 := openRateLimitIntegrationDB(t)
	dsn := strings.TrimSpace(os.Getenv(integrationDSNEnv))
	db2, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open second gateway database pool: %v", err)
	}
	db2.SetMaxOpenConns(16)
	db2.SetMaxIdleConns(8)
	t.Cleanup(func() { _ = db2.Close() })

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	first, err := NewPostgres(db1, key, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPostgres(db2, key, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var randomPrefix [8]byte
	if _, err := rand.Read(randomPrefix[:]); err != nil {
		t.Fatal(err)
	}
	ip := make(net.IP, net.IPv6len)
	ip[0], ip[1], ip[2], ip[3] = 0x20, 0x01, 0x0d, 0xb8
	copy(ip[4:12], randomPrefix[:])
	peer := ip.String()
	hash := clientKeyHash(key, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := db1.ExecContext(ctx, `DELETE FROM recovery_api_rate_limits WHERE client_key_hash = $1`, hash[:]); err != nil {
		t.Fatalf("clear unique rate-limit fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := db1.ExecContext(cleanupCtx, `DELETE FROM recovery_api_rate_limits WHERE client_key_hash = $1`, hash[:]); err != nil {
			t.Errorf("clean rate-limit fixture %s: %v", hex.EncodeToString(hash[:]), err)
		}
	})

	const requests = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	errorsSeen := make([]error, 0)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			limiter := first
			if index%2 == 1 {
				limiter = second
			}
			ok, _, callErr := limiter.Allow(ctx, peer)
			mu.Lock()
			defer mu.Unlock()
			if callErr != nil {
				errorsSeen = append(errorsSeen, callErr)
			} else if ok {
				allowed++
			}
		}(i)
	}
	wg.Wait()
	if len(errorsSeen) != 0 {
		t.Fatalf("rate-limit requests returned errors: %v", errorsSeen)
	}
	if allowed != 10 {
		t.Fatalf("two gateway instances allowed %d of %d concurrent requests; want exactly 10", allowed, requests)
	}
	ok, retryAfter, err := second.Allow(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if ok || retryAfter <= 0 {
		t.Fatalf("request after shared quota: allowed=%v retryAfter=%s; want denied with positive retry", ok, retryAfter)
	}
	var storedCount int
	if err := db1.QueryRowContext(ctx, `SELECT request_count FROM recovery_api_rate_limits WHERE client_key_hash = $1`, hash[:]).Scan(&storedCount); err != nil {
		t.Fatal(err)
	}
	if storedCount != 11 {
		t.Fatalf("stored request_count=%d; want capped count 11", storedCount)
	}
}
