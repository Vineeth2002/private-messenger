package authorization

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestPostgresEnrollmentChallengeLifecycleGuardIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var guardInstalled bool
	if err := db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM pg_trigger
    WHERE tgrelid = 'public.device_enrollment_challenges'::regclass
      AND tgname = 'device_enrollment_challenges_guard_lifecycle_trg'
      AND NOT tgisinternal
      AND tgenabled <> 'D'
)
`).Scan(&guardInstalled); err != nil {
		t.Fatalf("inspect enrollment challenge lifecycle trigger: %v", err)
	}
	if !guardInstalled {
		t.Fatal("migration 0010 is not installed or its lifecycle trigger is disabled")
	}

	first, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue first challenge: %v", err)
	}
	second, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue replacement challenge: %v", err)
	}

	var firstConsumed sql.NullTime
	if err := db.QueryRowContext(ctx, `
SELECT consumed_at FROM device_enrollment_challenges WHERE challenge_id = $1::uuid
`, uuidText(first.ID)).Scan(&firstConsumed); err != nil {
		t.Fatalf("read superseded challenge consumption: %v", err)
	}
	if !firstConsumed.Valid {
		t.Fatal("issuing a replacement challenge did not consume the previous challenge")
	}

	var originalCreatedAt, originalExpiresAt time.Time
	if err := db.QueryRowContext(ctx, `
SELECT created_at, expires_at
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
`, uuidText(second.ID)).Scan(&originalCreatedAt, &originalExpiresAt); err != nil {
		t.Fatalf("read replacement challenge timestamps: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET created_at = created_at - INTERVAL '1 microsecond'
WHERE challenge_id = $1::uuid
`, uuidText(second.ID)); err == nil {
		t.Fatal("database allowed challenge created_at to change")
	}
	if _, err := db.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET expires_at = expires_at + INTERVAL '1 microsecond'
WHERE challenge_id = $1::uuid
`, uuidText(second.ID)); err == nil {
		t.Fatal("database allowed challenge expires_at to change")
	}

	var beforeConsumption time.Time
	if err := db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&beforeConsumption); err != nil {
		t.Fatalf("read database clock before consumption: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = TIMESTAMPTZ '2000-01-01 00:00:00+00'
WHERE challenge_id = $1::uuid AND consumed_at IS NULL
`, uuidText(second.ID)); err != nil {
		t.Fatalf("first challenge consumption failed: %v", err)
	}

	var consumedAt time.Time
	if err := db.QueryRowContext(ctx, `
SELECT consumed_at FROM device_enrollment_challenges WHERE challenge_id = $1::uuid
`, uuidText(second.ID)).Scan(&consumedAt); err != nil {
		t.Fatalf("read consumed timestamp: %v", err)
	}
	if consumedAt.Before(beforeConsumption.Add(-time.Second)) {
		t.Fatalf("database did not replace caller timestamp with database time: consumed_at=%s before=%s", consumedAt, beforeConsumption)
	}

	if _, err := db.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = NULL
WHERE challenge_id = $1::uuid
`, uuidText(second.ID)); err == nil {
		t.Fatal("database allowed a consumed challenge to become unconsumed")
	}
	if _, err := db.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = consumed_at + INTERVAL '1 microsecond'
WHERE challenge_id = $1::uuid
`, uuidText(second.ID)); err == nil {
		t.Fatal("database allowed an existing consumed_at timestamp to change")
	}

	var finalCreatedAt, finalExpiresAt, finalConsumedAt time.Time
	if err := db.QueryRowContext(ctx, `
SELECT created_at, expires_at, consumed_at
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
`, uuidText(second.ID)).Scan(&finalCreatedAt, &finalExpiresAt, &finalConsumedAt); err != nil {
		t.Fatalf("read final challenge lifecycle state: %v", err)
	}
	if !finalCreatedAt.Equal(originalCreatedAt) || !finalExpiresAt.Equal(originalExpiresAt) || !finalConsumedAt.Equal(consumedAt) {
		t.Fatalf("challenge lifecycle timestamps changed unexpectedly: created %s/%s expiry %s/%s consumed %s/%s",
			finalCreatedAt, originalCreatedAt, finalExpiresAt, originalExpiresAt, finalConsumedAt, consumedAt)
	}
}
