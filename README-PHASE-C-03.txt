PRIVATE MESSENGER - PHASE C PATCH 03
Typed recovery-finalization event and append-only compatibility event table

TARGET
  Repository: C:\private-messenger
  Branch: phase-c/ratchet-persistence-design
  Base commit: d10afb4bd9bc914295d4d0b349482673b434adfb
  Previous migration series: 0001 through 0011

WHAT THIS PATCH CHANGES
  1. Adds migration 0012_typed_recovery_finalization_event.sql.
  2. Renames authorization_events.cert_cbor to authorization_events.payload_cbor.
     The separate device_certificates.cert_cbor column is unchanged.
  3. Adds RECOVERY_FINALIZED as an explicit authorization_events kind.
  4. Backfills only legacy TRANSITION rows that exactly match a durable
     FINALIZED account_recovery_requests record.
  5. Refuses migration if any FINALIZED recovery request lacks exact matching
     authorization event evidence.
  6. Adds database triggers rejecting UPDATE, DELETE, and TRUNCATE on
     authorization_events.
  7. Updates enrollment, transition, recovery-finalization, and initial-account
     bootstrap event writers/readers to use payload_cbor.
  8. Preserves initial-account bootstrap Gateway startup wiring and includes
     bootstrap, candidate enrollment, and recovery APIs in the migration-0012
     fail-closed schema guard.
  9. Updates PostgreSQL integration fixtures, schema checks, and migration
     behavior tests.

IMPORTANT LIMITS
  - This is a bounded compatibility-table correction. It is NOT the full
    append-only signed lifecycle journal/outbox or signed lifecycle-head
    implementation.
  - It does not implement the three independent ratchet witnesses, 3-of-3
    MARKED_USED/checkpoint protocol, native verified lifecycle context, or
    ratchet persistence.
  - PostgreSQL table owners and superusers can disable triggers. Production
    application database roles must not own these tables or have DDL privileges
    that allow disabling the guards. Deployment privilege separation remains
    outstanding.
  - Initial-account bootstrap, candidate enrollment, and recovery remain
    candidate/unfrozen features and are not production-ready.

APPLICATION
  1. Back up the target database and the listed repository files.
  2. Apply migration 0012 after migration 0011 using the deployment migration
     procedure.
  3. Do not enable initial-account bootstrap, candidate enrollment, or recovery
     APIs unless migration 0012 and its active guards are present.
  4. Keep application database roles separate from table-owner/superuser roles.
  5. Run the Go tests and PostgreSQL integration suite against the explicitly
     named disposable integration database.

VALIDATION PERFORMED IN THE PROJECT ENVIRONMENT
  - gofmt: clean for the changed Go files.
  - git diff --check: passed.
  - go vet ./...: passed after the final bootstrap restoration.
  - go test -p 1 ./... -count=1: passed against the approved disposable
    integration database pm_enrollment_test_20261030 after migration 0012.
  - Initial-account bootstrap HTTP tests: all three passed.
  - Migrations 0001 through 0012: applied successfully in sequence to the
    fresh disposable database pm_phasec_patch03_fresh_20261102.
  - Fresh schema verification: required tables, payload_cbor, event-kind
    constraint, both append-only triggers, and device_certificates.cert_cbor
    all verified.
  - Synthetic historical backfill test: exact legacy event converted to
    RECOVERY_FINALIZED with digest and payload preserved.
  - Synthetic inconsistent-history test: migration 0012 aborted as expected;
    PostgreSQL rolled back the schema changes.
  - The full Go suite intentionally could not run against the fresh database:
    several integration tests contain hard-coded database-name safety checks.
    Those safeguards were not weakened.

REMAINING RELEASE GATES
  - Review production database privileges and trigger-bypass exposure.
  - Review deployment and rollback procedures using representative database
    backups.
  - Implement and independently review the signed lifecycle journal and
    signed lifecycle-head system.
  - Implement native lifecycle verification, ratchet persistence, and the
    independent 3-of-3 witness protocol.
  - Complete end-to-end security testing and independent security review.

Do not describe this patch as a completed Phase C ratchet implementation or
as production-ready.
