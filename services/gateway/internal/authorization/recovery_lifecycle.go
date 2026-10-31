package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

type RecoveryRequestStatus string

const (
	RecoveryRequestPending   RecoveryRequestStatus = "PENDING"
	RecoveryRequestAborted   RecoveryRequestStatus = "ABORTED"
	RecoveryRequestFinalized RecoveryRequestStatus = "FINALIZED"
)

// RecoveryRequestState is the durable server-side state returned by recovery
// lifecycle operations. It contains public protocol metadata only.
type RecoveryRequestState struct {
	RequestID        [16]byte
	RequestDigest    [32]byte
	Status           RecoveryRequestStatus
	AcceptedAt       time.Time
	FinalizeAfter    time.Time
	AbortedAt        *time.Time
	AbortingDeviceID [16]byte
	FinalizedAt      *time.Time
}

type recoveryRequestRow struct {
	state                    RecoveryRequestState
	accountID                [16]byte
	raw                      []byte
	oldEpoch                 int64
	newEpoch                 int64
	targetDeviceID           [16]byte
	enrollmentCertificateSHA [32]byte
	abortDigest              []byte
	abortRaw                 []byte
}

func (a *PostgresAuthorizer) lockRecoveryAccountTx(
	ctx context.Context,
	tx *sql.Tx,
	accountID [16]byte,
) (persistedAccount, error) {
	var accountEpoch int64
	var irc []byte
	err := tx.QueryRowContext(ctx, `
SELECT account_epoch, irc
FROM accounts
WHERE account_id = $1::uuid
FOR UPDATE
`, uuidText(accountID)).Scan(&accountEpoch, &irc)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedAccount{}, ErrAccountNotFound
	}
	if err != nil {
		return persistedAccount{}, err
	}
	if accountEpoch < 1 || uint64(accountEpoch) > LifecycleWireV1MaxEpoch || len(irc) != 32 {
		return persistedAccount{}, ErrAuthorizationConflict
	}

	var authEpoch int64
	var commitmentBytes, publicBytes []byte
	var status int
	err = tx.QueryRowContext(ctx, `
SELECT epoch, recovery_commitment, recovery_pub, status
FROM authorization_accounts
WHERE account_id = $1::uuid
FOR UPDATE
`, uuidText(accountID)).Scan(&authEpoch, &commitmentBytes, &publicBytes, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	if err != nil {
		return persistedAccount{}, err
	}
	if authEpoch != accountEpoch || authEpoch < 1 || uint64(authEpoch) > LifecycleWireV1MaxEpoch ||
		len(commitmentBytes) != 32 || len(publicBytes) != 32 || !bytes.Equal(commitmentBytes, irc) ||
		(status != int(AccountActive) && status != int(AccountRecoveryLocked)) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	var commitment, recoveryPublic [32]byte
	copy(commitment[:], commitmentBytes)
	copy(recoveryPublic[:], publicBytes)
	if !VerifyRecoveryCommitment(commitment, recoveryPublic) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	return persistedAccount{
		Epoch:              uint64(authEpoch),
		RecoveryCommitment: commitment,
		RecoveryPub:        recoveryPublic,
		Status:             AccountStatus(status),
	}, nil
}

func loadRecoveryRequestTx(
	ctx context.Context,
	tx *sql.Tx,
	requestID [16]byte,
) (recoveryRequestRow, bool, error) {
	var accountBytes, digestBytes, targetBytes, enrollmentDigestBytes, abortingDeviceBytes []byte
	var raw, abortRaw, abortDigest []byte
	var oldEpoch, newEpoch int64
	var status string
	var acceptedAt, finalizeAfter time.Time
	var abortedAt, finalizedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `
SELECT uuid_send(account_id), request_digest, request_cbor,
       old_epoch, new_epoch, uuid_send(target_device_id),
       enrollment_certificate_digest, status, accepted_at, finalize_after,
       aborted_at,
       CASE WHEN aborting_device_id IS NULL THEN NULL ELSE uuid_send(aborting_device_id) END,
       abort_digest, abort_cbor, finalized_at
FROM account_recovery_requests
WHERE request_id = $1::uuid
FOR UPDATE
`, uuidText(requestID)).Scan(
		&accountBytes, &digestBytes, &raw, &oldEpoch, &newEpoch,
		&targetBytes, &enrollmentDigestBytes, &status, &acceptedAt, &finalizeAfter,
		&abortedAt, &abortingDeviceBytes, &abortDigest, &abortRaw, &finalizedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return recoveryRequestRow{}, false, nil
	}
	if err != nil {
		return recoveryRequestRow{}, false, err
	}
	if len(accountBytes) != 16 || len(digestBytes) != 32 || len(raw) == 0 ||
		len(targetBytes) != 16 || len(enrollmentDigestBytes) != 32 ||
		oldEpoch < 1 || uint64(oldEpoch) > LifecycleWireV1MaxEpoch ||
		newEpoch < 2 || uint64(newEpoch) > LifecycleWireV1MaxEpoch || newEpoch != oldEpoch+1 {
		return recoveryRequestRow{}, false, ErrAuthorizationConflict
	}
	if status != string(RecoveryRequestPending) && status != string(RecoveryRequestAborted) && status != string(RecoveryRequestFinalized) {
		return recoveryRequestRow{}, false, ErrAuthorizationConflict
	}
	if len(abortingDeviceBytes) != 0 && len(abortingDeviceBytes) != 16 {
		return recoveryRequestRow{}, false, ErrAuthorizationConflict
	}
	switch RecoveryRequestStatus(status) {
	case RecoveryRequestPending:
		if abortedAt.Valid || finalizedAt.Valid || len(abortingDeviceBytes) != 0 || len(abortDigest) != 0 || len(abortRaw) != 0 {
			return recoveryRequestRow{}, false, ErrAuthorizationConflict
		}
	case RecoveryRequestAborted:
		if !abortedAt.Valid || finalizedAt.Valid || len(abortingDeviceBytes) != 16 || len(abortDigest) != 32 || len(abortRaw) == 0 {
			return recoveryRequestRow{}, false, ErrAuthorizationConflict
		}
	case RecoveryRequestFinalized:
		if abortedAt.Valid || finalizedAt.Valid == false || len(abortingDeviceBytes) != 0 || len(abortDigest) != 0 || len(abortRaw) != 0 {
			return recoveryRequestRow{}, false, ErrAuthorizationConflict
		}
	}

	var row recoveryRequestRow
	copy(row.accountID[:], accountBytes)
	copy(row.state.RequestID[:], requestID[:])
	copy(row.state.RequestDigest[:], digestBytes)
	copy(row.targetDeviceID[:], targetBytes)
	copy(row.enrollmentCertificateSHA[:], enrollmentDigestBytes)
	row.raw = append([]byte(nil), raw...)
	row.oldEpoch, row.newEpoch = oldEpoch, newEpoch
	row.abortDigest = append([]byte(nil), abortDigest...)
	row.abortRaw = append([]byte(nil), abortRaw...)
	row.state.Status = RecoveryRequestStatus(status)
	row.state.AcceptedAt = acceptedAt
	row.state.FinalizeAfter = finalizeAfter
	if abortedAt.Valid {
		v := abortedAt.Time
		row.state.AbortedAt = &v
	}
	if finalizedAt.Valid {
		v := finalizedAt.Time
		row.state.FinalizedAt = &v
	}
	if len(abortingDeviceBytes) == 16 {
		copy(row.state.AbortingDeviceID[:], abortingDeviceBytes)
	}
	return row, true, nil
}

func verifyStoredRecoveryRequest(
	row recoveryRequestRow,
	accountID [16]byte,
	recoveryPublicKey [32]byte,
) (RecoveryRequestV1, error) {
	if row.accountID != accountID || sha256.Sum256(row.raw) != row.state.RequestDigest {
		return RecoveryRequestV1{}, ErrAuthorizationConflict
	}
	request, err := ParseRecoveryRequestV1(row.raw)
	if err != nil {
		return RecoveryRequestV1{}, ErrAuthorizationConflict
	}
	if request.AccountID != accountID || request.RequestID != row.state.RequestID ||
		request.OldEpoch != uint64(row.oldEpoch) || request.NewEpoch != uint64(row.newEpoch) ||
		request.TargetDeviceID != row.targetDeviceID ||
		request.EnrollmentCertDigest != row.enrollmentCertificateSHA {
		return RecoveryRequestV1{}, ErrAuthorizationConflict
	}
	if err := request.Verify(recoveryPublicKey); err != nil {
		return RecoveryRequestV1{}, ErrAuthorizationConflict
	}
	return request, nil
}

func hasPendingRecoveryTx(ctx context.Context, tx *sql.Tx, accountID [16]byte) (bool, error) {
	var pending bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM account_recovery_requests
    WHERE account_id = $1::uuid AND status = 'PENDING'
)
`, uuidText(accountID)).Scan(&pending)
	return pending, err
}

func hasPostgresSQLState(err error, state string) bool {
	type sqlStateError interface {
		SQLState() string
	}
	var coded sqlStateError
	return errors.As(err, &coded) && coded.SQLState() == state
}

// BeginRecovery verifies the recovery-signed request and enrollment certificate,
// checks the persisted recovery commitment, then records a DB-timed 48-hour request.
// Replaying the exact request returns its existing state; conflicting requests fail.
func (a *PostgresAuthorizer) BeginRecovery(
	ctx context.Context,
	requestRaw []byte,
	enrollmentCertificateRaw []byte,
	recoveryPublicKey [32]byte,
) (RecoveryRequestState, error) {
	if err := a.valid(); err != nil {
		return RecoveryRequestState{}, err
	}
	request, err := ParseRecoveryRequestV1(requestRaw)
	if err != nil {
		return RecoveryRequestState{}, ErrInvalidAuthorization
	}
	if _, err := parseCandidateEnrollmentCertificate(enrollmentCertificateRaw, recoveryPublicKey); err != nil {
		return RecoveryRequestState{}, err
	}
	if err := request.VerifyForEnrollment(recoveryPublicKey, enrollmentCertificateRaw); err != nil {
		return RecoveryRequestState{}, ErrInvalidAuthorization
	}
	requestDigest := request.Digest()

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	defer tx.Rollback()

	account, err := a.lockExistingCandidateEnrollmentAccountTx(ctx, tx, request.AccountID, recoveryPublicKey)
	if err != nil {
		return RecoveryRequestState{}, err
	}

	// The request ID is globally unique. Check it before current account status
	// so exact retries remain idempotent after abort/finalization.
	if existing, found, err := loadRecoveryRequestTx(ctx, tx, request.RequestID); err != nil {
		return RecoveryRequestState{}, err
	} else if found {
		if existing.accountID != request.AccountID || existing.state.RequestDigest != requestDigest ||
			!bytes.Equal(existing.raw, requestRaw) {
			return RecoveryRequestState{}, ErrAuthorizationConflict
		}
		if _, err := verifyStoredRecoveryRequest(existing, request.AccountID, recoveryPublicKey); err != nil {
			return RecoveryRequestState{}, err
		}
		if err := tx.Commit(); err != nil {
			return RecoveryRequestState{}, err
		}
		return existing.state, nil
	}

	if account.Status != AccountActive {
		return RecoveryRequestState{}, ErrAccountLocked
	}
	if account.Epoch != request.OldEpoch {
		return RecoveryRequestState{}, ErrInvalidEpoch
	}
	pending, err := hasPendingRecoveryTx(ctx, tx, request.AccountID)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if pending {
		return RecoveryRequestState{}, ErrRecoveryPending
	}
	var targetExists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM devices WHERE device_id = $1::uuid)
    OR EXISTS (SELECT 1 FROM authorization_devices WHERE device_id = $1::uuid)
`, uuidText(request.TargetDeviceID)).Scan(&targetExists); err != nil {
		return RecoveryRequestState{}, err
	}
	if targetExists {
		return RecoveryRequestState{}, ErrDeviceExists
	}

	// Invalidate any outstanding ordinary-enrollment challenges before accepting
	// recovery. Account-first locking serializes this with challenge issuance and use.
	if _, err := tx.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = COALESCE(consumed_at, clock_timestamp())
WHERE account_id = $1::uuid AND consumed_at IS NULL
`, uuidText(request.AccountID)); err != nil {
		return RecoveryRequestState{}, err
	}

	var state RecoveryRequestState
	state.RequestID = request.RequestID
	state.RequestDigest = requestDigest
	state.Status = RecoveryRequestPending
	err = tx.QueryRowContext(ctx, `
INSERT INTO account_recovery_requests (
    request_id, account_id, request_digest, request_cbor,
    old_epoch, new_epoch, target_device_id, enrollment_certificate_digest
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::uuid, $8)
RETURNING accepted_at, finalize_after
`, uuidText(request.RequestID), uuidText(request.AccountID), requestDigest[:], requestRaw,
		int64(request.OldEpoch), int64(request.NewEpoch), uuidText(request.TargetDeviceID),
		request.EnrollmentCertDigest[:]).Scan(&state.AcceptedAt, &state.FinalizeAfter)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if err := tx.Commit(); err != nil {
		return RecoveryRequestState{}, err
	}
	return state, nil
}

// AbortRecovery accepts a DSK-signed abort only while the request is pending,
// the aborting device is active at the request's old epoch, and DB time is
// strictly before finalize_after. The account and request locks serialize it
// against finalization.
func (a *PostgresAuthorizer) AbortRecovery(ctx context.Context, abortRaw []byte) (RecoveryRequestState, error) {
	if err := a.valid(); err != nil {
		return RecoveryRequestState{}, err
	}
	abort, err := ParseRecoveryAbortV1(abortRaw)
	if err != nil {
		return RecoveryRequestState{}, ErrInvalidAuthorization
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	defer tx.Rollback()

	account, err := a.lockRecoveryAccountTx(ctx, tx, abort.AccountID)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	row, found, err := loadRecoveryRequestTx(ctx, tx, abort.RequestID)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if !found || row.accountID != abort.AccountID {
		return RecoveryRequestState{}, ErrRecoveryRequestNotFound
	}
	request, err := verifyStoredRecoveryRequest(row, abort.AccountID, account.RecoveryPub)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if abort.RecoveryRequestDigest != row.state.RequestDigest || abort.AccountID != request.AccountID ||
		abort.OldEpoch != request.OldEpoch || abort.NewEpoch != request.NewEpoch || abort.RequestID != request.RequestID {
		return RecoveryRequestState{}, ErrInvalidAuthorization
	}
	if row.state.Status == RecoveryRequestFinalized {
		return RecoveryRequestState{}, ErrRecoveryFinalized
	}

	var deviceStatus int
	var authorizedEpoch int64
	var dskPublic, ddhkPublic []byte
	err = tx.QueryRowContext(ctx, `
SELECT status, authorized_epoch, dsk_pub, ddhk_pub
FROM authorization_devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR UPDATE
`, uuidText(abort.AccountID), uuidText(abort.DeviceID)).Scan(
		&deviceStatus, &authorizedEpoch, &dskPublic, &ddhkPublic,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryRequestState{}, ErrDeviceNotFound
	}
	if err != nil {
		return RecoveryRequestState{}, err
	}
	var deviceEpoch int64
	var deviceDSKPublic, deviceDDHKPublic []byte
	var revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT account_epoch, dsk_pub, ddhk_pub, revoked_at
FROM devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR UPDATE
`, uuidText(abort.AccountID), uuidText(abort.DeviceID)).Scan(
		&deviceEpoch, &deviceDSKPublic, &deviceDDHKPublic, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryRequestState{}, ErrDeviceNotFound
	}
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if len(dskPublic) != 32 || len(ddhkPublic) != 32 ||
		!bytes.Equal(dskPublic, deviceDSKPublic) || !bytes.Equal(ddhkPublic, deviceDDHKPublic) {
		return RecoveryRequestState{}, ErrAuthorizationConflict
	}
	var dsk [32]byte
	copy(dsk[:], dskPublic)
	if err := abort.VerifyForRequest(account.RecoveryPub, dsk, row.raw); err != nil {
		return RecoveryRequestState{}, ErrInvalidAuthorization
	}

	if row.state.Status == RecoveryRequestAborted {
		replayDigest := abort.Digest()
		if row.state.AbortingDeviceID != abort.DeviceID || len(row.abortDigest) != 32 ||
			!bytes.Equal(row.abortDigest, replayDigest[:]) || !bytes.Equal(row.abortRaw, abortRaw) {
			return RecoveryRequestState{}, ErrAuthorizationConflict
		}
		if err := tx.Commit(); err != nil {
			return RecoveryRequestState{}, err
		}
		return row.state, nil
	}
	if row.state.Status != RecoveryRequestPending {
		return RecoveryRequestState{}, ErrAuthorizationConflict
	}
	if account.Status != AccountActive {
		return RecoveryRequestState{}, ErrAccountLocked
	}
	if account.Epoch != request.OldEpoch || authorizedEpoch != int64(request.OldEpoch) || deviceEpoch != int64(request.OldEpoch) {
		return RecoveryRequestState{}, ErrInvalidEpoch
	}
	if deviceStatus != int(DeviceActive) || revokedAt.Valid {
		return RecoveryRequestState{}, ErrDeviceRevoked
	}

	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return RecoveryRequestState{}, err
	}
	if !databaseNow.Before(row.state.FinalizeAfter) {
		return RecoveryRequestState{}, ErrRecoveryAbortWindowClosed
	}

	abortDigest := abort.Digest()
	var abortedAt time.Time
	err = tx.QueryRowContext(ctx, `
UPDATE account_recovery_requests
SET status = 'ABORTED', aborting_device_id = $2::uuid,
    abort_digest = $3, abort_cbor = $4
WHERE request_id = $1::uuid AND status = 'PENDING'
RETURNING aborted_at
`, uuidText(abort.RequestID), uuidText(abort.DeviceID), abortDigest[:], abortRaw).Scan(&abortedAt)
	if err != nil {
		if hasPostgresSQLState(err, "55000") {
			return RecoveryRequestState{}, ErrRecoveryAbortWindowClosed
		}
		return RecoveryRequestState{}, err
	}
	row.state.Status = RecoveryRequestAborted
	row.state.AbortedAt = &abortedAt
	row.state.AbortingDeviceID = abort.DeviceID
	if err := tx.Commit(); err != nil {
		return RecoveryRequestState{}, err
	}
	return row.state, nil
}

// FinalizeRecovery commits the account epoch advance, revokes every currently
// active device, locks the account, writes the immutable authorization event,
// and marks the request finalized in one transaction. It is safe to retry.
func (a *PostgresAuthorizer) FinalizeRecovery(
	ctx context.Context,
	accountID, requestID [16]byte,
) (RecoveryRequestState, error) {
	if err := a.valid(); err != nil {
		return RecoveryRequestState{}, err
	}
	if accountID == [16]byte{} || requestID == [16]byte{} {
		return RecoveryRequestState{}, ErrInvalidAuthorization
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	defer tx.Rollback()

	account, err := a.lockRecoveryAccountTx(ctx, tx, accountID)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	row, found, err := loadRecoveryRequestTx(ctx, tx, requestID)
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if !found || row.accountID != accountID {
		return RecoveryRequestState{}, ErrRecoveryRequestNotFound
	}
	request, err := verifyStoredRecoveryRequest(row, accountID, account.RecoveryPub)
	if err != nil {
		return RecoveryRequestState{}, err
	}

	if row.state.Status == RecoveryRequestAborted {
		return RecoveryRequestState{}, ErrRecoveryAborted
	}
	if row.state.Status == RecoveryRequestFinalized {
		if account.Epoch < request.NewEpoch {
			return RecoveryRequestState{}, ErrAuthorizationConflict
		}
		var eventMatches bool
		err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM authorization_events
    WHERE auth_digest = $1 AND kind = 'TRANSITION'
      AND account_id = $2::uuid AND old_epoch = $3 AND new_epoch = $4
      AND target_device_id = $5::uuid AND cert_cbor = $6
)
`, row.state.RequestDigest[:], uuidText(accountID), int64(request.OldEpoch),
			int64(request.NewEpoch), uuidText(request.TargetDeviceID), row.raw).Scan(&eventMatches)
		if err != nil {
			return RecoveryRequestState{}, err
		}
		if !eventMatches {
			return RecoveryRequestState{}, ErrAuthorizationConflict
		}
		if err := tx.Commit(); err != nil {
			return RecoveryRequestState{}, err
		}
		return row.state, nil
	}
	if row.state.Status != RecoveryRequestPending {
		return RecoveryRequestState{}, ErrAuthorizationConflict
	}
	if account.Status != AccountActive || account.Epoch != request.OldEpoch {
		return RecoveryRequestState{}, ErrInvalidEpoch
	}

	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return RecoveryRequestState{}, err
	}
	if databaseNow.Before(row.state.FinalizeAfter) {
		return RecoveryRequestState{}, ErrRecoveryNotReady
	}

	// The database trigger independently rechecks the deadline after this row
	// is locked. This update is the terminal-state serialization point.
	var finalizedAt time.Time
	err = tx.QueryRowContext(ctx, `
UPDATE account_recovery_requests
SET status = 'FINALIZED'
WHERE request_id = $1::uuid AND status = 'PENDING'
RETURNING finalized_at
`, uuidText(requestID)).Scan(&finalizedAt)
	if err != nil {
		if hasPostgresSQLState(err, "55000") {
			return RecoveryRequestState{}, ErrRecoveryNotReady
		}
		return RecoveryRequestState{}, err
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE authorization_devices
SET status = 2, revoked_epoch = $2, updated_at = clock_timestamp()
WHERE account_id = $1::uuid AND status = 1
`, uuidText(accountID), int64(request.NewEpoch)); err != nil {
		return RecoveryRequestState{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE devices d
SET account_epoch = $2,
    revoked_at = COALESCE(d.revoked_at, clock_timestamp())
FROM authorization_devices ad
WHERE ad.device_id = d.device_id AND ad.account_id = $1::uuid AND ad.status = 2
`, uuidText(accountID), int64(request.NewEpoch)); err != nil {
		return RecoveryRequestState{}, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE accounts SET account_epoch = $2
WHERE account_id = $1::uuid AND account_epoch = $3
`, uuidText(accountID), int64(request.NewEpoch), int64(request.OldEpoch))
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return RecoveryRequestState{}, ErrAuthorizationConflict
	}
	result, err = tx.ExecContext(ctx, `
UPDATE authorization_accounts
SET epoch = $2, status = 2, updated_at = clock_timestamp()
WHERE account_id = $1::uuid AND epoch = $3 AND status = 1
`, uuidText(accountID), int64(request.NewEpoch), int64(request.OldEpoch))
	if err != nil {
		return RecoveryRequestState{}, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return RecoveryRequestState{}, ErrAuthorizationConflict
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO authorization_events (
    auth_digest, kind, account_id, old_epoch, new_epoch, target_device_id, cert_cbor
) VALUES ($1, 'TRANSITION', $2::uuid, $3, $4, $5::uuid, $6)
`, row.state.RequestDigest[:], uuidText(accountID), int64(request.OldEpoch),
		int64(request.NewEpoch), uuidText(request.TargetDeviceID), row.raw); err != nil {
		return RecoveryRequestState{}, err
	}

	row.state.Status = RecoveryRequestFinalized
	row.state.FinalizedAt = &finalizedAt
	if err := tx.Commit(); err != nil {
		return RecoveryRequestState{}, err
	}
	return row.state, nil
}
