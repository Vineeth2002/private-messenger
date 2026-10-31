package authorization

import "errors"

var (
	ErrNilAuthorizer               = errors.New("authorization: nil authorizer")
	ErrAccountNotFound             = errors.New("authorization: account not found")
	ErrAccountExists               = errors.New("authorization: account already initialized")
	ErrAccountLocked               = errors.New("authorization: account is recovery-locked")
	ErrDeviceExists                = errors.New("authorization: device already authorized")
	ErrDeviceNotFound              = errors.New("authorization: device not authorized")
	ErrDeviceRevoked               = errors.New("authorization: device is revoked")
	ErrInvalidEpoch                = errors.New("authorization: invalid epoch")
	ErrInvalidAuthorization        = errors.New("authorization: invalid authorization")
	ErrAuthorizationConflict       = errors.New("authorization: authorization conflict")
	ErrDuplicateAuthorization      = errors.New("authorization: authorization already applied")
	ErrEnrollmentProofRequired     = errors.New("authorization: proof of possession is required before activation")
	ErrEnrollmentChallengeNotFound = errors.New("authorization: enrollment challenge not found")
	ErrEnrollmentChallengeExpired  = errors.New("authorization: enrollment challenge expired")
	ErrEnrollmentChallengeConsumed = errors.New("authorization: enrollment challenge already consumed")
	ErrRecoveryRequestNotFound     = errors.New("authorization: recovery request not found")
	ErrRecoveryPending             = errors.New("authorization: another recovery request is pending")
	ErrRecoveryNotReady            = errors.New("authorization: recovery request is not yet eligible for finalization")
	ErrRecoveryAbortWindowClosed   = errors.New("authorization: recovery abort window has closed")
	ErrRecoveryAborted             = errors.New("authorization: recovery request was aborted")
	ErrRecoveryFinalized           = errors.New("authorization: recovery request was already finalized")
)
