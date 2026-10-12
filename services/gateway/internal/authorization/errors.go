package authorization

import "errors"

var (
	ErrNilAuthorizer          = errors.New("authorization: nil authorizer")
	ErrAccountNotFound        = errors.New("authorization: account not found")
	ErrAccountExists          = errors.New("authorization: account already initialized")
	ErrAccountLocked          = errors.New("authorization: account is recovery-locked")
	ErrDeviceExists           = errors.New("authorization: device already authorized")
	ErrDeviceNotFound         = errors.New("authorization: device not authorized")
	ErrDeviceRevoked          = errors.New("authorization: device is revoked")
	ErrInvalidEpoch           = errors.New("authorization: invalid epoch")
	ErrInvalidAuthorization   = errors.New("authorization: invalid authorization")
	ErrAuthorizationConflict  = errors.New("authorization: authorization conflict")
	ErrDuplicateAuthorization = errors.New("authorization: authorization already applied")
)
