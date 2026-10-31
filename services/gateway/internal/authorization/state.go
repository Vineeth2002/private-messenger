package authorization

import (
	"sync"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

type AccountStatus uint8

const (
	AccountActive AccountStatus = iota + 1
	AccountRecoveryLocked
)

type DeviceStatus uint8

const (
	DeviceActive DeviceStatus = iota + 1
	DeviceRevoked
)

type Account struct {
	ID                 [16]byte
	Epoch              uint64
	RecoveryCommitment [32]byte
	RecoveryPub        [32]byte
	Status             AccountStatus
}

type Device struct {
	AccountID            [16]byte
	ID                   [16]byte
	DSKPub               [32]byte
	DDHKPub              [32]byte
	Status               DeviceStatus
	AuthorizedEpoch      uint64
	EnrollmentAuthDigest [32]byte
	RevokedEpoch         uint64
}

type Authorizer struct {
	mu                 sync.RWMutex
	accounts           map[[16]byte]Account
	devices            map[[32]byte]Device
	enrollmentByDigest map[[32]byte]struct{}
	transitions        map[[48]byte][32]byte
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{accounts: map[[16]byte]Account{}, devices: map[[32]byte]Device{}, enrollmentByDigest: map[[32]byte]struct{}{}, transitions: map[[48]byte][32]byte{}}
}
func stateDeviceKey(accountID, deviceID [16]byte) [32]byte {
	var k [32]byte
	copy(k[:16], accountID[:])
	copy(k[16:], deviceID[:])
	return k
}
func stateTransitionKey(accountID [16]byte, oldEpoch uint64, deviceID [16]byte) [48]byte {
	var k [48]byte
	copy(k[:16], accountID[:])
	for i := 0; i < 8; i++ {
		k[16+i] = byte(oldEpoch >> (56 - 8*i))
	}
	copy(k[24:], deviceID[:])
	return k
}

// EnsureAccount initializes or verifies the account authority binding.
func (a *Authorizer) EnsureAccount(accountID [16]byte, epoch uint64, commitment, recoveryPub [32]byte) error {
	if a == nil {
		return ErrNilAuthorizer
	}
	if accountID == [16]byte{} || epoch == 0 || epoch > LifecycleWireV1MaxEpoch ||
		!VerifyRecoveryCommitment(commitment, recoveryPub) {
		return ErrInvalidAuthorization
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.accounts[accountID]; ok {
		if existing.Epoch != epoch || existing.RecoveryCommitment != commitment || existing.RecoveryPub != recoveryPub {
			return ErrAuthorizationConflict
		}
		return nil
	}
	a.accounts[accountID] = Account{ID: accountID, Epoch: epoch, RecoveryCommitment: commitment, RecoveryPub: recoveryPub, Status: AccountActive}
	return nil
}

func (a *Authorizer) Account(accountID [16]byte) (Account, bool) {
	if a == nil {
		return Account{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	v, ok := a.accounts[accountID]
	return v, ok
}
func (a *Authorizer) Device(accountID, deviceID [16]byte) (Device, bool) {
	if a == nil {
		return Device{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	v, ok := a.devices[stateDeviceKey(accountID, deviceID)]
	return v, ok
}

func (a *Authorizer) Enroll(cert DeviceEnrollmentAuthorizationV1, recoveryPub [32]byte) error {
	if a == nil {
		return ErrNilAuthorizer
	}
	digest := cert.Digest()
	if err := cert.Verify(recoveryPub); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	account, ok := a.accounts[cert.AccountID]
	if !ok {
		return ErrAccountNotFound
	}
	if account.RecoveryPub != recoveryPub {
		return ErrAuthorizationConflict
	}
	if _, ok := a.enrollmentByDigest[digest]; ok {
		return nil
	}
	if account.Status != AccountActive {
		return ErrAccountLocked
	}
	if account.Epoch != cert.Epoch {
		return ErrInvalidEpoch
	}
	key := stateDeviceKey(cert.AccountID, cert.DeviceID)
	if existing, ok := a.devices[key]; ok {
		if existing.Status == DeviceRevoked {
			return ErrDeviceRevoked
		}
		return ErrDeviceExists
	}
	a.devices[key] = Device{AccountID: cert.AccountID, ID: cert.DeviceID, DSKPub: cert.DSKPub, DDHKPub: cert.DDHKPub, Status: DeviceActive, AuthorizedEpoch: cert.Epoch, EnrollmentAuthDigest: digest}
	a.enrollmentByDigest[digest] = struct{}{}
	return nil
}

func (a *Authorizer) Revoke(cert EpochTransitionAuthorizationV1, recoveryPub [32]byte) error {
	return a.applyRevoke(cert, recoveryPub)
}

// RecoveryReset is retained as a compatibility shim for callers of the old
// immediate-reset API. It deliberately rejects all requests: account recovery
// must use the durable RecoveryRequestV1 flow and its 48-hour delay.
func (a *Authorizer) RecoveryReset(cert EpochTransitionAuthorizationV1, recoveryPub [32]byte) error {
	if a == nil {
		return ErrNilAuthorizer
	}
	return ErrInvalidAuthorization
}

func (a *Authorizer) applyRevoke(cert EpochTransitionAuthorizationV1, recoveryPub [32]byte) error {
	if a == nil {
		return ErrNilAuthorizer
	}
	if err := cert.Verify(recoveryPub); err != nil {
		return err
	}
	if cert.Action != RevokeDeviceAction {
		return ErrInvalidAuthorization
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	account, ok := a.accounts[cert.AccountID]
	if !ok {
		return ErrAccountNotFound
	}
	if account.RecoveryPub != recoveryPub {
		return ErrAuthorizationConflict
	}
	logical := stateTransitionKey(cert.AccountID, cert.OldEpoch, cert.DeviceID)
	if prior, ok := a.transitions[logical]; ok {
		if prior == cert.Digest() {
			return nil
		}
		return ErrAuthorizationConflict
	}
	if account.Epoch != cert.OldEpoch {
		return ErrInvalidEpoch
	}
	newEpoch := cert.NewEpoch
	key := stateDeviceKey(cert.AccountID, cert.DeviceID)
	target, ok := a.devices[key]
	if !ok {
		return ErrDeviceNotFound
	}
	if target.Status != DeviceActive {
		return ErrDeviceRevoked
	}
	target.Status = DeviceRevoked
	target.RevokedEpoch = newEpoch
	a.devices[key] = target
	for key, device := range a.devices {
		if device.AccountID != cert.AccountID || device.Status != DeviceActive {
			continue
		}
		device.AuthorizedEpoch = newEpoch
		a.devices[key] = device
	}
	account.Epoch = newEpoch
	account.Status = AccountActive
	a.accounts[cert.AccountID] = account
	a.transitions[logical] = cert.Digest()
	return nil
}

func (a *Authorizer) ValidateLeaf(leaf kt.TransparencyLeafV1) error {
	if a == nil {
		return ErrNilAuthorizer
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	account, ok := a.accounts[leaf.AccountID]
	if !ok {
		return ErrAccountNotFound
	}
	if account.Status != AccountActive {
		return ErrAccountLocked
	}
	device, ok := a.devices[stateDeviceKey(leaf.AccountID, leaf.DeviceID)]
	if !ok {
		return ErrDeviceNotFound
	}
	if device.Status != DeviceActive {
		return ErrDeviceRevoked
	}
	if leaf.Epoch == 0 || leaf.Epoch > LifecycleWireV1MaxEpoch ||
		account.Epoch == 0 || account.Epoch > LifecycleWireV1MaxEpoch ||
		device.AuthorizedEpoch == 0 || device.AuthorizedEpoch > LifecycleWireV1MaxEpoch ||
		device.AuthorizedEpoch != leaf.Epoch || account.Epoch != leaf.Epoch {
		return ErrInvalidEpoch
	}
	if device.DSKPub != leaf.DSKPub || device.DDHKPub != leaf.DDHKPub {
		return ErrAuthorizationConflict
	}
	return nil
}
