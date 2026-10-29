package authorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const DeviceEnrollmentPoPDomain = "PM-V1-DEVICE-POP-v1"

// DeviceEnrollmentPoPV1 is a wire-format candidate only. A valid proof does not
// authorize activation, prove challenge freshness, or consume a challenge.
type DeviceEnrollmentPoPV1 struct {
	Raw                         []byte
	AccountID                   [16]byte
	DeviceID                    [16]byte
	Epoch                       uint64
	EnrollmentCertificateDigest [32]byte
	ChallengeID                 [16]byte
	ChallengeNonce              [32]byte
	Signature                   [64]byte
}

func (p DeviceEnrollmentPoPV1) Digest() [32]byte { return sha256.Sum256(p.Raw) }

func validateDeviceEnrollmentPoPFields(accountID, deviceID, challengeID [16]byte, epoch uint64) error {
	if accountID == [16]byte{} || deviceID == [16]byte{} || challengeID == [16]byte{} {
		return ErrInvalidAuthorization
	}
	if epoch == 0 || epoch > LifecycleWireV1MaxEpoch {
		return ErrInvalidEpoch
	}
	return nil
}

func (p DeviceEnrollmentPoPV1) canonicalCore() ([]byte, error) {
	if err := validateDeviceEnrollmentPoPFields(p.AccountID, p.DeviceID, p.ChallengeID, p.Epoch); err != nil {
		return nil, err
	}
	return cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, p.AccountID[:]),
		bytesPair(3, p.DeviceID[:]),
		uintPair(4, p.Epoch),
		bytesPair(5, p.EnrollmentCertificateDigest[:]),
		bytesPair(6, p.ChallengeID[:]),
		bytesPair(7, p.ChallengeNonce[:]),
	}})
}

// ParseDeviceEnrollmentPoPV1 strictly parses the exact 8-field candidate map.
func ParseDeviceEnrollmentPoPV1(raw []byte) (DeviceEnrollmentPoPV1, error) {
	fields, err := decodeMap(raw)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	if err := requireFields(fields, 1, 2, 3, 4, 5, 6, 7, 8); err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	version, err := takeUint(fields, 1)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	if version != AuthorizationProtocolVersion {
		return DeviceEnrollmentPoPV1{}, fmt.Errorf("authorization: unsupported device enrollment PoP version %d", version)
	}
	accountID, err := takeFixed16(fields, 2)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	deviceID, err := takeFixed16(fields, 3)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	epoch, err := takeUint(fields, 4)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	enrollmentDigest, err := takeFixed32(fields, 5)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	challengeID, err := takeFixed16(fields, 6)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	challengeNonce, err := takeBytes(fields, 7)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	if len(challengeNonce) != 32 {
		return DeviceEnrollmentPoPV1{}, fmt.Errorf("authorization: challenge nonce must be bstr(32)")
	}
	signature, err := takeFixed64(fields, 8)
	if err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	if err := validateDeviceEnrollmentPoPFields(accountID, deviceID, challengeID, epoch); err != nil {
		return DeviceEnrollmentPoPV1{}, err
	}
	var nonce [32]byte
	copy(nonce[:], challengeNonce)
	return DeviceEnrollmentPoPV1{
		Raw: append([]byte(nil), raw...), AccountID: accountID, DeviceID: deviceID, Epoch: epoch,
		EnrollmentCertificateDigest: enrollmentDigest, ChallengeID: challengeID,
		ChallengeNonce: nonce, Signature: signature,
	}, nil
}

// Verify checks the DSK signature. The public key must be taken from a separately
// verified enrollment certificate, not from caller-supplied proof data.
func (p DeviceEnrollmentPoPV1) Verify(deviceSigningPub [32]byte) error {
	if len(p.Raw) == 0 {
		return ErrInvalidAuthorization
	}
	core, err := p.canonicalCore()
	if err != nil {
		return err
	}
	message := append([]byte(DeviceEnrollmentPoPDomain), core...)
	if !ed25519.Verify(ed25519.PublicKey(deviceSigningPub[:]), message, p.Signature[:]) {
		return ErrInvalidAuthorization
	}
	return nil
}

// VerifyForEnrollmentAndChallenge verifies the recovery-signed enrollment, exact
// complete certificate digest, certificate/account/device/epoch binding, and DSK
// proof signature. expectedChallengeID/Nonce MUST come from authoritative server
// storage; this helper does not establish expiry, freshness, single-use, or activation.
func (p DeviceEnrollmentPoPV1) VerifyForEnrollmentAndChallenge(
	recoveryPub [32]byte,
	enrollmentRaw []byte,
	expectedChallengeID [16]byte,
	expectedChallengeNonce [32]byte,
) error {
	if len(p.Raw) == 0 {
		return ErrInvalidAuthorization
	}
	enrollment, err := ParseDeviceEnrollmentAuthorizationV1(enrollmentRaw)
	if err != nil {
		return err
	}
	if err := enrollment.Verify(recoveryPub); err != nil {
		return err
	}
	exactDigest := sha256.Sum256(enrollmentRaw)
	if exactDigest != p.EnrollmentCertificateDigest || p.AccountID != enrollment.AccountID ||
		p.DeviceID != enrollment.DeviceID || p.Epoch != enrollment.Epoch ||
		p.ChallengeID != expectedChallengeID || p.ChallengeNonce != expectedChallengeNonce {
		return ErrInvalidAuthorization
	}
	return p.Verify(enrollment.DSKPub)
}
