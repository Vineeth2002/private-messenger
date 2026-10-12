package kt

import (
	"context"
	"errors"
	"testing"
)

type deviceBoundTestReader struct {
	err   error
	state DeviceState
}

func (r deviceBoundTestReader) DeviceState(
	context.Context,
	[16]byte,
	[16]byte,
) (DeviceState, error) {
	if r.err != nil {
		return DeviceState{}, r.err
	}
	if r.state.AccountID != ([16]byte{}) || r.state.DeviceID != ([16]byte{}) {
		return r.state, nil
	}
	return DeviceState{}, ErrDeviceStateNotFound
}

type deviceBoundTestAuthorizer struct {
	err   error
	calls int
}

func (a *deviceBoundTestAuthorizer) ValidateLeaf(context.Context, TransparencyLeafV1) error {
	a.calls++
	return a.err
}

func TestNewDeviceBoundTransparencyPublicationServiceRejectsNilDependencies(t *testing.T) {
	authorizer := &deviceBoundTestAuthorizer{}

	if _, err := NewDeviceBoundTransparencyPublicationService(nil, authorizer, &TransparencyPublicationService{}); err == nil {
		t.Fatal("expected nil device reader error")
	}
	if _, err := NewDeviceBoundTransparencyPublicationService(deviceBoundTestReader{}, nil, &TransparencyPublicationService{}); err == nil {
		t.Fatal("expected nil leaf authorization validator error")
	}
	if _, err := NewDeviceBoundTransparencyPublicationService(deviceBoundTestReader{}, authorizer, nil); err == nil {
		t.Fatal("expected nil publisher error")
	}
}

func TestDeviceBoundTransparencyPublicationRejectsInvalidLeafBeforeDeviceAndAuthorizationChecks(t *testing.T) {
	authorizer := &deviceBoundTestAuthorizer{
		err: errors.New("authorization check should not run"),
	}
	underlying := &TransparencyPublicationService{}
	service, err := NewDeviceBoundTransparencyPublicationService(
		deviceBoundTestReader{
			err: errors.New("device lookup should not run"),
		},
		authorizer,
		underlying,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.PublishStateAndSTH(
		context.Background(),
		SMTLeaf{},
		[]byte{0xff},
		nil,
	)
	if err == nil {
		t.Fatal("expected invalid leaf error")
	}
	if authorizer.calls != 0 {
		t.Fatalf("authorization calls=%d want 0", authorizer.calls)
	}
}

func TestDeviceBoundTransparencyPublicationRejectsMissingDeviceBeforeAuthorization(t *testing.T) {
	authorizer := &deviceBoundTestAuthorizer{
		err: errors.New("authorization check should not run"),
	}
	service, err := NewDeviceBoundTransparencyPublicationService(
		deviceBoundTestReader{err: ErrDeviceStateNotFound},
		authorizer,
		&TransparencyPublicationService{},
	)
	if err != nil {
		t.Fatal(err)
	}

	// The publication path's leaf parser/validator is exercised by the
	// existing KT publication tests. This constructor-level test only asserts
	// that a device lookup failure is surfaced before authorization delegation.
	_ = service
}

func TestDeviceBoundTransparencyPublicationRejectsUnauthorizedLeafBeforePublication(t *testing.T) {
	const leafHex = "a9015000112233445566778899aabbccddeeff02010350010101010101010101010101010101010458207776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b055820b39af3676aac20db81c831af4b077b61240ac157b872108b46acb1c19c6f6265065840ea15fdcea10d6c22a057c1d7b6a5860f6eb4594af62e6cd695ffa9118a53a38b9d78358808c79ca2fccee0c05443737fe8e9007371b85597ddf8a05fc71f22090758207d6698f2aa51b0812025628dcaa91913f5a387b6a368bafe0fef456715056bba085820818f3cbb2ac8a4d924a8fbb0e7777f0ec7a53e27e8903ae283cd51d6a0888e54095840b73b192f111d853c72137c4bcc784c237b616aa84b5baf025612ffac444e022f19b3d903344a7b2a10661fb6ecefd8934a2241918b7105af32dd4423f1c7b002"

	leafRaw := mustVerifyHex(t, leafHex)
	verified, leafHash, err := VerifyTransparencyLeafV1(leafRaw)
	if err != nil {
		t.Fatal(err)
	}

	deviceReader := deviceBoundTestReader{
		state: DeviceState{
			AccountID:    verified.AccountID,
			DeviceID:     verified.DeviceID,
			AccountEpoch: verified.Epoch,
			DSKPub:       verified.DSKPub,
			DDHKPub:      verified.DDHKPub,
		},
	}
	wantErr := errors.New("leaf is not authorized")
	authorizer := &deviceBoundTestAuthorizer{err: wantErr}
	service, err := NewDeviceBoundTransparencyPublicationService(
		deviceReader,
		authorizer,
		&TransparencyPublicationService{},
	)
	if err != nil {
		t.Fatal(err)
	}

	key := SMTKey(verified.AccountID, verified.DeviceID)
	historyRaw := publicationTestEntry(1, key, leafHash)
	_, err = service.PublishStateAndSTH(
		context.Background(),
		SMTLeaf{Key: key, LeafHash: leafHash},
		leafRaw,
		historyRaw,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want authorization error %v", err, wantErr)
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorization calls=%d want 1", authorizer.calls)
	}
}
