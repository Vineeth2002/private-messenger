package kt

import (
	"context"
	"testing"
)

type testDeviceStateReader struct {
	state DeviceState
	err   error
}

func (r testDeviceStateReader) DeviceState(context.Context, [16]byte, [16]byte) (DeviceState, error) {
	if r.err != nil {
		return DeviceState{}, r.err
	}
	return r.state, nil
}

func TestValidateTransparencyLeafAgainstDevice(t *testing.T) {
	var account, device [16]byte
	account[0] = 1
	device[0] = 2

	var dsk, ddhk [32]byte
	dsk[0] = 3
	ddhk[0] = 4

	leaf := TransparencyLeafV1{
		AccountID: account,
		Epoch:     7,
		DeviceID:  device,
		DSKPub:    dsk,
		DDHKPub:   ddhk,
	}
	reader := testDeviceStateReader{state: DeviceState{
		AccountID:    account,
		DeviceID:     device,
		AccountEpoch: 7,
		DSKPub:       dsk,
		DDHKPub:      ddhk,
	}}
	if err := ValidateTransparencyLeafAgainstDevice(context.Background(), reader, leaf); err != nil {
		t.Fatal(err)
	}

	reader.state.AccountEpoch++
	if err := ValidateTransparencyLeafAgainstDevice(context.Background(), reader, leaf); err != ErrDeviceStateMismatch {
		t.Fatalf("epoch mismatch err = %v", err)
	}
}

func TestValidateTransparencyLeafRejectsRevokedDevice(t *testing.T) {
	var account, device [16]byte
	reader := testDeviceStateReader{state: DeviceState{
		AccountID: account,
		DeviceID:  device,
		Revoked:   true,
	}}
	leaf := TransparencyLeafV1{AccountID: account, DeviceID: device, Epoch: 1}
	if err := ValidateTransparencyLeafAgainstDevice(context.Background(), reader, leaf); err != ErrDeviceRevoked {
		t.Fatalf("revoked device err = %v", err)
	}
}
