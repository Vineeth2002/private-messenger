package gwhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/devices"
)

type memoryDeviceDirectory struct {
	devices map[[16]byte]devices.Device
	certs   map[[16]byte][]devices.DeviceCertificate
	keys    map[[16]byte][]devices.SignedPrekey
}

func (m *memoryDeviceDirectory) Get(_ context.Context, accountID, deviceID [16]byte) (devices.Device, error) {
	d, ok := m.devices[deviceID]
	if !ok || d.AccountID != accountID {
		return devices.Device{}, devices.ErrNotFound
	}
	return d, nil
}

func (m *memoryDeviceDirectory) ListActive(_ context.Context, accountID [16]byte) ([]devices.Device, error) {
	var out []devices.Device
	for _, d := range m.devices {
		if d.AccountID == accountID && !d.Revoked {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *memoryDeviceDirectory) ListCertificates(_ context.Context, deviceID [16]byte) ([]devices.DeviceCertificate, error) {
	return append([]devices.DeviceCertificate(nil), m.certs[deviceID]...), nil
}

func (m *memoryDeviceDirectory) ListSignedPrekeys(_ context.Context, deviceID [16]byte) ([]devices.SignedPrekey, error) {
	return append([]devices.SignedPrekey(nil), m.keys[deviceID]...), nil
}

func TestDeviceDirectoryRoutesReturnCanonicalCBORBytes(t *testing.T) {
	var accountID, deviceID [16]byte
	for i := range accountID {
		accountID[i] = byte(i + 1)
		deviceID[i] = byte(0xa0 + i)
	}
	var dsk, ddhk, spk [32]byte
	var sig [64]byte
	dsk[0] = 1
	ddhk[0] = 2
	spk[0] = 3
	sig[0] = 4

	dir := &memoryDeviceDirectory{
		devices: map[[16]byte]devices.Device{
			deviceID: {
				AccountID:    accountID,
				DeviceID:     deviceID,
				AccountEpoch: 3,
				DSKPub:       dsk,
				DDHKPub:      ddhk,
				Revoked:      false,
				CreatedAt:    time.Unix(1700000000, 0).UTC(),
			},
		},
		certs: map[[16]byte][]devices.DeviceCertificate{
			deviceID: {{
				DeviceID:  deviceID,
				CertCBOR:  []byte{0xa1, 0x01, 0x02},
				CreatedAt: time.Unix(1700000001, 0).UTC(),
			}},
		},
		keys: map[[16]byte][]devices.SignedPrekey{
			deviceID: {{
				DeviceID:  deviceID,
				SPKID:     7,
				SPKPub:    spk,
				Signature: sig,
			}},
		},
	}

	h := NewHandlerWithSTHAndDevices(nil, dir)

	accountText := "01020304-0506-0708-090a-0b0c0d0e0f10"
	deviceText := "a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"

	cases := []struct {
		name string
		path string
	}{
		{"device", "/v1/devices/" + accountText + "/" + deviceText},
		{"devices", "/v1/accounts/" + accountText + "/devices"},
		{"certificates", "/v1/devices/" + deviceText + "/certificates"},
		{"prekeys", "/v1/devices/" + deviceText + "/prekeys"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if rr.Header().Get("Content-Type") != deviceCBORContentType {
				t.Fatalf("content type=%q", rr.Header().Get("Content-Type"))
			}
			if len(rr.Body.Bytes()) == 0 {
				t.Fatal("empty CBOR body")
			}
		})
	}
}

func TestDeviceDirectoryRoutesRejectInvalidUUID(t *testing.T) {
	h := NewHandlerWithSTHAndDevices(nil, &memoryDeviceDirectory{
		devices: map[[16]byte]devices.Device{},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/not-a-uuid/devices", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestDeviceDirectoryRoutesMethodGuard(t *testing.T) {
	h := NewHandlerWithSTHAndDevices(nil, &memoryDeviceDirectory{
		devices: map[[16]byte]devices.Device{},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/accounts/01020304-0506-0708-090a-0b0c0d0e0f10/devices", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rr.Code)
	}
}
