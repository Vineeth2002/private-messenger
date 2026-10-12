package gwhttp

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/devices"
)

const deviceCBORContentType = "application/cbor"

// NewHandlerWithSTHAndDevices extends the existing Phase A/KT handler with
// read-only device-directory routes backed by the existing devices package.
//
// API shapes are intentionally limited to the read surface agreed for this
// phase; enrollment/revocation writes remain internal until their authorization
// contract is frozen.
func NewHandlerWithSTHAndDevices(sthSource STHSource, directory devices.Directory) http.Handler {
	base := NewHandlerWithSTH(sthSource)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handled := serveDeviceDirectory(w, r, directory); handled {
			return
		}
		base.ServeHTTP(w, r)
	})
}

func serveDeviceDirectory(w http.ResponseWriter, r *http.Request, directory devices.Directory) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		return false
	}

	parts := splitPath(r.URL.Path)
	switch {
	case len(parts) == 4 && parts[1] == "devices" && parts[3] == "certificates":
		if r.Method != http.MethodGet {
			writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return true
		}
		deviceID, ok := parseUUIDPath(parts[2])
		if !ok {
			writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
			return true
		}
		if directory == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_DEVICE_DIRECTORY_UNAVAILABLE")
			return true
		}
		certs, err := directory.ListCertificates(r.Context(), deviceID)
		if err != nil {
			if err == devices.ErrNotFound {
				writeDeviceError(w, http.StatusNotFound, "ERR_DEVICE_NOT_FOUND")
			} else {
				writeDeviceError(w, http.StatusInternalServerError, "ERR_DEVICE_DIRECTORY")
			}
			return true
		}
		raw, err := encodeCertificates(certs)
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
			return true
		}
		writeCBOR(w, raw)
		return true

	case len(parts) == 4 && parts[1] == "devices" && parts[3] == "prekeys":
		if r.Method != http.MethodGet {
			writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return true
		}
		deviceID, ok := parseUUIDPath(parts[2])
		if !ok {
			writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
			return true
		}
		if directory == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_DEVICE_DIRECTORY_UNAVAILABLE")
			return true
		}
		prekeys, err := directory.ListSignedPrekeys(r.Context(), deviceID)
		if err != nil {
			if err == devices.ErrNotFound {
				writeDeviceError(w, http.StatusNotFound, "ERR_DEVICE_NOT_FOUND")
			} else {
				writeDeviceError(w, http.StatusInternalServerError, "ERR_DEVICE_DIRECTORY")
			}
			return true
		}
		raw, err := encodeSignedPrekeys(prekeys)
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
			return true
		}
		writeCBOR(w, raw)
		return true

	case len(parts) == 4 && parts[1] == "devices":
		if r.Method != http.MethodGet {
			writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return true
		}
		accountID, ok := parseUUIDPath(parts[2])
		if !ok {
			writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_ACCOUNT_ID")
			return true
		}
		deviceID, ok := parseUUIDPath(parts[3])
		if !ok {
			writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_DEVICE_ID")
			return true
		}
		if directory == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_DEVICE_DIRECTORY_UNAVAILABLE")
			return true
		}
		device, err := directory.Get(r.Context(), accountID, deviceID)
		if err != nil {
			if err == devices.ErrNotFound {
				writeDeviceError(w, http.StatusNotFound, "ERR_DEVICE_NOT_FOUND")
			} else {
				writeDeviceError(w, http.StatusInternalServerError, "ERR_DEVICE_DIRECTORY")
			}
			return true
		}
		raw, err := encodeDevice(device)
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
			return true
		}
		writeCBOR(w, raw)
		return true

	case len(parts) == 4 && parts[1] == "accounts" && parts[3] == "devices":
		if r.Method != http.MethodGet {
			writeDeviceError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED")
			return true
		}
		accountID, ok := parseUUIDPath(parts[2])
		if !ok {
			writeDeviceError(w, http.StatusBadRequest, "ERR_INVALID_ACCOUNT_ID")
			return true
		}
		if directory == nil {
			writeDeviceError(w, http.StatusServiceUnavailable, "ERR_DEVICE_DIRECTORY_UNAVAILABLE")
			return true
		}
		list, err := directory.ListActive(r.Context(), accountID)
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "ERR_DEVICE_DIRECTORY")
			return true
		}
		raw, err := encodeDevices(list)
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "ERR_CBOR_ENCODE")
			return true
		}
		writeCBOR(w, raw)
		return true
	}

	return false
}

func splitPath(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, len(raw))
	for i := range raw {
		out[i] = raw[i]
	}
	return out
}

func parseUUIDPath(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return out, false
	}
	dst := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		if i+1 >= len(s) {
			return out, false
		}
		hi, ok := hexDigit(s[i])
		if !ok {
			return out, false
		}
		i++
		lo, ok := hexDigit(s[i])
		if !ok {
			return out, false
		}
		out[dst] = hi<<4 | lo
		dst++
	}
	return out, dst == len(out)
}

func hexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func writeCBOR(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", deviceCBORContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func writeDeviceError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func encodeDevice(device devices.Device) ([]byte, error) {
	count := 7
	if len(device.PushPub) > 0 {
		count++
	}
	out := make([]byte, 0, 256)
	out = appendMapHeader(out, count)
	out = appendMapKey(out, 1)
	out = appendBytes(out, device.AccountID[:])
	out = appendMapKey(out, 2)
	out = appendBytes(out, device.DeviceID[:])
	out = appendMapKey(out, 3)
	out = appendUint(out, device.AccountEpoch)
	out = appendMapKey(out, 4)
	out = appendBytes(out, device.DSKPub[:])
	out = appendMapKey(out, 5)
	out = appendBytes(out, device.DDHKPub[:])
	if len(device.PushPub) > 0 {
		out = appendMapKey(out, 6)
		out = appendBytes(out, device.PushPub)
	}
	out = appendMapKey(out, 7)
	out = appendBool(out, device.Revoked)
	out = appendMapKey(out, 8)
	out = appendUint(out, uint64(device.CreatedAt.Unix()))
	return out, nil
}

func encodeDevices(list []devices.Device) ([]byte, error) {
	out := appendArrayHeader(nil, len(list))
	for _, device := range list {
		raw, err := encodeDevice(device)
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
	}
	return out, nil
}

func encodeCertificates(list []devices.DeviceCertificate) ([]byte, error) {
	out := appendArrayHeader(nil, len(list))
	for _, cert := range list {
		out = appendMapHeader(out, 3)
		out = appendMapKey(out, 1)
		out = appendBytes(out, cert.DeviceID[:])
		out = appendMapKey(out, 2)
		out = appendBytes(out, cert.CertCBOR)
		out = appendMapKey(out, 3)
		out = appendUint(out, uint64(cert.CreatedAt.Unix()))
	}
	return out, nil
}

func encodeSignedPrekeys(list []devices.SignedPrekey) ([]byte, error) {
	out := appendArrayHeader(nil, len(list))
	for _, key := range list {
		out = appendMapHeader(out, 4)
		out = appendMapKey(out, 1)
		out = appendBytes(out, key.DeviceID[:])
		out = appendMapKey(out, 2)
		out = appendInt(out, key.SPKID)
		out = appendMapKey(out, 3)
		out = appendBytes(out, key.SPKPub[:])
		out = appendMapKey(out, 4)
		out = appendBytes(out, key.Signature[:])
	}
	return out, nil
}

func appendMapHeader(out []byte, n int) []byte {
	return appendMajorUint(out, 5, uint64(n))
}

func appendArrayHeader(out []byte, n int) []byte {
	return appendMajorUint(out, 4, uint64(n))
}

func appendMapKey(out []byte, n uint64) []byte {
	return appendUint(out, n)
}

func appendBytes(out []byte, b []byte) []byte {
	out = appendMajorUint(out, 2, uint64(len(b)))
	return append(out, b...)
}

func appendUint(out []byte, n uint64) []byte {
	return appendMajorUint(out, 0, n)
}

func appendInt(out []byte, n int64) []byte {
	if n >= 0 {
		return appendUint(out, uint64(n))
	}
	encoded := uint64(-(n + 1))
	return appendMajorUint(out, 1, encoded)
}

func appendBool(out []byte, value bool) []byte {
	if value {
		return append(out, 0xf5)
	}
	return append(out, 0xf4)
}

func appendMajorUint(out []byte, major byte, n uint64) []byte {
	switch {
	case n <= 23:
		return append(out, major<<5|byte(n))
	case n <= 0xff:
		out = append(out, major<<5|24, byte(n))
	case n <= 0xffff:
		out = append(out, major<<5|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		out = append(out, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		out = append(out, major<<5|27,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return out
}
