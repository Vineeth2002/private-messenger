// Package deviceauth parses and verifies the candidate PM-V1 device HTTP
// request proof. It does not perform database authorization or consume replay
// nonces; callers must do both before invoking protected operations.
package deviceauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	Scheme          = "PM-Device-V1"
	Version         = byte(1)
	ProofSize       = 145
	MaxEpoch        = uint64(^uint32(0))
	MaxMethodSize   = 16
	MaxTargetSize   = 2048
	MaxBodySize     = 1 << 20
	MaxClockSkew    = 5 * time.Minute
	proofHeaderSize = len(Scheme) + 1
)

var (
	ErrMalformedProof = errors.New("device auth: malformed proof")
	ErrInvalidProof   = errors.New("device auth: invalid proof")
	ErrExpiredProof   = errors.New("device auth: expired proof")
)

var requestDomain = []byte("PM-V1-DEVICE-HTTP-REQUEST-AUTH-v1\x00")

type Principal struct {
	AccountID [16]byte
	DeviceID  [16]byte
	Epoch     uint64
	Timestamp uint64
	Nonce     [32]byte
}

type Proof struct {
	Principal
	Signature [ed25519.SignatureSize]byte
	Raw       [ProofSize]byte
}

// ParseAuthorizationHeader accepts only canonical unpadded base64url and the
// exact PM-Device-V1 scheme. Alternate encodings are rejected.
func ParseAuthorizationHeader(header string) (Proof, error) {
	var out Proof
	prefix := Scheme + " "
	if !strings.HasPrefix(header, prefix) {
		return out, ErrMalformedProof
	}
	encoded := strings.TrimPrefix(header, prefix)
	if encoded == "" || strings.ContainsAny(encoded, " \t\r\n") {
		return out, ErrMalformedProof
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != ProofSize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return out, ErrMalformedProof
	}
	copy(out.Raw[:], raw)
	if out.Raw[0] != Version {
		return Proof{}, ErrMalformedProof
	}
	copy(out.AccountID[:], out.Raw[1:17])
	copy(out.DeviceID[:], out.Raw[17:33])
	out.Epoch = binary.BigEndian.Uint64(out.Raw[33:41])
	out.Timestamp = binary.BigEndian.Uint64(out.Raw[41:49])
	copy(out.Nonce[:], out.Raw[49:81])
	copy(out.Signature[:], out.Raw[81:145])
	if err := validatePrincipal(out.Principal); err != nil {
		return Proof{}, ErrMalformedProof
	}
	return out, nil
}

// Verify checks the exact request transcript and a bounded timestamp window.
// The public key MUST be retrieved from authoritative server-side device state,
// never from the proof or an untrusted request field.
func (p Proof) Verify(publicKey ed25519.PublicKey, method, requestTarget string, body []byte, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize || validateRequest(method, requestTarget, body) != nil {
		return ErrInvalidProof
	}
	if err := validatePrincipal(p.Principal); err != nil {
		return ErrInvalidProof
	}
	if now.Unix() <= 0 {
		return ErrExpiredProof
	}
	nowUnix := uint64(now.Unix())
	var delta uint64
	if p.Timestamp >= nowUnix {
		delta = p.Timestamp - nowUnix
	} else {
		delta = nowUnix - p.Timestamp
	}
	if delta > uint64(MaxClockSkew/time.Second) {
		return ErrExpiredProof
	}
	transcript := requestTranscript(p.Principal, method, requestTarget, body)
	if !ed25519.Verify(publicKey, transcript, p.Signature[:]) {
		return ErrInvalidProof
	}
	return nil
}

func VerifyAuthorizationHeader(header string, publicKey ed25519.PublicKey, method, requestTarget string, body []byte, now time.Time) (Principal, error) {
	proof, err := ParseAuthorizationHeader(header)
	if err != nil {
		return Principal{}, err
	}
	if err := proof.Verify(publicKey, method, requestTarget, body, now); err != nil {
		return Principal{}, err
	}
	return proof.Principal, nil
}

func validatePrincipal(p Principal) error {
	if allZero(p.AccountID[:]) || allZero(p.DeviceID[:]) || allZero(p.Nonce[:]) || p.Epoch == 0 || p.Epoch > MaxEpoch || p.Timestamp == 0 {
		return ErrInvalidProof
	}
	return nil
}

func validateRequest(method, target string, body []byte) error {
	if len(method) == 0 || len(method) > MaxMethodSize {
		return ErrInvalidProof
	}
	for i, b := range []byte(method) {
		if i == 0 {
			if b < 'A' || b > 'Z' {
				return ErrInvalidProof
			}
		} else if !((b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-') {
			return ErrInvalidProof
		}
	}
	if len(target) == 0 || len(target) > MaxTargetSize || target[0] != '/' {
		return ErrInvalidProof
	}
	for _, b := range []byte(target) {
		if b < 0x21 || b > 0x7e || b == '#' {
			return ErrInvalidProof
		}
	}
	if len(body) > MaxBodySize {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidProof, MaxBodySize)
	}
	return nil
}

func requestTranscript(p Principal, method, target string, body []byte) []byte {
	bodyDigest := sha256.Sum256(body)
	out := make([]byte, 0, len(requestDomain)+1+16+16+8+8+32+2+len(method)+4+len(target)+32)
	out = append(out, requestDomain...)
	out = append(out, Version)
	out = append(out, p.AccountID[:]...)
	out = append(out, p.DeviceID[:]...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], p.Epoch)
	out = append(out, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], p.Timestamp)
	out = append(out, u64[:]...)
	out = append(out, p.Nonce[:]...)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(method)))
	out = append(out, u16[:]...)
	out = append(out, method...)
	binary.BigEndian.PutUint32(u64[:4], uint32(len(target)))
	out = append(out, u64[:4]...)
	out = append(out, target...)
	out = append(out, bodyDigest[:]...)
	return out
}

func allZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}
