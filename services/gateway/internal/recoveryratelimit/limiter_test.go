package recoveryratelimit

import (
	"bytes"
	"database/sql"
	"testing"
	"time"
)

func TestClientKeyHashUsesKeyedPeerIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	first := clientKeyHash(key, "203.0.113.25")
	if first != clientKeyHash(key, "203.0.113.25") {
		t.Fatal("same key and peer produced different hashes")
	}
	if first == clientKeyHash(bytes.Repeat([]byte{0x43}, 32), "203.0.113.25") {
		t.Fatal("different HMAC keys produced the same client hash")
	}
	if first == clientKeyHash(key, "203.0.113.26") {
		t.Fatal("different peers produced the same client hash")
	}
}

func TestNormalizePeerGroupsIPv6Within64(t *testing.T) {
	first := normalizePeer("2001:db8:1234:5678::1")
	second := normalizePeer("2001:db8:1234:5678:ffff::abcd")
	if first != "2001:db8:1234:5678::/64" || second != first {
		t.Fatalf("IPv6 peers normalized to %q and %q; want the same /64", first, second)
	}
	if got := normalizePeer("203.0.113.25"); got != "203.0.113.25/32" {
		t.Fatalf("IPv4 peer normalized to %q", got)
	}
	if got := normalizePeer("invalid-peer"); got != "unknown" {
		t.Fatalf("invalid peer normalized to %q, want unknown", got)
	}
}

func TestNewPostgresRejectsInvalidConfiguration(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	if _, err := NewPostgres(nil, key, 10, time.Minute); err == nil {
		t.Fatal("nil database accepted")
	}
	if _, err := NewPostgres(&sql.DB{}, key[:16], 10, time.Minute); err == nil {
		t.Fatal("short key accepted")
	}
}
