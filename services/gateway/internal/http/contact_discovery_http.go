package gwhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type contactDiscoverRequest struct {
	SelfHash string   `json:"selfHash"`
	Hashes   []string `json:"hashes"`
}

type contactDiscoverMatch struct {
	Hash        string `json:"hash"`
	DisplayName string `json:"displayName"`
	PairingCode string `json:"pairingCode,omitempty"`
}

type contactDiscoverResponse struct {
	Matches []contactDiscoverMatch `json:"matches"`
}

// WithContactDiscovery adds a privacy-preserving /v1/contacts/discover endpoint
// that validates hashed phone/email identifiers without storing plaintext contacts.
func WithContactDiscovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/contacts/discover" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		if err != nil {
			http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		var req contactDiscoverRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		matches := make([]contactDiscoverMatch, 0, len(req.Hashes))
		seen := make(map[string]struct{}, len(req.Hashes))
		for _, rawHash := range req.Hashes {
			h := strings.ToLower(strings.TrimSpace(rawHash))
			if len(h) != 64 || h == strings.ToLower(strings.TrimSpace(req.SelfHash)) {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			if _, err := hex.DecodeString(h); err != nil {
				continue
			}
			seen[h] = struct{}{}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(contactDiscoverResponse{Matches: matches})
	})
}

func Sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
