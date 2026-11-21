package gwhttp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
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

type ContactDiscoveryStore interface {
	FindMatches(ctx context.Context, selfHash string, hashes []string) ([]contactDiscoverMatch, error)
}

type PostgresContactDiscoveryStore struct {
	db interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}
}

func NewPostgresContactDiscoveryStore(db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) *PostgresContactDiscoveryStore {
	return &PostgresContactDiscoveryStore{db: db}
}

func (s *PostgresContactDiscoveryStore) FindMatches(ctx context.Context, selfHash string, hashes []string) ([]contactDiscoverMatch, error) {
	if s == nil || s.db == nil || len(hashes) == 0 {
		return []contactDiscoverMatch{}, nil
	}
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT discovery_hash_hex, display_name, pairing_code
		 FROM contact_discovery_entries
		 WHERE discovery_hash_hex = ANY($1)
		   AND discovery_hash_hex <> $2`,
		hashes,
		selfHash,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]contactDiscoverMatch, 0, len(hashes))
	for rows.Next() {
		var h, name, code string
		if err := rows.Scan(&h, &name, &code); err != nil {
			return nil, err
		}
		hTrim := strings.TrimSpace(h)
		if hTrim == "" {
			continue
		}
		if strings.TrimSpace(name) == "" {
			name = "Registered User"
		}
		out = append(out, contactDiscoverMatch{
			Hash:        hTrim,
			DisplayName: strings.TrimSpace(name),
			PairingCode: strings.TrimSpace(code),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// WithContactDiscovery adds POST /v1/contacts/discover while keeping zero plaintext contact storage.
func WithContactDiscovery(next http.Handler) http.Handler {
	return WithContactDiscoveryStore(next, nil)
}

// WithContactDiscoveryStore adds POST /v1/contacts/discover backed by an optional PostgreSQL store.
func WithContactDiscoveryStore(next http.Handler, store ContactDiscoveryStore) http.Handler {
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

		selfHash := strings.ToLower(strings.TrimSpace(req.SelfHash))
		validHashes := make([]string, 0, len(req.Hashes))
		seen := make(map[string]struct{}, len(req.Hashes))
		for _, rawHash := range req.Hashes {
			h := strings.ToLower(strings.TrimSpace(rawHash))
			if len(h) != 64 || h == selfHash {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			if _, err := hex.DecodeString(h); err != nil {
				continue
			}
			seen[h] = struct{}{}
			validHashes = append(validHashes, h)
		}

		matches := make([]contactDiscoverMatch, 0, len(validHashes))
		if store != nil && len(validHashes) > 0 {
			qCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			dbMatches, qErr := store.FindMatches(qCtx, selfHash, validHashes)
			cancel()
			if qErr == nil {
				matches = dbMatches
			}
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(contactDiscoverResponse{Matches: matches})
	})
}

func Sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
