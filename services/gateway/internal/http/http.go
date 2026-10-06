// Package gwhttp is the gateway's HTTP surface. Phase A exposes only a health probe
// and a PM-CBOR-2026 validation endpoint. The gateway never decrypts E2EE content.
package gwhttp

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const MaxBodyBytes = 1 << 20 // 1 MiB

// NewHandler returns the gateway mux.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/v1/cbor/validate", validate)
	return mux
}

func validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if _, err := cbor.DecodeStrict(body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(cbor.CategoryOf(err))})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
