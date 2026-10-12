// Package gwhttp is the gateway's HTTP surface. The gateway never decrypts E2EE content.
package gwhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

const MaxBodyBytes = 1 << 20 // 1 MiB

type STHSource interface {
	Latest(ctx context.Context) (kt.SignedTreeHeadV1, []byte, time.Time, error)
}

// NewHandler returns the gateway mux with no KT persistence configured.
func NewHandler() http.Handler {
	return NewHandlerWithSTH(nil)
}

// NewHandlerWithSTH adds KT STH retrieval while preserving the existing
// health and strict-CBOR validation endpoints.
func NewHandlerWithSTH(sthSource STHSource) http.Handler {
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
	mux.HandleFunc("/v1/kt/sth", func(w http.ResponseWriter, r *http.Request) {
		getSTH(w, r, sthSource)
	})
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

func getSTH(w http.ResponseWriter, r *http.Request, source STHSource) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if source == nil {
		http.Error(w, "KT STH persistence is not configured", http.StatusServiceUnavailable)
		return
	}
	_, raw, _, err := source.Latest(r.Context())
	if errors.Is(err, kt.ErrSTHNotFound) {
		http.Error(w, "no STH has been published", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "KT STH unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
