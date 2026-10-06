// Command gateway is the Sovereign Private Messenger delivery/control-plane
// gateway. Phase A: health + CBOR validation only.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	gwhttp "github.com/sovereign-messenger/private-messenger/services/gateway/internal/http"
)

func main() {
	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080" // conservative default: loopback only
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           gwhttp.NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	log.Printf("gateway listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
