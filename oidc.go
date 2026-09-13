package main

import (
	// "encoding/json"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const DEFAULT_PORT uint16 = 8192

const DEV_CLIENT_ID = "tinyoidc"
const DEV_CLIENT_SECRET = "tinyoidc-dev-secret"

type OidcRelyingParty struct {
	server *http.Server

	issuerUrl        string
	clientId         string
	clientSecret     string
	redirectUri      string
	scopes           []string
	cookieSigningKey []byte
}

func myHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func NewOidcRelyingParty(port uint16) *OidcRelyingParty {
	mux := http.NewServeMux()

	// Endpoints for OIDC
	mux.Handle("/foo", http.HandlerFunc(myHandler))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      mux,
	}

	cookieSigningKey := make([]byte, 32)
	_, err := rand.Read(cookieSigningKey)
	if err != nil {
		panic("keygen")
	}

	return &OidcRelyingParty{
		server:           srv,
		issuerUrl:        fmt.Sprintf("http://localhost:%d/", DEFAULT_PORT),
		clientId:         DEV_CLIENT_ID,
		clientSecret:     DEV_CLIENT_SECRET,
		redirectUri:      fmt.Sprintf("http://localhost:%d/auth/callback", DEFAULT_PORT),
		scopes:           []string{"openid", "email"},
		cookieSigningKey: cookieSigningKey,
	}
}

func (o *OidcRelyingParty) ListenAndServe() error {
	slog.Info("starting server", "addr", o.server.Addr)
	return o.server.ListenAndServe()
}
