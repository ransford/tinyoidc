package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const DEFAULT_PORT uint16 = 8192

type OidcServer struct {
	server *http.Server
}

func authzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Parse authz payload. Example: foo@example.com

	// If the payload includes a signed authz from the IdP, reconstruct it and make sure it matches what
	// we expect. If so, sign a payload that the client will present to our token endpoint
	//
	// Otherwise (no signature from IdP), fetch its keys from the .well-known endpoint and redirect to
	// its authz endpoint
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Parse the request payload. If there's a refresh token, validate it and return a new token and
	// refresh token. If there's no refresh token but there's a signed payload from our authz
	// endpoint, validate it and assemble a new session token and refresh token.
	//
	// Return a session token and a refresh token
}

type oidcConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	conf := oidcConfiguration{
		AuthorizationEndpoint: "foo",
		TokenEndpoint:         "bar",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(conf)
}

func NewOidcServer(port uint16) *OidcServer {
	mux := http.NewServeMux()

	// Endpoints for OIDC
	mux.Handle("/authorize", http.HandlerFunc(authzHandler))
	mux.Handle("/token", http.HandlerFunc(tokenHandler))
	mux.Handle("/.well-known/openid-configuration", http.HandlerFunc(wellKnownHandler))
	// TODO: .well-known info?

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      mux,
	}

	return &OidcServer{
		server: srv,
	}
}

func (o *OidcServer) ListenAndServe() error {
	slog.Info("starting server", "addr", o.server.Addr)
	return o.server.ListenAndServe()
}
