package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const DEFAULT_PORT uint16 = 8192

const DEV_ISSUER_URL = "http://localhost:5556/dex"
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

	fetchedOidcConfig *OpenIDConfig
}

func myHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func NewOidcRelyingParty(port uint16) (*OidcRelyingParty, error) {
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
		return nil, err
	}

	// Get OID configuration from SP
	oidcConfigUrl := fmt.Sprintf("%s/.well-known/openid-configuration", DEV_ISSUER_URL)
	slog.Info("fetching", "url", oidcConfigUrl)
	resp, err := http.Get(oidcConfigUrl)
	if err != nil {
		return nil, err
	}
	j := json.NewDecoder(resp.Body)
	conf := OpenIDConfig{}
	if err := j.Decode(&conf); err != nil {
		return nil, err
	}
	slog.Info("fetched", "url", oidcConfigUrl)
	slog.Debug("issuer", "metadata", conf)

	return &OidcRelyingParty{
		server:            srv,
		issuerUrl:         DEV_ISSUER_URL,
		clientId:          DEV_CLIENT_ID,
		clientSecret:      DEV_CLIENT_SECRET,
		redirectUri:       fmt.Sprintf("http://localhost:%d/auth/callback", DEFAULT_PORT),
		scopes:            []string{"openid", "email"},
		cookieSigningKey:  cookieSigningKey,
		fetchedOidcConfig: &conf,
	}, nil
}

func (o *OidcRelyingParty) ListenAndServe() error {
	slog.Info("starting server", "addr", o.server.Addr)
	return o.server.ListenAndServe()
}

type OpenIDConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksUri                           string   `json:"jwks_uri"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
}
