package main

import (
	// "bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

	mu       sync.Mutex
	sessions map[string]*ClientCookie
}

type ClientCookie struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`

	// Client's original destination before we made them auth
	Next string `json:"next"`

	created time.Time
}

func (o *OidcRelyingParty) authCallbackHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := r.URL.Query()
	if params.Get("error") != "" {
		slog.Error("callback error",
			"error", params.Get("error"),
			"error_description", params.Get("error_description"))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`"error"`))
		return
	}

	// Check that the state is present and state matches cookie so it can't be reused
	state := params.Get("state")
	cookie, err := r.Cookie("__Host-tinyoidc_state")
	if err != nil {
		slog.Error("callback error", "missing state cookie", state)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`"error: tinyoidc_state cookie not found"`))
		return
	}
	if cookie.Value != state {
		slog.Error("callback error", "mismatching state cookie", state)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`"error: tinyoidc_state cookie mismatch"`))
		return
	}

	o.mu.Lock()
	session, ok := o.sessions[state]
	if ok {
		delete(o.sessions, state)
	}
	o.mu.Unlock()
	if !ok {
		slog.Error("callback error", "missing state", state)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`"error: state not found"`))
		return
	}
	slog.Debug("found session", "state", state)

	code := params.Get("code")
	if code == "" {
		slog.Error("callback error: missing code")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`"error: missing code"`))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", o.redirectUri)
	data.Set("code_verifier", session.CodeVerifier)
	slog.Debug("POST to token endpoint", "data", data)
	formEncodedReader := strings.NewReader(data.Encode())
	fetchToken, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.fetchedOidcConfig.TokenEndpoint, formEncodedReader)
	if err != nil {
		slog.Error("callback error: post")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`"error: post"`))
		return
	}
	fetchToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fetchToken.SetBasicAuth(o.clientId, o.clientSecret)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(fetchToken)
	if err != nil {
		slog.Error("callback error: fetch token")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`"error: fetch token"`))
		return
	}
	defer resp.Body.Close() // Always close the body to prevent memory leaks
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("callback error: parse token")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`"error: parse token"`))
		return
	}

	// Delete the state cookie so it can't be reused
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-tinyoidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	})

	// Do something with the access token
	slog.Debug("got token", "body", body)

	w.Write([]byte(`{"status": "omg"}`))

	// TOOD: reconstruct the cookie and check what the browser sent
}

func (o *OidcRelyingParty) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Log in
	w.Header().Set("Content-Type", "application/json")

	state := make([]byte, 32)
	rand.Read(state)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	// PKCE: compute a challenge from a (secret) random verifier
	codeVerifierRaw := make([]byte, 32)
	rand.Read(codeVerifierRaw)
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierRaw)
	verifierSha := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(verifierSha[:])
	slog.Debug("code challenge", "challenge", codeChallenge)

	stateStr := base64.RawURLEncoding.EncodeToString(state)
	cookieVal := ClientCookie{
		State:        stateStr,
		Nonce:        base64.RawURLEncoding.EncodeToString(nonce),
		CodeVerifier: codeVerifier,

		// Next should always be a valid path on this site
		Next: "/successfully-logged-in",

		created: time.Now(),
	}
	o.mu.Lock()
	o.sessions[stateStr] = &cookieVal
	slog.Debug("wrote session", "key", stateStr)
	o.mu.Unlock()

	cookie := http.Cookie{
		Name:     "__Host-tinyoidc_state",
		Value:    stateStr,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Use the http.SetCookie() function to send the cookie to the client.
	// Behind the scenes this adds a `Set-Cookie` header to the response
	// containing the necessary cookie data.
	http.SetCookie(w, &cookie)

	// Redirect URL
	baseUrl, _ := url.Parse(o.fetchedOidcConfig.AuthorizationEndpoint)
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", o.clientId)
	params.Add("redirect_uri", o.redirectUri)
	params.Add("scope", "openid email")
	params.Add("state", cookieVal.State)
	params.Add("nonce", cookieVal.Nonce)
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", codeChallenge)
	baseUrl.RawQuery = params.Encode()
	slog.Debug("redirecting", "location", baseUrl.String())

	http.Redirect(w, r, baseUrl.String(), http.StatusFound)
}

func (o *OidcRelyingParty) TidyForever() {
	for {
		o.mu.Lock()
		deletions := []string{}
		for s, c := range o.sessions {
			if time.Since(c.created) > 10*time.Minute {
				deletions = append(deletions, s)
			}
		}
		for _, d := range deletions {
			delete(o.sessions, d)
		}
		o.mu.Unlock()
		slog.Debug("tidied", "num_sessions", len(deletions))
		time.Sleep(1 * time.Minute)
	}
}

func NewOidcRelyingParty(port uint16) (*OidcRelyingParty, error) {
	mux := http.NewServeMux()

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
	if conf.Issuer != DEV_ISSUER_URL {
		return nil, fmt.Errorf("wrong issuer url")
	}

	rp := &OidcRelyingParty{
		server:            srv,
		issuerUrl:         DEV_ISSUER_URL,
		clientId:          DEV_CLIENT_ID,
		clientSecret:      DEV_CLIENT_SECRET,
		redirectUri:       fmt.Sprintf("http://localhost:%d/auth/callback", DEFAULT_PORT),
		scopes:            []string{"openid", "email"},
		cookieSigningKey:  cookieSigningKey,
		fetchedOidcConfig: &conf,

		sessions: make(map[string]*ClientCookie),
	}

	mux.Handle("/login", http.HandlerFunc(rp.loginHandler))
	mux.Handle("/auth/callback", http.HandlerFunc(rp.authCallbackHandler))

	// clean up old sessions
	go rp.TidyForever()

	return rp, nil
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
