package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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

func (o *OidcRelyingParty) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Log in
	w.Header().Set("Content-Type", "application/json")

	state := make([]byte, 32)
	rand.Read(state)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	// PKCE
	codeVerifier := make([]byte, 32)
	rand.Read(codeVerifier)

	stateStr := base64.StdEncoding.EncodeToString(state)
	cookieVal := ClientCookie{
		State:        stateStr,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		CodeVerifier: base64.StdEncoding.EncodeToString(codeVerifier),

		// Next should always be a valid path on this site
		Next: "/successfully-logged-in",

		created: time.Now(),
	}
	j, err := json.Marshal(cookieVal)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	o.mu.Lock()
	o.sessions[stateStr] = &cookieVal
	slog.Debug("wrote session", "key", stateStr)
	o.mu.Unlock()

	cv := sha256.Sum256(j)
	cookie := http.Cookie{
		Name:     "tinyoidc_session",
		Value:    base64.RawURLEncoding.EncodeToString(cv[:]),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		// Secure:   true,
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
	params.Add("state", stateStr)
	params.Add("code_challenge_method", "S256")
	cv2 := sha256.Sum256(codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(cv2[:])
	params.Add("code_challenge", codeChallenge)
	baseUrl.RawQuery = params.Encode()
	slog.Debug("redirecting", "location", baseUrl.String())

	http.Redirect(w, r, baseUrl.String(), http.StatusFound)

	w.Write([]byte(`{"hi": "there"}`))
	// w.WriteHeader(http.StatusOK)
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
