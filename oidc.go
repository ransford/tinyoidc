package tinyoidc

import (
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
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

const DEFAULT_PORT uint16 = 8192

const DEV_ISSUER_URL = "http://localhost:5556/dex"
const DEV_CLIENT_ID = "tinyoidc"
const DEV_CLIENT_SECRET = "tinyoidc-dev-secret"
const STATE_COOKIE_NAME = "__Host-tinyoidc_state"
const SESSION_COOKIE_NAME = "__Host-tinyoidc_session"

type OidcRelyingParty struct {
	mux *http.ServeMux

	issuerUrl    string
	clientId     string
	clientSecret string
	redirectUri  string
	scopes       []string

	fetchedOidcConfig *OpenIDConfig

	mu          sync.Mutex
	jwks        *Jwks
	jwksFetched time.Time // last JWKS fetch attempt, successful or not

	// Storage for pending and active sessions
	pendingSessions map[string]*ClientCookie
	activeSessions  map[string]*ActiveSession
}

type ClientCookie struct {
	State        string
	Nonce        string
	CodeVerifier string

	// Client's original destination before we made them auth
	Next string

	created time.Time
}

type ActiveSession struct {
	Username string
	claims   *IDTokenClaims

	created time.Time
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

type IDTokenClaims struct {
	jwt.RegisteredClaims        // iss, sub, aud, exp, iat
	Nonce                string `json:"nonce"`
	Azp                  string `json:"azp"`
	Email                string `json:"email"`
	EmailVerified        bool   `json:"email_verified"`
}

// keyFor is the jwt.Keyfunc: choose the OP's public key by the token's kid. An unknown
// kid may mean the OP rotated its keys, so re-fetch the JWKS, at most once per
// jwksRefetchInterval.
func (o *OidcRelyingParty) keyFor(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)

	o.mu.Lock()
	// Rechecked on each call: another goroutine's re-fetch may have brought the key in.
	if k, err := o.jwks.rsaKey(kid); k != nil || err != nil {
		o.mu.Unlock()
		return k, err
	}
	if time.Since(o.jwksFetched) < jwksRefetchInterval {
		o.mu.Unlock()
		return nil, fmt.Errorf("no key for kid %q", kid)
	}
	// Claim the fetch before unlocking so concurrent callers don't fetch too. The lock
	// isn't held across the request: Claims takes it on every request.
	o.jwksFetched = time.Now()
	o.mu.Unlock()

	slog.Info("unknown kid, re-fetching jwks", "kid", kid)
	jwks, err := fetchJwks(o.fetchedOidcConfig.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("no key for kid %q: %w", kid, err)
	}
	o.mu.Lock()
	o.jwks = jwks
	o.mu.Unlock()

	if k, err := jwks.rsaKey(kid); k != nil || err != nil {
		return k, err
	}
	return nil, fmt.Errorf("no key for kid %q", kid)
}

// verifyIDToken checks the ID token's signature and claims, and that its nonce is the
// one we issued for this login attempt.
func (o *OidcRelyingParty) verifyIDToken(raw, nonce string) (*IDTokenClaims, error) {
	claims := &IDTokenClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, o.keyFor,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(o.issuerUrl),
		jwt.WithAudience(o.clientId),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Minute),
	)
	if err != nil {
		return nil, err
	}
	if claims.Nonce != nonce {
		return nil, fmt.Errorf("nonce mismatch")
	}
	if len(claims.Audience) > 1 && claims.Azp != o.clientId {
		return nil, fmt.Errorf("azp mismatch")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("empty subject")
	}
	if claims.Email != "" && !claims.EmailVerified {
		return nil, fmt.Errorf("unverified email")
	}
	return claims, nil
}

func (o *OidcRelyingParty) authCallbackHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	if params.Get("error") != "" {
		http.Error(w, params.Get("error"), http.StatusBadRequest)
		return
	}

	// Check that the state is present and state matches cookie so it can't be reused
	state := params.Get("state")
	cookie, err := r.Cookie(STATE_COOKIE_NAME)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if cookie.Value != state {
		http.Error(w, "mismatching state cookie", http.StatusBadRequest)
		return
	}

	o.mu.Lock()
	session, ok := o.pendingSessions[state]
	if ok {
		delete(o.pendingSessions, state)
	}
	o.mu.Unlock()
	if !ok {
		http.Error(w, "no such state", http.StatusBadRequest)
		return
	}

	code := params.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", o.redirectUri)
	data.Set("code_verifier", session.CodeVerifier)
	formEncodedReader := strings.NewReader(data.Encode())
	fetchToken, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.fetchedOidcConfig.TokenEndpoint, formEncodedReader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fetchToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fetchToken.SetBasicAuth(o.clientId, o.clientSecret)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(fetchToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "fetch error", http.StatusInternalServerError)
		return
	}

	// Do something with the access token
	tokenResponse := TokenResponse{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Debug("parsed access token", "expires", tokenResponse.ExpiresIn)

	claims, err := o.verifyIDToken(tokenResponse.IdToken, session.Nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	slog.Info("logged in", "email", claims.Email)

	// Delete the state cookie so it can't be reused
	http.SetCookie(w, &http.Cookie{
		Name:     STATE_COOKIE_NAME,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	})

	sessionId := uuid.New().String()
	o.mu.Lock()
	o.activeSessions[sessionId] = &ActiveSession{
		Username: claims.Email,
		claims:   claims,
		created:  time.Now(),
	}
	o.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     SESSION_COOKIE_NAME,
		Value:    sessionId,
		Path:     "/",
		MaxAge:   int(time.Until(claims.ExpiresAt.Time).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Re-check the destination even though loginHandler validated it before storing.
	next := session.Next
	if !isLocalPath(next) {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// logoutHandler is registered for POST only, so a cross-site <img> or link can't log
// anyone out. A cross-site form POST won't carry the SameSite=Lax session cookie.
func (o *OidcRelyingParty) logoutHandler(w http.ResponseWriter, r *http.Request) {
	var sessionId string

	cookie, err := r.Cookie(SESSION_COOKIE_NAME)
	if err != nil {
		slog.Error("logout: invalid session")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	sessionId = cookie.Value

	logout := false
	var u string
	var dur time.Duration

	o.mu.Lock()
	if s, ok := o.activeSessions[sessionId]; ok {
		logout = true
		u = s.Username
		dur = time.Since(s.created)
	}
	delete(o.activeSessions, sessionId)
	o.mu.Unlock()
	if !logout {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SESSION_COOKIE_NAME,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	})

	slog.Info("logout", "username", u, "after", dur)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (o *OidcRelyingParty) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Log in
	w.Header().Set("Content-Type", "application/json")

	next := r.URL.Query().Get("next")
	if !isLocalPath(next) {
		next = "/"
	}

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
		Next: next,

		created: time.Now(),
	}
	o.mu.Lock()
	o.pendingSessions[stateStr] = &cookieVal
	o.mu.Unlock()

	cookie := http.Cookie{
		Name:     STATE_COOKIE_NAME,
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
	params.Add("scope", strings.Join(o.scopes, " "))
	params.Add("state", cookieVal.State)
	params.Add("nonce", cookieVal.Nonce)
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", codeChallenge)
	baseUrl.RawQuery = params.Encode()

	http.Redirect(w, r, baseUrl.String(), http.StatusFound)
}

func (o *OidcRelyingParty) tidyForever() {
	for {
		o.mu.Lock()

		for s, c := range o.pendingSessions {
			if time.Since(c.created) > 10*time.Minute {
				delete(o.pendingSessions, s)
			}
		}

		for s, c := range o.activeSessions {
			if time.Now().After(c.claims.ExpiresAt.Time) {
				delete(o.activeSessions, s)
			}
		}

		o.mu.Unlock()
		time.Sleep(1 * time.Minute)
	}
}

func fetchOidcConfig(uri string) (*OpenIDConfig, error) {
	resp, err := getWithTimeout(uri, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	j := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	conf := OpenIDConfig{}
	if err := j.Decode(&conf); err != nil {
		return nil, err
	}
	slog.Debug("issuer", "metadata", conf)
	if conf.Issuer != DEV_ISSUER_URL {
		return nil, fmt.Errorf("wrong issuer url")
	}
	if _, err := url.Parse(conf.AuthorizationEndpoint); err != nil {
		return nil, fmt.Errorf("invalid authz endpoint URL")
	}
	if _, err := url.Parse(conf.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("invalid token endpoint URL")
	}

	return &conf, nil
}

func NewOidcRelyingParty(port uint16) (*OidcRelyingParty, error) {
	mux := http.NewServeMux()

	// Get OIDC configuration from SP
	oidcConfigUrl := fmt.Sprintf("%s/.well-known/openid-configuration", DEV_ISSUER_URL)
	conf, err := fetchOidcConfig(oidcConfigUrl)
	if err != nil {
		return nil, err
	}

	slog.Debug("fetching jwks", "jwks_uri", conf.JwksUri)
	jwks, err := fetchJwks(conf.JwksUri)
	if err != nil {
		return nil, err
	}
	slog.Debug("parsed jwks", "jwks", jwks)

	rp := &OidcRelyingParty{
		mux:               mux,
		issuerUrl:         DEV_ISSUER_URL,
		clientId:          DEV_CLIENT_ID,
		clientSecret:      DEV_CLIENT_SECRET,
		redirectUri:       fmt.Sprintf("http://localhost:%d/auth/callback", DEFAULT_PORT),
		scopes:            []string{"openid", "email"},
		fetchedOidcConfig: conf,
		jwks:              jwks,
		jwksFetched:       time.Now(),

		pendingSessions: make(map[string]*ClientCookie),
		activeSessions:  make(map[string]*ActiveSession),
	}

	mux.Handle("/auth/login", http.HandlerFunc(rp.loginHandler))
	mux.Handle("POST /auth/logout", http.HandlerFunc(rp.logoutHandler))
	mux.Handle("/auth/callback", http.HandlerFunc(rp.authCallbackHandler))

	// clean up old sessions
	go rp.tidyForever()

	return rp, nil
}

// Handler serves the /auth/* routes. Mount it at "/auth/" on the application's mux.
func (o *OidcRelyingParty) Handler() http.Handler {
	return o.mux
}

type claimsContextKey struct{}

// Middleware passes requests with a valid session through to next, with the
// session's ID token claims in the request context. Otherwise, navigations are
// redirected to /auth/login and everything else gets a 401.
func (o *OidcRelyingParty) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := o.Claims(r)
		if !ok {
			// The response depends on these headers, so caches must not share it.
			w.Header().Add("Vary", "Sec-Fetch-Mode, Sec-Fetch-Dest, Accept")
			w.Header().Set("Cache-Control", "no-store")

			login := "/auth/login?" + url.Values{"next": {r.URL.RequestURI()}}.Encode()
			if isNavigation(r) {
				http.Redirect(w, r, login, http.StatusFound)
				return
			}
			// 401 requires WWW-Authenticate, but cookie sessions have no registered
			// scheme, so this one is made up.
			w.Header().Set("WWW-Authenticate", `Session realm="tinyoidc"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated", "login": login})
			return
		}
		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Claims returns the ID token claims for the request's session, if it has a valid
// one. Unlike Middleware it never redirects, so public pages can use it too.
func (o *OidcRelyingParty) Claims(r *http.Request) (*IDTokenClaims, bool) {
	cookie, err := r.Cookie(SESSION_COOKIE_NAME)
	if err != nil {
		return nil, false
	}
	o.mu.Lock()
	session := o.activeSessions[cookie.Value]
	o.mu.Unlock()
	if session == nil || time.Now().After(session.claims.ExpiresAt.Time) {
		return nil, false
	}
	return session.claims, true
}

// ClaimsFromContext returns the claims Middleware stored in a request context.
func ClaimsFromContext(ctx context.Context) (*IDTokenClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*IDTokenClaims)
	return claims, ok
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
