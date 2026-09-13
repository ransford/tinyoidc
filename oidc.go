package tinyoidc

import (
	// "bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
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

type OidcRelyingParty struct {
	mux *http.ServeMux

	issuerUrl        string
	clientId         string
	clientSecret     string
	redirectUri      string
	scopes           []string
	cookieSigningKey []byte

	fetchedOidcConfig *OpenIDConfig

	mu              sync.Mutex
	jwks            *Jwks
	jwksFetched     time.Time // last JWKS fetch attempt, successful or not
	pendingSessions map[string]*ClientCookie
	activeSessions  map[string]*ActiveSession
}

type ClientCookie struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`

	// Client's original destination before we made them auth
	Next string `json:"next"`

	created time.Time
}

type ActiveSession struct {
	Username string `json:"username"`
	created  time.Time
	claims   *IDTokenClaims
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

type Jwks struct {
	Keys []Jwk `json:"keys"`
}

type Jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksRefetchInterval rate-limits JWKS fetches triggered by unknown kids, so a stream
// of tokens with bogus kids can't turn into a stream of requests to the OP.
const jwksRefetchInterval = time.Minute

func fetchJwks(uri string) (*Jwks, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: %s", resp.Status)
	}
	jwks := &Jwks{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(jwks); err != nil {
		return nil, err
	}
	return jwks, nil
}

// rsaKey returns the RSA key with the given kid, or nil if jwks has none.
func (j *Jwks) rsaKey(kid string) (*rsa.PublicKey, error) {
	for _, k := range j.Keys {
		if k.Kid != kid || k.Kty != "RSA" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, nil
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
	session, ok := o.pendingSessions[state]
	if ok {
		delete(o.pendingSessions, state)
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

	client := &http.Client{}
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
		slog.Error("callback error: read token")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`"error: read token"`))
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
	tokenResponse := TokenResponse{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		slog.Error("callback error: parse token")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`"error: parse token"`))
		return
	}
	slog.Debug("parsed access token", "expires", tokenResponse.ExpiresIn)

	claims, err := o.verifyIDToken(tokenResponse.IdToken, session.Nonce)
	if err != nil {
		slog.Error("callback error: verify ID token", "err", err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`"error: invalid ID token"`))
		return
	}
	slog.Debug("JWT claims", "claims", claims)

	slog.Info("logged in", "email", claims.Email)

	sessionId := uuid.New().String()
	o.mu.Lock()
	o.activeSessions[sessionId] = &ActiveSession{
		Username: claims.Email,
		created:  time.Now(),
		claims:   claims,
	}
	o.mu.Unlock()

	expiration := claims.ExpiresAt.Time.Sub(time.Now()).Seconds()
	sessionCookie := http.Cookie{
		Name:     "__Host-tinyoidc_session",
		Value:    sessionId,
		Path:     "/",
		MaxAge:   int(math.Round(expiration)),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Use the http.SetCookie() function to send the cookie to the client.
	// Behind the scenes this adds a `Set-Cookie` header to the response
	// containing the necessary cookie data.
	http.SetCookie(w, &sessionCookie)

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

	cookie, err := r.Cookie("__Host-tinyoidc_session")
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
		Name:     "__Host-tinyoidc_session",
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

// isLocalPath reports whether next is a path on this site, and so safe to redirect to
// after login. Anything else is a potential open redirect.
func isLocalPath(next string) bool {
	// "//evil" and "/\\evil" are scheme-relative URLs to browsers.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\") {
		return false
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(next)
	return err == nil && u.Scheme == "" && u.Host == ""
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
		for s, c := range o.pendingSessions {
			if time.Since(c.created) > 10*time.Minute {
				deletions = append(deletions, s)
			}
		}
		for _, d := range deletions {
			delete(o.pendingSessions, d)
		}
		o.mu.Unlock()
		slog.Debug("tidied", "num_sessions", len(deletions))
		time.Sleep(1 * time.Minute)
	}
}

func NewOidcRelyingParty(port uint16) (*OidcRelyingParty, error) {
	mux := http.NewServeMux()

	cookieSigningKey := make([]byte, 32)
	_, err := rand.Read(cookieSigningKey)
	if err != nil {
		return nil, err
	}

	// Get OIDC configuration from SP
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
		cookieSigningKey:  cookieSigningKey,
		fetchedOidcConfig: &conf,
		jwks:              jwks,
		jwksFetched:       time.Now(),

		pendingSessions: make(map[string]*ClientCookie),
		activeSessions:  make(map[string]*ActiveSession),
	}

	mux.Handle("/auth/login", http.HandlerFunc(rp.loginHandler))
	mux.Handle("POST /auth/logout", http.HandlerFunc(rp.logoutHandler))
	mux.Handle("/auth/callback", http.HandlerFunc(rp.authCallbackHandler))

	// clean up old sessions
	go rp.TidyForever()

	return rp, nil
}

// Handler serves the /auth/* routes. Mount it at "/auth/" on the application's mux.
func (o *OidcRelyingParty) Handler() http.Handler {
	return o.mux
}

type claimsContextKey struct{}

// isNavigation reports whether r is a browser loading a page, as opposed to fetch/XHR,
// a subresource, or an API client. Only navigations should be sent through a login flow:
// fetch() would silently follow the redirect to the OP's HTML and fail on CORS.
func isNavigation(r *http.Request) bool {
	// A redirected POST loses its body, so only GET and HEAD can resume after login.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	// Browsers set Sec-Fetch-* themselves and scripts can't forge it.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
	}
	// No Sec-Fetch-*: an older browser or a non-browser client. Only an explicit
	// text/html counts; curl's default */* does not.
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

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
	cookie, err := r.Cookie("__Host-tinyoidc_session")
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
