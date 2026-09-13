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
	jwks              *Jwks

	mu              sync.Mutex
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
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type IDTokenClaims struct {
	jwt.RegisteredClaims        // iss, sub, aud, exp, iat
	Nonce                string `json:"nonce"`
	Azp                  string `json:"azp"`
	Email                string `json:"email"`
	EmailVerified        bool   `json:"email_verified"`
}

// keyFor is the jwt.Keyfunc: choose the OP's public key by the token's kid.
func (o *OidcRelyingParty) keyFor(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	for _, k := range o.jwks.Keys {
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
	return nil, fmt.Errorf("no key for kid %q", kid) // later: refetch JWKS once
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

	claims := &IDTokenClaims{}
	_, err = jwt.ParseWithClaims(tokenResponse.IdToken, claims, o.keyFor,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(o.issuerUrl),
		jwt.WithAudience(o.clientId),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Minute),
	)
	if err != nil {
		slog.Error("callback error: validate JWT claims")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`"error: validate JWT"`))
		return
	}
	slog.Debug("JWT claims", "claims", claims)
	if claims.Nonce != session.Nonce { /* 401 */
		slog.Error("callback error: nonce mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`"error: nonce mismatch"`))
		return
	}
	if len(claims.Audience) > 1 && claims.Azp != o.clientId {
		slog.Error("callback error: audience mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`"error: audience mismatch"`))
		return
	}
	if claims.Subject == "" {
		slog.Error("callback error: empty subject")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`"error: empty subject"`))
		return
	}
	if claims.Email != "" && !claims.EmailVerified {
		slog.Error("callback error: unverified email")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`"error: unverified email"`))
		return
	}

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

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"status": "logged in", "email": "%s"}`, claims.Email)))
}

func (o *OidcRelyingParty) logoutHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: make this be POST or CSRF protected

	var sessionId string

	cookie, err := r.Cookie("__Host-tinyoidc_session")
	if err != nil {
		slog.Error("logout: invalid session")
		w.WriteHeader(http.StatusBadRequest)
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
	w.WriteHeader(http.StatusOK)
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

	// Get the JWKS URI
	slog.Debug("fetching jwks", "jwks_uri", conf.JwksUri)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, conf.JwksUri, nil)
	if err != nil {
		return nil, err
	}
	resp2, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, err
	}
	slog.Debug("jwks", "body", body)
	parsedJwks := Jwks{}
	if err := json.Unmarshal(body, &parsedJwks); err != nil {
		return nil, err
	}
	slog.Debug("parsed jwks", "jwks", parsedJwks)

	rp := &OidcRelyingParty{
		mux:               mux,
		issuerUrl:         DEV_ISSUER_URL,
		clientId:          DEV_CLIENT_ID,
		clientSecret:      DEV_CLIENT_SECRET,
		redirectUri:       fmt.Sprintf("http://localhost:%d/auth/callback", DEFAULT_PORT),
		scopes:            []string{"openid", "email"},
		cookieSigningKey:  cookieSigningKey,
		fetchedOidcConfig: &conf,
		jwks:              &parsedJwks,

		pendingSessions: make(map[string]*ClientCookie),
		activeSessions:  make(map[string]*ActiveSession),
	}

	mux.Handle("/auth/login", http.HandlerFunc(rp.loginHandler))
	mux.Handle("/auth/logout", http.HandlerFunc(rp.logoutHandler))
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

// Middleware passes requests with a valid session through to next, with the
// session's ID token claims in the request context. Everything else is
// redirected to /auth/login.
func (o *OidcRelyingParty) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var session *ActiveSession
		if cookie, err := r.Cookie("__Host-tinyoidc_session"); err == nil {
			o.mu.Lock()
			session = o.activeSessions[cookie.Value]
			o.mu.Unlock()
		}
		if session == nil || time.Now().After(session.claims.ExpiresAt.Time) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), claimsContextKey{}, session.claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
