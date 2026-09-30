package tinyoidc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer = "https://op.example"
	testClient = "tinyoidc"
	testNonce  = "n0nce"
	testKid    = "k1"
)

func TestVerifyIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rp := &OidcRelyingParty{issuerUrl: testIssuer, clientId: testClient,
		jwks: &Jwks{Keys: []Jwk{jwkFor(testKid, key)}}, jwksFetched: time.Now()}

	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// claims returns valid claims with mut applied.
	claims := func(mut func(*IDTokenClaims)) *IDTokenClaims {
		now := time.Now()
		c := &IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    testIssuer,
				Subject:   "alice",
				Audience:  jwt.ClaimStrings{testClient},
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
			Nonce: testNonce,
		}
		if mut != nil {
			mut(c)
		}
		return c
	}
	sign := func(m jwt.SigningMethod, key any, kid string, c *IDTokenClaims) string {
		tok := jwt.NewWithClaims(m, c)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	rs256 := func(mut func(*IDTokenClaims)) string {
		return sign(jwt.SigningMethodRS256, key, testKid, claims(mut))
	}
	tampered := func() string {
		parts := strings.Split(rs256(nil), ".")
		payload, _ := json.Marshal(claims(func(c *IDTokenClaims) { c.Subject = "mallory" }))
		parts[1] = base64.RawURLEncoding.EncodeToString(payload)
		return strings.Join(parts, ".")
	}

	tests := []struct {
		name  string
		token string
		ok    bool
	}{
		{"valid", rs256(nil), true},
		{"expired", rs256(func(c *IDTokenClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) }), false},
		{"iat in future", rs256(func(c *IDTokenClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) }), false},
		{"alg none", sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, testKid, claims(nil)), false},
		{"HMAC with public key", sign(jwt.SigningMethodHS256, pubPEM, testKid, claims(nil)), false},
		{"wrong aud", rs256(func(c *IDTokenClaims) { c.Audience = jwt.ClaimStrings{"someone-else"} }), false},
		{"multi aud without azp", rs256(func(c *IDTokenClaims) { c.Audience = append(c.Audience, "someone-else") }), false},
		{"wrong iss", rs256(func(c *IDTokenClaims) { c.Issuer = "https://evil.example" }), false},
		{"wrong nonce", rs256(func(c *IDTokenClaims) { c.Nonce = "other" }), false},
		{"unknown kid", sign(jwt.SigningMethodRS256, key, "nope", claims(nil)), false},
		{"tampered payload", tampered(), false},
		{"missing sub", rs256(func(c *IDTokenClaims) { c.Subject = "" }), false},
		{"azp mismatch with single aud", rs256(func(c *IDTokenClaims) { c.Azp = "someone-else" }), false},
		{"azp matching client id", rs256(func(c *IDTokenClaims) { c.Azp = testClient }), true},
		{"multi aud with azp", rs256(func(c *IDTokenClaims) {
			c.Audience = append(c.Audience, "someone-else")
			c.Azp = testClient
		}), true},
		{"unverified email", rs256(func(c *IDTokenClaims) { c.Email = "alice@example.com" }), false},
		{"verified email", rs256(func(c *IDTokenClaims) {
			c.Email = "alice@example.com"
			c.EmailVerified = true
		}), true},
		{"no kid", sign(jwt.SigningMethodRS256, key, "", claims(nil)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rp.verifyIDToken(tt.token, testNonce)
			if (err == nil) != tt.ok {
				t.Errorf("verifyIDToken: err = %v, want ok = %v", err, tt.ok)
			}
		})
	}
}

func jwkFor(kid string, key *rsa.PrivateKey) Jwk {
	return Jwk{Kty: "RSA", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

func TestKeyRefetch(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name        string
		kid         string
		key         *rsa.PrivateKey
		lastFetch   time.Duration // how long ago the cached JWKS was fetched
		ok          bool
		wantFetches int // across 3 verifications
	}{
		{"known kid", "old", oldKey, time.Hour, true, 0},
		{"rotated, cache stale", "new", newKey, time.Hour, true, 1},
		{"rotated, cache fresh", "new", newKey, time.Second, false, 0},
		{"bogus kid is rate-limited", "bogus", newKey, time.Hour, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetches := 0
			op := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fetches++
				json.NewEncoder(w).Encode(Jwks{Keys: []Jwk{jwkFor("new", newKey)}})
			}))
			defer op.Close()

			rp := &OidcRelyingParty{issuerUrl: testIssuer, clientId: testClient,
				fetchedOidcConfig: &OpenIDConfig{JwksUri: op.URL},
				jwks:              &Jwks{Keys: []Jwk{jwkFor("old", oldKey)}},
				jwksFetched:       time.Now().Add(-tt.lastFetch)}

			now := time.Now()
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "alice",
					Audience: jwt.ClaimStrings{testClient}, IssuedAt: jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))},
				Nonce: testNonce,
			})
			tok.Header["kid"] = tt.kid
			raw, err := tok.SignedString(tt.key)
			if err != nil {
				t.Fatal(err)
			}

			for range 3 {
				if _, err := rp.verifyIDToken(raw, testNonce); (err == nil) != tt.ok {
					t.Errorf("verifyIDToken: err = %v, want ok = %v", err, tt.ok)
				}
			}
			if fetches != tt.wantFetches {
				t.Errorf("fetches = %d, want %d", fetches, tt.wantFetches)
			}
		})
	}
}

func TestTidy(t *testing.T) {
	now := time.Now()
	session := func(exp time.Time) *ActiveSession {
		return &ActiveSession{claims: &IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(exp)}}}
	}
	rp := &OidcRelyingParty{
		pendingSessions: map[string]*ClientCookie{
			"fresh": {created: now},
			"stale": {created: now.Add(-11 * time.Minute)},
		},
		activeSessions: map[string]*ActiveSession{
			"live":    session(now.Add(time.Hour)),
			"expired": session(now.Add(-time.Hour)),
		},
	}
	rp.tidy()
	if _, ok := rp.pendingSessions["fresh"]; !ok || len(rp.pendingSessions) != 1 {
		t.Errorf("pendingSessions = %v, want only fresh", rp.pendingSessions)
	}
	if _, ok := rp.activeSessions["live"]; !ok || len(rp.activeSessions) != 1 {
		t.Errorf("activeSessions = %v, want only live", rp.activeSessions)
	}
}

func TestClose(t *testing.T) {
	rp := &OidcRelyingParty{stop: make(chan struct{}), tidyDone: make(chan struct{})}
	go rp.tidyLoop()

	done := make(chan struct{})
	go func() {
		rp.Close()
		rp.Close() // a second Close must not panic or block
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not return")
	}
}

func TestRsaKey(t *testing.T) {
	strong, _ := rsa.GenerateKey(rand.Reader, 2048)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)

	jwks := &Jwks{Keys: []Jwk{
		jwkFor("strong", strong),
		jwkFor("weak", weak),
		// A key the OP published without a kid.
		jwkFor("", strong),
		// An exponent too wide for an int, which Int64 would silently truncate
		// into some other, wrong, exponent.
		{Kty: "RSA", Kid: "huge-e", N: jwkFor("strong", strong).N,
			E: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 16))},
		// An exponent Go's rsa package would reject anyway.
		{Kty: "RSA", Kid: "zero-e", N: jwkFor("strong", strong).N,
			E: base64.RawURLEncoding.EncodeToString([]byte{0})},
	}}

	tests := []struct {
		name    string
		kid     string
		wantKey bool
		wantErr bool
	}{
		{"known kid", "strong", true, false},
		{"unknown kid is not an error", "nope", false, false},
		{"short modulus rejected", "weak", false, true},
		{"empty kid never matches", "", false, false},
		{"oversized exponent rejected", "huge-e", false, true},
		{"zero exponent rejected", "zero-e", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := jwks.rsaKey(tt.kid)
			if (k != nil) != tt.wantKey || (err != nil) != tt.wantErr {
				t.Errorf("rsaKey(%q) = %v, %v; want key = %v, err = %v",
					tt.kid, k, err, tt.wantKey, tt.wantErr)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		raw string
		ok  bool
	}{
		{"https://op.example/token", true},
		{"https://op.example:8443/token", true},
		{"http://localhost:5556/dex/token", true},
		{"http://127.0.0.1:5556/token", true},
		{"http://[::1]:5556/token", true},
		{"http://op.example/token", false}, // plaintext off-host
		{"http://127.0.0.1.evil.example/", false},
		{"https://user:pw@op.example/token", false},
		{"ftp://op.example/token", false},
		{"file:///etc/passwd", false},
		{"/token", false}, // relative
		{"", false},
		{"://nonsense", false},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if err := validateEndpoint(tt.raw); (err == nil) != tt.ok {
				t.Errorf("validateEndpoint(%q) = %v, want ok = %v", tt.raw, err, tt.ok)
			}
		})
	}
}

// TestLoginHandlerPendingCap checks that an unauthenticated flood of /auth/login can't
// grow the pending store without bound.
func TestLoginHandlerPendingCap(t *testing.T) {
	rp := &OidcRelyingParty{
		clientId:          testClient,
		fetchedOidcConfig: &OpenIDConfig{AuthorizationEndpoint: "https://op.example/authorize"},
		pendingSessions:   make(map[string]*ClientCookie),
		activeSessions:    make(map[string]*ActiveSession),
	}
	for i := range maxPendingSessions {
		w := httptest.NewRecorder()
		rp.loginHandler(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if w.Code != http.StatusFound {
			t.Fatalf("login %d: status = %d, want %d", i, w.Code, http.StatusFound)
		}
	}

	w := httptest.NewRecorder()
	rp.loginHandler(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("login past the cap: status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if n := len(rp.pendingSessions); n != maxPendingSessions {
		t.Errorf("pendingSessions = %d, want %d", n, maxPendingSessions)
	}
}
