package tinyoidc

import (
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
