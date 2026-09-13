package tinyoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
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
	rp := &OidcRelyingParty{issuerUrl: testIssuer, clientId: testClient, jwks: &Jwks{}}
	rp.jwks.Keys = append(rp.jwks.Keys, struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	}{"RSA", testKid,
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())})

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
