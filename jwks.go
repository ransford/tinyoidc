package tinyoidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"time"
)

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
	resp, err := getWithTimeout(uri, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
