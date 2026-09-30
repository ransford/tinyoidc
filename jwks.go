package tinyoidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
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

// minRsaKeyBits is the smallest modulus we'll verify a signature with. Go's rsa
// package enforces no minimum, so a JWKS naming a short key would otherwise be
// accepted and its signatures forgeable.
const minRsaKeyBits = 2048

// rsaKey returns the RSA key with the given kid, or nil if jwks has none. An empty kid
// never matches: a token with no kid must not silently pick up a key with none either.
func (j *Jwks) rsaKey(kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, nil
	}
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
		// A public exponent wider than an int would be silently truncated into
		// some other, wrong, exponent by Int64.
		bigE := new(big.Int).SetBytes(e)
		if !bigE.IsInt64() || bigE.Int64() < 3 || bigE.Int64() > math.MaxInt32 {
			return nil, fmt.Errorf("kid %q: unusable RSA exponent", kid)
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(bigE.Int64())}
		if bits := key.N.BitLen(); bits < minRsaKeyBits {
			return nil, fmt.Errorf("kid %q: RSA modulus is %d bits, want >= %d",
				kid, bits, minRsaKeyBits)
		}
		return key, nil
	}
	return nil, nil
}
