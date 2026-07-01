// internal/auth/keys.go
// RSA and EC public key parsing from JWK JSON representations.
// These functions are used by the JWKS cache in jwt.go.
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// rsaJWK is the JSON structure for an RSA public key in JWK format.
type rsaJWK struct {
	N string `json:"n"` // Base64URL-encoded modulus
	E string `json:"e"` // Base64URL-encoded public exponent
}

// ecJWK is the JSON structure for an EC public key in JWK format.
type ecJWK struct {
	Crv string `json:"crv"` // Curve name: P-256, P-384, P-521
	X   string `json:"x"`   // Base64URL-encoded X coordinate
	Y   string `json:"y"`   // Base64URL-encoded Y coordinate
}

// parseRSAKey parses a JWK RSA public key.
func parseRSAKey(raw json.RawMessage) (*rsa.PublicKey, error) {
	var k rsaJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("unmarshalling RSA JWK: %w", err)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// parseECKey parses a JWK EC public key.
func parseECKey(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var k ecJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("unmarshalling EC JWK: %w", err)
	}

	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", k.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding EC X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding EC Y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
