package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Provider manages the RS256 signing key and JWKS.
type Provider struct {
	signingKey *jose.JSONWebKey
	jwks       jose.JSONWebKeySet
}

// NewProvider loads or generates an RSA key. keyDir empty => ephemeral.
func NewProvider(keyDir string) (*Provider, error) {
	var key *rsa.PrivateKey
	var err error
	if keyDir != "" {
		key, err = loadOrCreateKey(filepath.Join(keyDir, "rsa.pem"))
		if err != nil {
			return nil, err
		}
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}
	kid := "cert-built-in"
	pub := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return &Provider{
		signingKey: &jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"},
		jwks:       jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}},
	}, nil
}

// JWKS returns the public keyset.
func (p *Provider) JWKS() jose.JSONWebKeySet { return p.jwks }

// SignIDToken issues an RS256-signed ID token.
func (p *Provider) SignIDToken(issuer, subject, audience, nonce string, claims map[string]any, ttl time.Duration) (string, error) {
	now := time.Now()
	reg := jwt.Claims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  jwt.Audience{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now),
	}
	if nonce != "" {
		if claims == nil {
			claims = map[string]any{}
		}
		claims["nonce"] = nonce
	}
	opts := &jose.SignerOptions{}
	opts.WithHeader("kid", p.signingKey.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.signingKey.Key}, opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(signer).Claims(reg)
	if len(claims) > 0 {
		builder = builder.Claims(claims)
	}
	return builder.Serialize()
}

func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return k, nil
			}
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk, nil
				}
			}
		}
		return nil, errors.New("oidc: invalid RSA key file")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
