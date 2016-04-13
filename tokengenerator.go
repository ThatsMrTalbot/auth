package auth

import (
	"errors"

	"gopkg.in/dgrijalva/jwt-go.v2"
)

// Errors returned from TokenGenerator
var (
	ErrTokenInvalid = errors.New("Token is invalid")
)

// TokenGenerator generates and verifies tokens
type TokenGenerator struct {
	method SigningMethod
}

// NewTokenGenerator creates a new token generator
func NewTokenGenerator(method SigningMethod) *TokenGenerator {
	return &TokenGenerator{
		method: method,
	}
}

// Create creates a new token using the correct method
func (t *TokenGenerator) Create() *jwt.Token {
	return jwt.New(t.method.Method())
}

// Sign signs the token and returns its string
func (t *TokenGenerator) Sign(token *jwt.Token) (string, error) {
	kid := t.method.KID()

	token.Header["kid"] = kid
	return token.SignedString(t.method.PrivateKey(kid))
}

// Verify verifies and parses a token string
func (t *TokenGenerator) Verify(str string) (*jwt.Token, error) {
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		if token.Header["alg"] != t.method.Method().Alg() {
			return nil, ErrTokenInvalid
		}

		return t.method.PublicKey(token.Header["kid"]), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}
