package auth

import "time"

// Authenticator is user authenticator and token generator
type Authenticator struct {
	generator *TokenGenerator
	lifetime  time.Duration
	storage   Storage
}

// NewAuthenticator creates a Authenticator
func NewAuthenticator(generator *TokenGenerator, storage Storage, lifetime time.Duration) *Authenticator {
	return &Authenticator{
		generator: generator,
		storage:   storage,
		lifetime:  lifetime,
	}
}

// Authenticate user and generate token
func (a *Authenticator) Authenticate(user string, pass string) (string, error) {
	uid, err := a.storage.GetUser(user, pass)
	if err != nil {
		return "", err
	}

	return a.Generate(uid)
}

// Validate token and return UID
func (a *Authenticator) Validate(token string) (string, error) {
	parsed, err := a.generator.Verify(token)
	if err != nil {
		return "", err
	}

	if uid, ok := parsed.Claims["uid"].(string); ok {
		return uid, nil
	}

	return "", ErrTokenInvalid
}

// Generate token for UID
func (a *Authenticator) Generate(uid string) (string, error) {
	token := a.generator.Create()

	if a.lifetime > 0 {
		token.Claims["exp"] = time.Now().Add(a.lifetime).Unix()
	}

	token.Claims["uid"] = uid

	return a.generator.Sign(token)
}
