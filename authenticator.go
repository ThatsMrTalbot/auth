package auth

import "time"

// Authenticator is user authenticator and token generator
type Authenticator struct {
	generator       *TokenGenerator
	lifetime        time.Duration
	refreshLifetime time.Duration
	storage         Storage
}

// NewAuthenticator creates a Authenticator
func NewAuthenticator(generator *TokenGenerator, storage Storage, lifetime time.Duration, refreshLifetime time.Duration) *Authenticator {
	return &Authenticator{
		generator: generator,
		storage:   storage,
		lifetime:  lifetime,
	}
}

// Authenticate user and generate token
func (a *Authenticator) Authenticate(user string, pass string) (string, string, error) {
	u, err := a.storage.Authenticate(user, pass)
	if err != nil {
		return "", "", err
	}

	token, err := a.Generate(u)
	if err != nil {
		return "", "", err
	}

	refresh, err := a.GenerateRefresh(u)
	if err != nil {
		return "", "", err
	}

	return token, refresh, nil
}

// ValidateToken token and return UID
func (a *Authenticator) ValidateToken(token string) (*User, error) {
	user, typ, err := a.validate(token)
	if err != nil {
		return nil, err
	}
	if typ != "token" {
		return nil, ErrTokenInvalid
	}
	return user, nil
}

// ValidateRefresh refresh token and return UID
func (a *Authenticator) ValidateRefresh(token string) (*User, error) {
	user, typ, err := a.validate(token)
	if err != nil {
		return nil, err
	}
	if typ != "refresh" {
		return nil, ErrTokenInvalid
	}
	return user, nil
}

func (a *Authenticator) validate(token string) (*User, string, error) {
	parsed, err := a.generator.Verify(token)
	if err != nil {
		return nil, "", err
	}

	uid, ok := parsed.Claims["uid"].(string)
	if !ok {
		return nil, "", ErrTokenInvalid
	}

	typ, ok := parsed.Claims["type"].(string)
	if !ok {
		return nil, "", ErrTokenInvalid
	}

	permissions, ok := parsed.Claims["permissions"].([]interface{})
	if !ok {
		return nil, "", ErrTokenInvalid
	}

	user := &User{
		UID:         uid,
		Permissions: make([]string, 0, len(permissions)),
	}

	for _, permission := range permissions {
		if p, ok := permission.(string); ok {
			user.Permissions = append(user.Permissions, p)
		}
	}

	return user, typ, nil
}

// Generate token for UID
func (a *Authenticator) Generate(user *User) (string, error) {
	token := a.generator.Create()

	if a.lifetime > 0 {
		token.Claims["exp"] = time.Now().Add(a.lifetime).Unix()
	}

	token.Claims["uid"] = user.UID
	token.Claims["type"] = "token"
	token.Claims["permissions"] = []string{}
	if user.Permissions != nil {
		token.Claims["permissions"] = user.Permissions
	}

	return a.generator.Sign(token)
}

// GenerateRefresh generates a refresh token for UID
func (a *Authenticator) GenerateRefresh(user *User) (string, error) {
	token := a.generator.Create()

	if a.lifetime > 0 {
		token.Claims["exp"] = time.Now().Add(a.refreshLifetime).Unix()
	}

	token.Claims["uid"] = user.UID
	token.Claims["type"] = "refresh"
	token.Claims["permissions"] = []string{}
	if user.Permissions != nil {
		token.Claims["permissions"] = user.Permissions
	}

	return a.generator.Sign(token)
}
