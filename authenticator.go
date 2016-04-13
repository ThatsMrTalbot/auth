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
	u, err := a.storage.Authenticate(user, pass)
	if err != nil {
		return "", err
	}

	return a.Generate(u)
}

// Validate token and return UID
func (a *Authenticator) Validate(token string) (*User, error) {
	parsed, err := a.generator.Verify(token)
	if err != nil {
		return nil, err
	}

	uid, ok := parsed.Claims["uid"].(string)
	if !ok {
		return nil, ErrTokenInvalid
	}

	permissions, ok := parsed.Claims["permissions"].([]interface{})
	if !ok {
		return nil, ErrTokenInvalid
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

	return user, nil
}

// Generate token for UID
func (a *Authenticator) Generate(user *User) (string, error) {
	token := a.generator.Create()

	if a.lifetime > 0 {
		token.Claims["exp"] = time.Now().Add(a.lifetime).Unix()
	}

	token.Claims["uid"] = user.UID
	token.Claims["permissions"] = []string{}
	if user.Permissions != nil {
		token.Claims["permissions"] = user.Permissions
	}

	return a.generator.Sign(token)
}
