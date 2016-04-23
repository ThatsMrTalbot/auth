package auth

import (
	"net/http"
	"time"

	"github.com/pquerna/ffjson/ffjson"

	"golang.org/x/net/context"
)

const (
	contextKey = "uid"
)

// Handler is a login handler
type Handler struct {
	auth *Authenticator
}

// NewHandler creates a new login handler
func NewHandler(auth *Authenticator) *Handler {
	return &Handler{
		auth: auth,
	}
}

// NewHandlerAndAuthenticator creates a new login handler and Authenticator
func NewHandlerAndAuthenticator(method SigningMethod, storage Storage, lifetime time.Duration, refreshLifetime time.Duration) (*Handler, *Authenticator) {
	generator := NewTokenGenerator(method)
	auth := NewAuthenticator(generator, storage, lifetime, refreshLifetime)
	return NewHandler(auth), auth
}

// CtxServeHTTP implements scaffold.Handler
func (h *Handler) CtxServeHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	response := &Response{}

	defer func() {
		encoder := ffjson.NewEncoder(w)
		encoder.Encode(response)
	}()

	req, err := ParseRequest(r)
	if err != nil {
		response.Error = err.Error()
		return
	}

	var token, refresh string

	if req.Refresh != "" {
		var user *User
		user, err = h.auth.ValidateRefresh(req.Refresh)
		if err != nil {
			response.Error = err.Error()
			return
		}
		token, err = h.auth.Generate(user)
		if err != nil {
			response.Error = err.Error()
			return
		}
		refresh, err = h.auth.GenerateRefresh(user)
		if err != nil {
			response.Error = err.Error()
			return
		}
	} else {
		token, refresh, err = h.auth.Authenticate(req.Username, req.Password)
		if err != nil {
			response.Error = err.Error()
			return
		}
	}

	response.Token = token
	response.RefreshToken = refresh
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.CtxServeHTTP(nil, w, r)
}

// UserFromRequest parses the UID from the request
func (h *Handler) UserFromRequest(r *http.Request) (*User, error) {
	req, err := ParseRequest(r)
	if err != nil {
		return nil, err
	}

	user, err := h.auth.ValidateToken(req.Token)

	return user, nil
}

// UserFromContext get the uid of the context
func UserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(contextKey).(*User); ok {
		return user
	}
	return nil
}

// NewUserContext stores a user information in the context
func NewUserContext(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, contextKey, user)
}
