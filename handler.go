package auth

import (
	"encoding/json"
	"net/http"

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

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response := &Response{}

	defer func() {
		encoder := json.NewEncoder(w)
		encoder.Encode(response)
	}()

	req, err := ParseRequest(r)
	if err != nil {
		response.Error = err.Error()
		return
	}

	token, err := h.auth.Authenticate(req.Username, req.Password)
	if err != nil {
		response.Error = err.Error()
		return
	}

	response.Token = token
}

// UID parses the UID from the request
func (h *Handler) UID(r *http.Request) (string, error) {
	req, err := ParseRequest(r)
	if err != nil {
		return "", err
	}

	return h.auth.Validate(req.Token)
}

// UID get the uid of the context
func UID(ctx context.Context) string {
	if uid, ok := ctx.Value(contextKey).(string); ok {
		return uid
	}
	return ""
}

// NewContext stores a uid in the context
func NewContext(ctx context.Context, uid string) context.Context {
	return context.WithValue(ctx, contextKey, uid)
}
