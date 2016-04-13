package auth

// Response is a login response
type Response struct {
	Error string `json:"error,omitempty"`
	Token string `json:"token,omitempty"`
}
