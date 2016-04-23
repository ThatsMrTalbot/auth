//go:generate ffjson -nodecoder $GOFILE

package auth

// Response is a login response
type Response struct {
	Error        string `json:"error,omitempty"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
