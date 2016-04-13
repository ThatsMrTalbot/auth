package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Request is a request
type Request struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ParseRequest parses a request from a http.Request
func ParseRequest(r *http.Request) (*Request, error) {
	request := &Request{
		Token:    r.FormValue("token"),
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "json") {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(request)
		if err != nil {
			return nil, err
		}
	}

	return request, nil
}
