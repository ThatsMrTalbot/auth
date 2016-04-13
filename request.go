//go:generate ffjson -noencoder $GOFILE

package auth

import (
	"net/http"
	"strings"

	"github.com/pquerna/ffjson/ffjson"
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
		decoder := ffjson.NewDecoder()
		err := decoder.DecodeReader(r.Body, request)
		if err != nil {
			return nil, err
		}
	}

	return request, nil
}
