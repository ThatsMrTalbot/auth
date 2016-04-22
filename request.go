//go:generate ffjson -noencoder $GOFILE

package auth

import (
	"bytes"
	"io"
	"io/ioutil"
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

func reader(r *http.Request) (io.Reader, error) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	rdr1 := bytes.NewReader(buf)
	rdr2 := bytes.NewReader(buf)

	r.Body = ioutil.NopCloser(rdr2)

	return rdr1, nil
}

// ParseRequest parses a request from a http.Request
func ParseRequest(r *http.Request) (*Request, error) {
	request := &Request{
		Token:    r.FormValue("token"),
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}
	contentType := r.Header.Get("Content-Type")

	if tok := r.Header.Get("Bearer"); tok != "" {
		request.Token = tok
	}

	if strings.Contains(contentType, "json") {
		decoder := ffjson.NewDecoder()

		reader, err := reader(r)
		if err != nil {
			return nil, err
		}

		err = decoder.DecodeReader(reader, request)
		if err != nil {
			return nil, err
		}
	}

	return request, nil
}
