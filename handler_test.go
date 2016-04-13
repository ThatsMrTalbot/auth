package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHandler(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given an test server", t, func() {
		handler := NewMockHandler()
		server := httptest.NewServer(handler)

		Convey("When the handler is requested with valid login JSON", func() {

			body := `{"username": "test_user", "password": "test_pass"}`
			response, err := http.Post(server.URL, "application/json", strings.NewReader(body))
			So(err, ShouldBeNil)

			Convey("The response contains a valid token", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldNotContainKey, "error")
				So(body, ShouldContainKey, "token")
				So(body["token"], ShouldNotBeEmpty)
			})
		})

		Convey("When the handler is requested with valid login post data", func() {
			response, err := http.PostForm(server.URL, url.Values{
				"username": []string{"test_user"},
				"password": []string{"test_pass"},
			})
			So(err, ShouldBeNil)

			Convey("The response contains a valid token", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldNotContainKey, "error")
				So(body, ShouldContainKey, "token")
				So(body["token"], ShouldNotBeEmpty)
			})
		})

		Convey("When the handler is requested with invalid login JSON", func() {

			body := `{"username": "invalid", "password": "invalid"}`
			response, err := http.Post(server.URL, "application/json", strings.NewReader(body))
			So(err, ShouldBeNil)

			Convey("The response contains a valid token", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldContainKey, "error")
				So(body, ShouldNotContainKey, "token")
				So(body["error"], ShouldNotBeEmpty)
			})
		})

		Convey("When the handler is requested with invalid body", func() {
			response, err := http.Post(server.URL, "application/json", strings.NewReader(""))
			So(err, ShouldBeNil)

			Convey("The response contains a valid token", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldContainKey, "error")
				So(body, ShouldNotContainKey, "token")
				So(body["error"], ShouldNotBeEmpty)
			})
		})
	})

	Convey("Given an valid token post value in a request", t, func() {
		handler := NewMockHandler()

		token, err := handler.auth.Generate("someid")
		So(err, ShouldBeNil)

		data := url.Values{"token": []string{token}}
		req, err := http.NewRequest("POST", "/", strings.NewReader(data.Encode()))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		Convey("When request is parsed", func() {
			uid, err := handler.UID(req)

			Convey("Then the uid should correct", func() {
				So(uid, ShouldEqual, "someid")
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given an valid token JSON in a request", t, func() {
		handler := NewMockHandler()

		token, err := handler.auth.Generate("someid")
		So(err, ShouldBeNil)

		data := fmt.Sprintf(`{"token":"%s"}`, token)
		req, err := http.NewRequest("POST", "/", strings.NewReader(data))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/json")

		Convey("When request is parsed", func() {
			uid, err := handler.UID(req)

			Convey("Then the uid should correct", func() {
				So(uid, ShouldEqual, "someid")
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given an invalid JSON data in a request", t, func() {
		handler := NewMockHandler()

		req, err := http.NewRequest("POST", "/", strings.NewReader(""))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/json")

		Convey("When request is parsed", func() {
			uid, err := handler.UID(req)

			Convey("Then the uid should empty", func() {
				So(uid, ShouldBeEmpty)
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an context instance", t, func() {
		ctx := context.Background()

		Convey("When context with uid is created", func() {
			ctx = NewContext(ctx, "someid")

			Convey("Then the uid should be in the context", func() {
				uid := UID(ctx)
				So(uid, ShouldEqual, "someid")
			})
		})
	})

	Convey("Given an context instance", t, func() {
		ctx := context.Background()

		Convey("When no uid is in the context", func() {
			Convey("Then the uid should not be in the context", func() {
				uid := UID(ctx)
				So(uid, ShouldBeEmpty)
			})
		})
	})
}

func NewMockHandler() *Handler {
	method := NewMockSigningMethod()
	storage := NewMockStorage("test_uid", "test_user", "test_pass")
	handler, _ := NewHandlerAndAuthenticator(method, storage, time.Hour)
	return handler
}
