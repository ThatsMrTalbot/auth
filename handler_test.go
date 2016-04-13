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

		Convey("When logging in with valid JSON", func() {

			body := `{"username": "test_user", "password": "test_pass"}`
			response, err := http.Post(server.URL, "application/json", strings.NewReader(body))
			So(err, ShouldBeNil)

			Convey("Then the response should contain a valid token", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldNotContainKey, "error")
				So(body, ShouldContainKey, "token")
				So(body["token"], ShouldNotBeEmpty)
			})
		})

		Convey("When logging in with valid POST data", func() {
			response, err := http.PostForm(server.URL, url.Values{
				"username": []string{"test_user"},
				"password": []string{"test_pass"},
			})
			So(err, ShouldBeNil)

			Convey("Then the response should contain a valid token", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldNotContainKey, "error")
				So(body, ShouldContainKey, "token")
				So(body["token"], ShouldNotBeEmpty)
			})
		})

		Convey("When logging in with incorrect user details in valid JSON", func() {

			body := `{"username": "invalid", "password": "invalid"}`
			response, err := http.Post(server.URL, "application/json", strings.NewReader(body))
			So(err, ShouldBeNil)

			Convey("Then the response should contain an error", func() {
				body := make(map[string]string)
				decoder := json.NewDecoder(response.Body)
				err := decoder.Decode(&body)

				So(err, ShouldBeNil)
				So(body, ShouldContainKey, "error")
				So(body, ShouldNotContainKey, "token")
				So(body["error"], ShouldNotBeEmpty)
			})
		})

		Convey("When logging in with invalid JSON", func() {
			response, err := http.Post(server.URL, "application/json", strings.NewReader(""))
			So(err, ShouldBeNil)

			Convey("Then the response should contain an error", func() {
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

	Convey("Given a server request with a valid token in the POST data", t, func() {
		handler := NewMockHandler()

		user := NewMockUser("someid")
		token, err := handler.auth.Generate(user)
		So(err, ShouldBeNil)

		data := url.Values{"token": []string{token}}
		req, err := http.NewRequest("POST", "/", strings.NewReader(data.Encode()))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		Convey("When the request is parsed", func() {
			user, err := handler.UserFromRequest(req)

			Convey("Then the user data should be returned", func() {
				So(user, ShouldNotBeNil)
				So(user.UID, ShouldEqual, "someid")
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given a server request with a valid token using JSON data", t, func() {
		handler := NewMockHandler()

		user := NewMockUser("someid")
		token, err := handler.auth.Generate(user)
		So(err, ShouldBeNil)

		data := fmt.Sprintf(`{"token":"%s"}`, token)
		req, err := http.NewRequest("POST", "/", strings.NewReader(data))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/json")

		Convey("When request is parsed", func() {
			user, err := handler.UserFromRequest(req)

			Convey("Then the user data should be returned", func() {
				So(user, ShouldNotBeNil)
				So(user.UID, ShouldEqual, "someid")
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given a server request with invalid JSON data", t, func() {
		handler := NewMockHandler()

		req, err := http.NewRequest("POST", "/", strings.NewReader(""))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/json")

		Convey("When request is parsed", func() {
			user, err := handler.UserFromRequest(req)

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an context instance", t, func() {
		ctx := context.Background()

		Convey("When context with user information is created", func() {
			user := NewMockUser("someid")
			ctx = NewUserContext(ctx, user)

			Convey("Then the user information should be in the context", func() {
				retrieved := UserFromContext(ctx)
				So(retrieved, ShouldResemble, user)
			})
		})
	})

	Convey("Given an context instance", t, func() {
		ctx := context.Background()

		Convey("When no user information in the context", func() {
			Convey("Then no user information should be in the context", func() {
				user := UserFromContext(ctx)
				So(user, ShouldBeNil)
			})
		})
	})
}

func NewMockHandler() *Handler {
	method := NewMockSigningMethod()
	storage := NewMockStorage("test_uid", "test_user", "test_pass", []string{"permission1", "permission2"})
	handler, _ := NewHandlerAndAuthenticator(method, storage, time.Hour)
	return handler
}
