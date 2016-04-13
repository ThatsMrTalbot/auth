package auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestParseRequest(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given an request with valid POST parameters", t, func() {
		data := url.Values{
			"username": []string{"test_user"},
			"password": []string{"test_pass"},
			"token":    []string{"test_token"},
		}
		req, err := http.NewRequest("POST", "/auth", strings.NewReader(data.Encode()))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		Convey("When the request is parsed", func() {
			parsed, err := ParseRequest(req)
			So(err, ShouldBeNil)

			Convey("Then the request fields should be returned", func() {
				So(parsed.Username, ShouldEqual, "test_user")
				So(parsed.Username, ShouldEqual, "test_user")
				So(parsed.Token, ShouldEqual, "test_token")
			})
		})
	})

	Convey("Given an request with valid JSON data", t, func() {
		data := `{"username": "test_user", "password": "test_pass", "token": "test_token"}`
		req, err := http.NewRequest("POST", "/auth", strings.NewReader(data))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/json")

		Convey("When the request is parsed", func() {
			parsed, err := ParseRequest(req)
			So(err, ShouldBeNil)

			Convey("hen the request fields should be returned", func() {
				So(parsed.Username, ShouldEqual, "test_user")
				So(parsed.Password, ShouldEqual, "test_pass")
				So(parsed.Token, ShouldEqual, "test_token")
			})
		})
	})

	Convey("Given an request with invalid JSON data", t, func() {
		req, err := http.NewRequest("POST", "/auth", strings.NewReader(""))
		So(err, ShouldBeNil)

		req.Header.Set("Content-Type", "application/json")

		Convey("When the request is parsed", func() {
			parsed, err := ParseRequest(req)

			Convey("Then a parse error should be returned", func() {
				So(err, ShouldNotBeNil)
				So(parsed, ShouldBeNil)
			})
		})
	})
}
