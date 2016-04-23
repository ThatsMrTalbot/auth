package auth

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAuthenticator(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given an Authenticator", t, func() {
		auth := NewMockAuthenticator("test_uid", "test_user", "test_pass", []string{"permission1", "permission2"})

		Convey("When a valid user is authenticated", func() {
			token, _, err := auth.Authenticate("test_user", "test_pass")

			Convey("Then a token should be generated", func() {
				So(err, ShouldBeNil)
				So(token, ShouldNotBeEmpty)
			})
		})

		Convey("When an invalid user is authenticated", func() {
			token, _, err := auth.Authenticate("invalid_user", "invalid_pass")

			Convey("Then a token should not be generated", func() {
				So(err, ShouldNotBeNil)
				So(token, ShouldBeEmpty)
			})
		})

		Convey("When a valid token validated", func() {
			token, _, err := auth.Authenticate("test_user", "test_pass")
			So(err, ShouldBeNil)

			user, err := auth.ValidateToken(token)

			Convey("Then the user infomation should be returned", func() {
				So(err, ShouldBeNil)
				So(user, ShouldNotBeNil)
				So(user.UID, ShouldEqual, "test_uid")
				So(user.Permissions, ShouldContain, "permission1")
				So(user.Permissions, ShouldContain, "permission2")
			})
		})

		Convey("When a refresh valid token validated", func() {
			_, token, err := auth.Authenticate("test_user", "test_pass")
			So(err, ShouldBeNil)

			user, err := auth.ValidateRefresh(token)

			Convey("Then the user infomation should be returned", func() {
				So(err, ShouldBeNil)
				So(user, ShouldNotBeNil)
				So(user.UID, ShouldEqual, "test_uid")
				So(user.Permissions, ShouldContain, "permission1")
				So(user.Permissions, ShouldContain, "permission2")
			})
		})

		Convey("When an token is validated as a refresh token", func() {
			token, _, err := auth.Authenticate("test_user", "test_pass")
			So(err, ShouldBeNil)

			user, err := auth.ValidateRefresh(token)

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When an refresh token is validated as a token", func() {
			_, token, err := auth.Authenticate("test_user", "test_pass")
			So(err, ShouldBeNil)

			user, err := auth.ValidateToken(token)

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When an invalid token is validated", func() {
			user, err := auth.ValidateToken("bad_token")

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When an invalid refresh token is validated", func() {
			user, err := auth.ValidateRefresh("bad_token")

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token with no UID is validated", func() {
			tok := auth.generator.Create()
			tok.Claims["permissions"] = []string{"permission1"}
			token, err := auth.generator.Sign(tok)
			So(err, ShouldBeNil)

			user, err := auth.ValidateToken(token)

			Convey("hen an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token with invalid permissions is validated", func() {
			tok := auth.generator.Create()
			tok.Claims["uid"] = "uid"
			tok.Claims["type"] = "token"
			token, err := auth.generator.Sign(tok)
			So(err, ShouldBeNil)

			user, err := auth.ValidateToken(token)

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token with invalid type is validated", func() {
			tok := auth.generator.Create()
			tok.Claims["uid"] = "uid"
			tok.Claims["permissions"] = []string{"permission1"}
			token, err := auth.generator.Sign(tok)
			So(err, ShouldBeNil)

			user, err := auth.ValidateToken(token)

			Convey("Then an error should be returned", func() {
				So(user, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func NewMockAuthenticator(uid string, user string, pass string, permissions []string) *Authenticator {
	generator := NewMockTokenGenerator()
	storage := NewMockStorage(uid, user, pass, permissions)

	return NewAuthenticator(generator, storage, time.Hour, time.Hour*24)
}
