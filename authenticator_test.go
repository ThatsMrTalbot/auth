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
		auth := NewMockAuthenticator("test_uid", "test_user", "test_pass")

		Convey("When a valid user is authenticated", func() {
			token, err := auth.Authenticate("test_user", "test_pass")

			Convey("Then a token should be generated", func() {
				So(err, ShouldBeNil)
				So(token, ShouldNotBeEmpty)
			})
		})

		Convey("When an invalid user is authenticated", func() {
			token, err := auth.Authenticate("invalid_user", "invalid_pass")

			Convey("Then a token should not be generated", func() {
				So(err, ShouldNotBeNil)
				So(token, ShouldBeEmpty)
			})
		})

		Convey("When a valid token validated", func() {
			token, err := auth.Authenticate("test_user", "test_pass")
			So(err, ShouldBeNil)

			uid, err := auth.Validate(token)

			Convey("Then the UID should be valid", func() {
				So(uid, ShouldEqual, "test_uid")
				So(err, ShouldBeNil)
			})
		})

		Convey("When an invalid token validated", func() {
			uid, err := auth.Validate("bad_token")

			Convey("Then token should not be validated", func() {
				So(uid, ShouldBeEmpty)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token with no UID is validated", func() {
			tok := auth.generator.Create()
			token, err := auth.generator.Sign(tok)
			So(err, ShouldBeNil)

			uid, err := auth.Validate(token)

			Convey("Then token should not be validated", func() {
				So(uid, ShouldBeEmpty)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func NewMockAuthenticator(uid string, user string, pass string) *Authenticator {
	generator := NewMockTokenGenerator()
	storage := NewMockStorage(uid, user, pass)

	return NewAuthenticator(generator, storage, time.Hour)
}
