package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestTokenGenerator(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given a token generator method with a random secret", t, func() {
		secret := make([]byte, 50)
		rand.Read(secret)

		method := SigningMethodHMAC(secret, Size512)
		generator := NewTokenGenerator(method)

		Convey("When a token is signed", func() {

			token := generator.Create()
			token.Claims["foo"] = "bar"

			str, err := generator.Sign(token)
			So(err, ShouldBeNil)

			Convey("Then the token should be valid", func() {
				parsed, err := generator.Verify(str)
				So(err, ShouldBeNil)

				So(parsed.Claims["foo"], ShouldEqual, "bar")
			})
		})

		Convey("When an expired token is signed", func() {

			token := generator.Create()
			token.Claims["exp"] = time.Now().Add(-time.Hour).Unix()
			token.Claims["foo"] = "bar"

			str, err := generator.Sign(token)
			So(err, ShouldBeNil)

			Convey("Then the token should be invalid", func() {
				parsed, err := generator.Verify(str)
				So(parsed, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When an invalid token is verified", func() {
			parsed, err := generator.Verify("invalid_token")

			Convey("Then an error should be returned", func() {
				So(parsed, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When an token with an invalid alg is verified", func() {
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			So(err, ShouldBeNil)

			keygen := SimpleRSAKeyGen(key)
			methodRSA := SigningMethodRSAPSS(keygen, Size256)
			generatorRSA := NewTokenGenerator(methodRSA)

			token := generatorRSA.Create()
			str, err := generatorRSA.Sign(token)
			So(err, ShouldBeNil)

			Convey("Then an error should be returned", func() {
				parsed, err := generator.Verify(str)
				So(parsed, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func NewMockTokenGenerator() *TokenGenerator {
	method := NewMockSigningMethod()
	return NewTokenGenerator(method)
}
