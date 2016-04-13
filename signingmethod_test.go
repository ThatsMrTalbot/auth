package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSigningMethodHMAC(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given a HMAC signing method with a random secret", t, func() {
		secret := make([]byte, 50)
		rand.Read(secret)

		method1 := SigningMethodHMAC(secret, Size256)
		method2 := SigningMethodHMAC(secret, Size384)
		method3 := SigningMethodHMAC(secret, Size512)

		Convey("When a string is signed", func() {

			kid1 := method1.KID()
			kid2 := method2.KID()
			kid3 := method3.KID()

			signed1, err1 := method1.Method().Sign("somestring", method1.PrivateKey(kid1))
			signed2, err2 := method2.Method().Sign("somestring", method2.PrivateKey(kid2))
			signed3, err3 := method3.Method().Sign("somestring", method3.PrivateKey(kid3))

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)

			Convey("Then the signature should be valid", func() {
				err1 := method1.Method().Verify("somestring", signed1, method1.PublicKey(kid1))
				err2 := method2.Method().Verify("somestring", signed2, method2.PublicKey(kid2))
				err3 := method3.Method().Verify("somestring", signed3, method3.PublicKey(kid3))

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(err3, ShouldBeNil)
			})
		})
	})
}

func TestSigningMethodECDSA(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given a ECDSA signing method with a random key", t, func() {
		curve1 := elliptic.P256()
		curve2 := elliptic.P384()
		curve3 := elliptic.P521()

		key1, err1 := ecdsa.GenerateKey(curve1, rand.Reader)
		key2, err2 := ecdsa.GenerateKey(curve2, rand.Reader)
		key3, err3 := ecdsa.GenerateKey(curve3, rand.Reader)

		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		So(err3, ShouldBeNil)

		keygen1 := SimpleECDSAKeyGen(key1)
		keygen2 := SimpleECDSAKeyGen(key2)
		keygen3 := SimpleECDSAKeyGen(key3)

		method1 := SigningMethodECDSA(keygen1, Size256)
		method2 := SigningMethodECDSA(keygen2, Size384)
		method3 := SigningMethodECDSA(keygen3, Size512)

		Convey("When a string is signed", func() {

			kid1 := method1.KID()
			kid2 := method2.KID()
			kid3 := method3.KID()

			signed1, err1 := method1.Method().Sign("somestring", method1.PrivateKey(kid1))
			signed2, err2 := method2.Method().Sign("somestring", method2.PrivateKey(kid2))
			signed3, err3 := method3.Method().Sign("somestring", method3.PrivateKey(kid3))

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)

			Convey("Then the signature should be valid", func() {
				err1 := method1.Method().Verify("somestring", signed1, method1.PublicKey(kid1))
				err2 := method2.Method().Verify("somestring", signed2, method2.PublicKey(kid2))
				err3 := method3.Method().Verify("somestring", signed3, method3.PublicKey(kid3))

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(err3, ShouldBeNil)
			})
		})
	})
}

func TestSigningMethodRSA(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given a RSA signing method with a random key", t, func() {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		So(err, ShouldBeNil)

		keygen := SimpleRSAKeyGen(key)

		method1 := SigningMethodRSA(keygen, Size256)
		method2 := SigningMethodRSA(keygen, Size384)
		method3 := SigningMethodRSA(keygen, Size512)

		Convey("When a string is signed", func() {

			kid1 := method1.KID()
			kid2 := method2.KID()
			kid3 := method3.KID()

			signed1, err1 := method1.Method().Sign("somestring", method1.PrivateKey(kid1))
			signed2, err2 := method2.Method().Sign("somestring", method2.PrivateKey(kid2))
			signed3, err3 := method3.Method().Sign("somestring", method3.PrivateKey(kid3))

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)

			Convey("Then the signature should be valid", func() {
				err1 := method1.Method().Verify("somestring", signed1, method1.PublicKey(kid1))
				err2 := method2.Method().Verify("somestring", signed2, method2.PublicKey(kid2))
				err3 := method3.Method().Verify("somestring", signed3, method3.PublicKey(kid3))

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(err3, ShouldBeNil)
			})
		})
	})
}

func TestSigningMethodRSAPSS(t *testing.T) {
	if !testing.Verbose() {
		t.Parallel()
	}

	Convey("Given a RSAPSS signing method with a random key", t, func() {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		So(err, ShouldBeNil)

		keygen := SimpleRSAKeyGen(key)

		method1 := SigningMethodRSAPSS(keygen, Size256)
		method2 := SigningMethodRSAPSS(keygen, Size384)
		method3 := SigningMethodRSAPSS(keygen, Size512)

		Convey("When a string is signed", func() {

			kid1 := method1.KID()
			kid2 := method2.KID()
			kid3 := method3.KID()

			signed1, err1 := method1.Method().Sign("somestring", method1.PrivateKey(kid1))
			signed2, err2 := method2.Method().Sign("somestring", method2.PrivateKey(kid2))
			signed3, err3 := method3.Method().Sign("somestring", method3.PrivateKey(kid3))

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)

			Convey("Then the signature should be valid", func() {
				err1 := method1.Method().Verify("somestring", signed1, method1.PublicKey(kid1))
				err2 := method2.Method().Verify("somestring", signed2, method2.PublicKey(kid2))
				err3 := method3.Method().Verify("somestring", signed3, method3.PublicKey(kid3))

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(err3, ShouldBeNil)
			})
		})
	})
}

func NewMockSigningMethod() SigningMethod {
	secret := make([]byte, 50)
	rand.Read(secret)

	return SigningMethodHMAC(secret, Size512)
}
