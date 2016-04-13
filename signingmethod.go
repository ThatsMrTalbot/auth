package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"

	"gopkg.in/dgrijalva/jwt-go.v2"
)

// Size is the signature size
type Size int

// Size vars
const (
	Size256 Size = 256
	Size384 Size = 384
	Size512 Size = 512
)

// SigningMethod generates public and private keys
type SigningMethod interface {
	KID() interface{}
	PublicKey(interface{}) interface{}
	PrivateKey(interface{}) interface{}
	Method() jwt.SigningMethod
}

type signingMethodHMAC struct {
	secret []byte
	method *jwt.SigningMethodHMAC
}

func (s *signingMethodHMAC) KID() interface{} {
	kid := make([]byte, 10)
	rand.Read(kid)
	return base64.StdEncoding.EncodeToString(kid)
}

func (s *signingMethodHMAC) PublicKey(kid interface{}) interface{} {
	hash := sha1.New()
	binary.Write(hash, binary.BigEndian, s.secret)
	binary.Write(hash, binary.BigEndian, kid)
	return hash.Sum(nil)
}

func (s *signingMethodHMAC) PrivateKey(kid interface{}) interface{} {
	return s.PublicKey(kid)
}

func (s *signingMethodHMAC) Method() jwt.SigningMethod {
	return s.method
}

// SigningMethodHMAC implements SigningMethod based off a secret
func SigningMethodHMAC(secret []byte, size Size) SigningMethod {
	var method *jwt.SigningMethodHMAC

	switch size {
	case Size256:
		method = jwt.SigningMethodHS256
	case Size384:
		method = jwt.SigningMethodHS384
	case Size512:
		method = jwt.SigningMethodHS512
	}

	return &signingMethodHMAC{
		secret: secret,
		method: method,
	}
}

// ECDSAKeyGen gets ecdsa keys based on an id
type ECDSAKeyGen interface {
	KID() interface{}
	Key(kid interface{}) *ecdsa.PrivateKey
}

type simpleECDSAKeyGen struct {
	key *ecdsa.PrivateKey
}

func (s *simpleECDSAKeyGen) KID() interface{} {
	return nil
}

func (s *simpleECDSAKeyGen) Key(kid interface{}) *ecdsa.PrivateKey {
	return s.key
}

// SimpleECDSAKeyGen ignores the kid and returnes a consitent private key
func SimpleECDSAKeyGen(key *ecdsa.PrivateKey) ECDSAKeyGen {
	return &simpleECDSAKeyGen{
		key: key,
	}
}

type signingMethodECDSA struct {
	keygen ECDSAKeyGen
	method *jwt.SigningMethodECDSA
}

// SigningMethodECDSA implements SigningMethod based off a private key
func SigningMethodECDSA(keygen ECDSAKeyGen, size Size) SigningMethod {
	var method *jwt.SigningMethodECDSA

	switch size {
	case Size256:
		method = jwt.SigningMethodES256
	case Size384:
		method = jwt.SigningMethodES384
	case Size512:
		method = jwt.SigningMethodES512
	}

	return &signingMethodECDSA{
		keygen: keygen,
		method: method,
	}
}

func (s *signingMethodECDSA) KID() interface{} {
	return s.keygen.KID()
}

func (s *signingMethodECDSA) PublicKey(kid interface{}) interface{} {
	return &(s.keygen.Key(kid).PublicKey)
}

func (s *signingMethodECDSA) PrivateKey(kid interface{}) interface{} {
	return s.keygen.Key(kid)
}

func (s *signingMethodECDSA) Method() jwt.SigningMethod {
	return s.method
}

// RSAKeyGen gets rsa keys based on an id
type RSAKeyGen interface {
	KID() interface{}
	Key(kid interface{}) *rsa.PrivateKey
}

type simpleRSAKeyGen struct {
	key *rsa.PrivateKey
}

func (s *simpleRSAKeyGen) KID() interface{} {
	return nil
}

func (s *simpleRSAKeyGen) Key(kid interface{}) *rsa.PrivateKey {
	return s.key
}

// SimpleRSAKeyGen ignores the kid and returnes a consitent private key
func SimpleRSAKeyGen(key *rsa.PrivateKey) RSAKeyGen {
	return &simpleRSAKeyGen{
		key: key,
	}
}

type signingMethodRSA struct {
	keygen RSAKeyGen
	method *jwt.SigningMethodRSA
}

// SigningMethodRSA implements SigningMethod based off a private key
func SigningMethodRSA(keygen RSAKeyGen, size Size) SigningMethod {
	var method *jwt.SigningMethodRSA

	switch size {
	case Size256:
		method = jwt.SigningMethodRS256
	case Size384:
		method = jwt.SigningMethodRS384
	case Size512:
		method = jwt.SigningMethodRS512
	}

	return &signingMethodRSA{
		keygen: keygen,
		method: method,
	}
}

func (s *signingMethodRSA) KID() interface{} {
	return s.keygen.KID()
}

func (s *signingMethodRSA) PublicKey(kid interface{}) interface{} {
	return &(s.keygen.Key(kid).PublicKey)
}

func (s *signingMethodRSA) PrivateKey(kid interface{}) interface{} {
	return s.keygen.Key(kid)
}

func (s *signingMethodRSA) Method() jwt.SigningMethod {
	return s.method
}

type signingMethodRSAPSS struct {
	keygen RSAKeyGen
	method *jwt.SigningMethodRSAPSS
}

// SigningMethodRSAPSS implements SigningMethod based off a private key
func SigningMethodRSAPSS(keygen RSAKeyGen, size Size) SigningMethod {
	var method *jwt.SigningMethodRSAPSS

	switch size {
	case Size256:
		method = jwt.SigningMethodPS256
	case Size384:
		method = jwt.SigningMethodPS384
	case Size512:
		method = jwt.SigningMethodPS512
	}

	return &signingMethodRSAPSS{
		keygen: keygen,
		method: method,
	}
}

func (s *signingMethodRSAPSS) KID() interface{} {
	return s.keygen.KID()
}

func (s *signingMethodRSAPSS) PublicKey(kid interface{}) interface{} {
	return &(s.keygen.Key(kid).PublicKey)
}

func (s *signingMethodRSAPSS) PrivateKey(kid interface{}) interface{} {
	return s.keygen.Key(kid)
}

func (s *signingMethodRSAPSS) Method() jwt.SigningMethod {
	return s.method
}
