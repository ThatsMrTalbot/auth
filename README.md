# Auth
_Simple auth using JWT tokens_

[![Coverage Status](https://coveralls.io/repos/github/ThatsMrTalbot/auth/badge.svg?branch=master)](https://coveralls.io/github/ThatsMrTalbot/auth?branch=master) [![Build Status](https://travis-ci.org/ThatsMrTalbot/auth.svg?branch=master)](https://travis-ci.org/ThatsMrTalbot/auth) [![GoDoc](https://godoc.org/github.com/ThatsMrTalbot/auth?status.svg)](https://godoc.org/github.com/ThatsMrTalbot/auth)

## Example - the login handler

```go
secret := make([]byte, 20)
rand.Read(secret)
// Signing method is used to sign tokens
signingMethod := auth.SigningMethodHMAC(secret, auth.Size256)

// TokenGenerator is used to create/verify tokens
tokenGenerator := auth.NewTokenGenerator(signingMethod)

// Authenticator authenticates logins and creates a token
authenticator := auth.NewAuthenticator(tokenGenerator, storage, time.Hour)

// Handler implements http.Handler and handles logins
handler := auth.NewHandler(authenticator)

http.Handle("/auth", handler)
http.ListenAndServe(:8080, nil)
```

### OR

```go
secret := make([]byte, 20)
rand.Read(secret)
// Signing method is used to sign tokens
signingMethod := auth.SigningMethodHMAC(secret, auth.Size256)

// Handler implements http.Handler and handles logins
handler, authenticator := auth.NewHandlerAndAuthenticator(signingMethod, storage, time.Hour))

http.Handle("/auth", handler)
http.ListenAndServe(:8080, nil)
```

## Example - getting the users information

```go

func SomeHandlerOrMiddleware(w http.ResponseWriter, r *http.Request) {
    user, _ := handler.UserFromRequest(r);
    
    // You can also store and retrieve from a context
    ctx := context.Background()
    ctx = auth.NewUserContext(ctx, user)
    
    userFromContext := auth.UserFromContext(ctx)
}
```
