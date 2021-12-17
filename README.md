# Go JWT Auth

**Note**: This repo is in the early stages and may change/break.

This repo is meant to be imported into your current Go server and does the work to set up JWT authentication.

## How to use

Install all packages in this repo using: `go get github.com/talhaguy/go-jwt-auth/...`.

Setup as follows:

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/talhaguy/go-jwt-auth/handler"
	"github.com/talhaguy/go-jwt-auth/repository"
	"github.com/talhaguy/go-jwt-auth/route"
)

func main() {
	port := "8080"

	// 1) Create the route handlers struct
	handlers := handler.NewDefaultHandler(
		// 1.1) Use a provided or custom user repository of your choice
		repository.NewDefaultUserRepository(),
		// 1.2) Use a provided or custom blacklisted repository of your choice
		repository.NewDefaultBlacklistedRefreshTokenRepository(),
		"my-access-token-secret", // NOTE: Remember not to commit your secrets
		"my-refresh-token-secret", // NOTE: Remember not to commit your secrets
	)

	// 2) Set up the authentication routes
	router, subRouter := route.SetupRoutes(
		handlers,
		// 2.1) Pass in allowed cross origin domains
		[]string{"http://localhost:8000"}
	)

	// 3) Add protected paths to the subRouter
	subRouter.HandleFunc("/data", ApiDataHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	// 4) Create the server
	server := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// 4) Start the server
	log.Printf("starting server on port %s", port)
	log.Fatal(server.ListenAndServe())
}

func ApiDataHandler(rw http.ResponseWriter, r *http.Request) {
	username := r.Context().Value(handler.UserContextKey)
	log.Printf("API DATA HANDLER for %s", username)
}
```

### Routes

The following routes will be set up:

#### /register

Method: POST
Headers: `Content-Type: application/json`

Expected request body:

```json
{
  "username": "name@email.com",
  "password": "astrongpassword"
}
```

Registers a user using the configured user repository.

#### /login

Method: POST
Headers: `Content-Type: application/json`

Expected request body:

```json
{
  "username": "name@email.com",
  "password": "astrongpassword"
}
```

Using the username and password, authenticates a user using the configured user repository. On success, returns back an access JWT and sets a refresh token cookie, `refresh-token`.

#### /refresh

Method: POST

If a the refresh token cookie, `refresh-token`, is present, will provide back an access JWT.

#### /isLoggedIn

Method: GET
Headers: `Authorization: Bearer USE_ACCESS_JWT_HERE`

Will return whether or not a user is logged in based on if the access JWT is valid.

#### /api/\*

Headers: `Authorization: Bearer USE_ACCESS_JWT_HERE`

Using the subrouter returned from `route.SetupRoutes` you can set up your own authenticated routes.

### Repositories

Repositories are a means to access data from storage. Some are provided in the `repository` package.

#### User Repositories

- `repository.DefaultUserRepository`
  - An in-memory user key-value store. Useful for testing or prototyping. Do NOT use in production.

Use your own custom repository by implementing the `repository.UserRepository` interface.

#### Blacklisted Token Repositories

- `repository.DefaultBlacklistedRefreshTokenRepository`
  - An in-memory token key-value store. Useful for testing or prototyping. Do NOT use in production.

Use your own custom repository by implementing the `repository.BlacklistedRefreshTokenRepository` interface.
