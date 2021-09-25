# Go JWT Auth

**Note**: This repo is in the early stages and may change/break.

This repo is meant to be imported into your current Go server and does the work to set up JWT authentication.

# How to use

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

func StartServer(port string) {
	handlers := handler.NewDefaultHandler(
		repository.NewDefaultUserRepository(),
		repository.NewDefaultBlacklistedRefreshTokenRepository(),
		"my-secret", // NOTE: Remember not to commit your secrets
		"my-secret", // NOTE: Remember not to commit your secrets
	)

	router, subRouter := route.SetupRoutes(handlers, []string{"http://localhost:8000"})
	subRouter.HandleFunc("/data", ApiDataHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	server := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Printf("starting server on port %s", port)
	log.Fatal(server.ListenAndServe())
}

func main() {
	StartServer("8080")
}

func ApiDataHandler(rw http.ResponseWriter, r *http.Request) {
	username := r.Context().Value(handler.UserContextKey)
	log.Printf("API DATA HANDLER for %s", username)
}
```