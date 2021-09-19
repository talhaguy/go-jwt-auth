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
	)
	router, _ := setupRoutes(handlers)
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
	route.StartServer("8080")
}
```