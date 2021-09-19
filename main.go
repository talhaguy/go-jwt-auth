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
		"my-secret",
		"my-secret",
	)

	router, subRouter := route.SetupRoutes(handlers)
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
	log.Println("API DATA HANDLER...")
}
