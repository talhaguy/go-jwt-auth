package server

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/talhaguy/go-jwt-auth/handler"
	"github.com/talhaguy/go-jwt-auth/repository"
	"github.com/urfave/negroni"
)

func StartServer(port string) {
	handlers := handler.NewDefaultHandler(
		repository.NewDefaultUserRepository(),
		repository.NewDefaultBlacklistedRefreshTokenRepository(),
	)
	router := setupRoutes(handlers)
	server := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Printf("starting server on port %s", port)
	log.Fatal(server.ListenAndServe())
}

func setupRoutes(handlers handler.Handler) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/register", handlers.RegistrationHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/login", handlers.LoginHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/refresh", handlers.RefreshHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	subRouter := mux.NewRouter().PathPrefix("/api").Subrouter().StrictSlash(true)
	subRouter.HandleFunc("/data", handlers.ApiDataHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	router.PathPrefix("/api").Handler(negroni.New(
		negroni.HandlerFunc(handler.VerifyAccessToken),
		negroni.Wrap(subRouter),
	))

	return router
}
