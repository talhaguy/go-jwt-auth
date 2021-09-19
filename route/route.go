package route

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/talhaguy/go-jwt-auth/handler"
	"github.com/urfave/negroni"
)

func SetupRoutes(handlers handler.Handler) (*mux.Router, *mux.Router) {
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

	return router, subRouter
}