package route

import (
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/talhaguy/go-jwt-auth/handler"
	"github.com/urfave/negroni"
)

func SetupRoutes(handler handler.Handler, allowedOrigins []string) (http.Handler, *mux.Router) {
	// TODO: change name of handler parameter to be less confusing with gorilla handlers package
	router := mux.NewRouter()
	router.HandleFunc("/register", handler.RegistrationHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/login", handler.LoginHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/refresh", handler.RefreshHandler).Methods(http.MethodPost)
	router.HandleFunc("/isLoggedIn", handler.IsLoggedIn).Methods(http.MethodGet)

	subRouter := mux.NewRouter().PathPrefix("/api").Subrouter().StrictSlash(true)

	router.PathPrefix("/api").Handler(negroni.New(
		negroni.HandlerFunc(handler.VerifyAccessToken),
		negroni.Wrap(subRouter),
	))

	// enable cors
	allowedCredentialsOpt := handlers.AllowCredentials()
	allowedMethodsOpt := handlers.AllowedMethods([]string{"POST", "GET"})
	allowedOriginsOpt := handlers.AllowedOrigins(allowedOrigins)
	allowedHeadersOpt := handlers.AllowedHeaders([]string{"Content-Type", "Authorization"})
	corsEnabledRouter := handlers.CORS(allowedCredentialsOpt, allowedMethodsOpt, allowedOriginsOpt, allowedHeadersOpt)(router)

	return corsEnabledRouter, subRouter
}
