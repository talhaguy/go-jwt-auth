package route

import (
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/talhaguy/go-jwt-auth/handler"
	"github.com/urfave/negroni"
)

func SetupRoutes(routeHandler handler.RouteHandler, allowedOrigins []string) (http.Handler, *mux.Router) {
	// TODO: change name of handler parameter to be less confusing with gorilla handlers package
	router := mux.NewRouter()
	router.HandleFunc("/register", routeHandler.RegistrationHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/login", routeHandler.LoginHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/refresh", routeHandler.RefreshHandler).Methods(http.MethodPost)
	router.HandleFunc("/isLoggedIn", routeHandler.IsLoggedIn).Methods(http.MethodGet)

	subRouter := mux.NewRouter().PathPrefix("/api").Subrouter().StrictSlash(true)

	router.PathPrefix("/api").Handler(negroni.New(
		negroni.HandlerFunc(routeHandler.VerifyAccessToken),
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
