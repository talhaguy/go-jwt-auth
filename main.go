package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

var UserDb = make(map[string]string)

func main() {
	router := setupRoutes()
	// TODO: get port from args
	server := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("starting server on port 8080")
	log.Fatal(server.ListenAndServe())
}

func setupRoutes() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/register", RegistrationHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/login", LoginHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/refresh", RefreshHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	subRouter := mux.NewRouter().PathPrefix("/api").Subrouter().StrictSlash(true)
	subRouter.HandleFunc("/data", ApiDataHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	router.PathPrefix("/api").Handler(negroni.New(
		negroni.HandlerFunc(VerifyAccessToken),
		negroni.Wrap(subRouter),
	))

	return router
}

func VerifyAccessToken(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Println("verifying access jwt")

	accessTokenHeaderValue, ok := r.Header["Authorization"]
	if !ok {
		log.Println("missing access token")
		WriteErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	log.Printf("DEBUG - token header val - %s", accessTokenHeaderValue)

	token, err := getTokenFromAuthHeader(accessTokenHeaderValue[0])
	if err != nil {
		log.Println("could not find access token")
		WriteErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	log.Printf("DEBUG - got token - %s", token)

	// TODO: verify access JWT

	next(rw, r)
}

func getTokenFromAuthHeader(headerVal string) (string, error) {
	const tokenPrefix = "Bearer "
	pos := strings.Index(headerVal, tokenPrefix)
	if pos == -1 {
		return "", errors.New("incorrect format")
	}
	pos = pos + len(tokenPrefix)

	token := headerVal[pos:]

	return token, nil
}

func RegistrationHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("registration handler")

	jsonForm, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		WriteErrorResponse(rw, http.StatusInternalServerError, "could not read body")
		return
	}

	var registrationForm RegistrationForm
	err = json.Unmarshal(jsonForm, &registrationForm)
	if err != nil {
		WriteErrorResponse(rw, http.StatusBadRequest, "could not parse json")
		return
	}

	// TODO: username validation
	// TODO: password validation
	// TODO: check if user exists in DB validation
	// TODO: hash password

	// TODO: registration
	log.Printf("registering user %s", registrationForm.Username)
	UserDb[registrationForm.Username] = registrationForm.Password

	serverResponse := ServerResponse{
		Status: "SUCCESS",
	}
	jsonResponse, err := json.Marshal(serverResponse)
	if err != nil {
		WriteErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonResponse)
}

const RefreshTokenCookieName = "refresh-token"

func LoginHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("login handler")

	// TODO: if already logged in (has refresh valid token header) skip

	jsonForm, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		WriteErrorResponse(rw, http.StatusInternalServerError, "could not read body")
		return
	}

	var loginForm LoginForm
	err = json.Unmarshal(jsonForm, &loginForm)
	if err != nil {
		WriteErrorResponse(rw, http.StatusBadRequest, "could not parse json")
		return
	}

	// TODO: username validation
	// TODO: password validation

	hashedPass, ok := UserDb[loginForm.Username]
	if !ok {
		log.Printf("user %s does not exist", loginForm.Username)
		WriteErrorResponse(rw, http.StatusUnauthorized, "wrong credentials")
		return
	}

	// TODO: unhash password

	if loginForm.Password != hashedPass {
		log.Printf("wrong password for user %s", loginForm.Username)
		WriteErrorResponse(rw, http.StatusUnauthorized, "wrong credentials")
		return
	}

	log.Printf("auth successful for user %s", loginForm.Username)

	// TODO: create access JWT
	accessJWT := "access-jwt-12345"

	// TODO: create refresh JWT
	refreshJWT := "refresh-jwt-12345"

	http.SetCookie(rw, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshJWT,
		Expires:  time.Now().Add(time.Minute * 30),
		HttpOnly: true,
	})

	serverResponse := &AccessTokenServerResponse{
		ServerResponse: ServerResponse{
			Status: "SUCCESS",
		},
		Data: AccessTokenServerResponseData{
			AccessToken: accessJWT,
		},
	}
	jsonResponse, err := json.Marshal(serverResponse)
	if err != nil {
		WriteErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonResponse)
}

func RefreshHandler(rw http.ResponseWriter, r *http.Request) {
	refreshTokenCookie, err := r.Cookie(RefreshTokenCookieName)
	if err != nil {
		WriteErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// TODO: validate JWT
	_ = refreshTokenCookie

	// TODO: check DB for disallowed refresh tokens

	log.Printf("auth successful for refresh token")

	// TODO: create access JWT
	accessJWT := "access-jwt-12345"

	// TODO: create refresh JWT
	refreshJWT := "refresh-jwt-12345"

	// TODO: store old refresh token in disallowed refresh tokens DB

	http.SetCookie(rw, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshJWT,
		Expires:  time.Now().Add(time.Minute * 30),
		HttpOnly: true,
	})

	serverResponse := &AccessTokenServerResponse{
		ServerResponse: ServerResponse{
			Status: "SUCCESS",
		},
		Data: AccessTokenServerResponseData{
			AccessToken: accessJWT,
		},
	}
	jsonResponse, err := json.Marshal(serverResponse)
	if err != nil {
		WriteErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonResponse)
}

func WriteErrorResponse(rw http.ResponseWriter, status int, message string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	serverResponse := &ServerResponse{
		Status:  "ERROR",
		Message: message,
	}
	jsonResponse, err := json.Marshal(serverResponse)
	if err != nil {
		rw.Write([]byte("{\"status\":\"ERROR\"}"))
		return
	}

	rw.Write(jsonResponse)
}

func ApiDataHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("in api data handler")
}

type RegistrationForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ServerResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type AccessTokenServerResponse struct {
	ServerResponse
	Data AccessTokenServerResponseData `json:"data"`
}

type AccessTokenServerResponseData struct {
	AccessToken string `json:"accessToken"`
}
