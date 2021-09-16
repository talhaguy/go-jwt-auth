package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

var UserDb = make(map[string]string)

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/register", RegistrationHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")
	router.HandleFunc("/login", LoginHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	server := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("starting server")
	log.Fatal(server.ListenAndServe())
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
		Name:     "refresh-token",
		Value:    refreshJWT,
		Expires:  time.Now().Add(time.Minute * 30),
		HttpOnly: true,
	})

	serverResponse := &LoginServerResponse{
		ServerResponse: ServerResponse{
			Status: "SUCCESS",
		},
		Data: LoginServerResponseData{
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

type LoginServerResponse struct {
	ServerResponse
	Data LoginServerResponseData `json:"data"`
}

type LoginServerResponseData struct {
	AccessToken string `json:"accessToken"`
}
