package handler

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/talhaguy/go-jwt-auth/repository"
)

type Handler interface {
	RegistrationHandler(rw http.ResponseWriter, r *http.Request)
	LoginHandler(rw http.ResponseWriter, r *http.Request)
	RefreshHandler(rw http.ResponseWriter, r *http.Request)
	ApiDataHandler(rw http.ResponseWriter, r *http.Request)
}

type DefaultHander struct {
	userRepo                    repository.UserRepository
	blacklistedRefreshTokenRepo repository.BlacklistedRefreshTokenRepository
}

func NewDefaultHandler(
	userRepo repository.UserRepository,
	blacklistedRefreshTokenRepo repository.BlacklistedRefreshTokenRepository,
) *DefaultHander {
	return &DefaultHander{
		userRepo:                    userRepo,
		blacklistedRefreshTokenRepo: blacklistedRefreshTokenRepo,
	}
}

func (h *DefaultHander) RegistrationHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("registration handler")

	jsonForm, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not read body")
		return
	}

	var registrationForm RegistrationForm
	err = json.Unmarshal(jsonForm, &registrationForm)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, "could not parse json")
		return
	}

	// TODO: username validation
	// TODO: password validation
	// TODO: check if user exists in DB validation
	// TODO: hash password

	log.Printf("registering user %s", registrationForm.Username)
	err = h.userRepo.Save(registrationForm.Username, registrationForm.Password)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not save user")
		return
	}

	serverResponse := ServerResponse{
		Status: "SUCCESS",
	}
	jsonResponse, err := json.Marshal(serverResponse)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonResponse)
}

const RefreshTokenCookieName = "refresh-token"

func (h *DefaultHander) LoginHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("login handler")

	// TODO: if already logged in (has refresh valid token header) skip

	jsonForm, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not read body")
		return
	}

	var loginForm LoginForm
	err = json.Unmarshal(jsonForm, &loginForm)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, "could not parse json")
		return
	}

	// TODO: username validation
	// TODO: password validation

	user, err := h.userRepo.GetByUserName(loginForm.Username)
	if err != nil {
		log.Println(err)
		writeErrorResponse(rw, http.StatusUnauthorized, "wrong credentials")
		return
	}

	// TODO: unhash password
	unhashedPassword := user.HashedPassword

	if loginForm.Password != unhashedPassword {
		log.Printf("wrong password for user %s", loginForm.Username)
		writeErrorResponse(rw, http.StatusUnauthorized, "wrong credentials")
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
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonResponse)
}

func (h *DefaultHander) RefreshHandler(rw http.ResponseWriter, r *http.Request) {
	refreshTokenCookie, err := r.Cookie(RefreshTokenCookieName)
	if err != nil {
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// TODO: validate JWT

	// check if token is not black listed
	_, err = h.blacklistedRefreshTokenRepo.GetByValue(refreshTokenCookie.Value)
	if err != nil {
		// if anything other than a NotFoundError, write an error response
		_, ok := err.(*repository.NotFoundError)
		if !ok {
			writeErrorResponse(rw, http.StatusInternalServerError, "error validating")
			return
		}
	}

	log.Printf("auth successful for refresh token")

	// TODO: create access JWT
	accessJWT := "access-jwt-12345"

	// TODO: create refresh JWT
	refreshJWT := "refresh-jwt-12345"

	// store old refresh token in disallowed refresh tokens DB
	h.blacklistedRefreshTokenRepo.Save(refreshTokenCookie.Value)

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
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonResponse)
}

func (h *DefaultHander) ApiDataHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("in api data handler")
}

func writeErrorResponse(rw http.ResponseWriter, status int, message string) {
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

type AccessTokenServerResponse struct {
	ServerResponse
	Data AccessTokenServerResponseData `json:"data"`
}

type AccessTokenServerResponseData struct {
	AccessToken string `json:"accessToken"`
}
