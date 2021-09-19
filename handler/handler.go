package handler

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
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

	// username validation
	isUsernameValid := validateUsername(registrationForm.Username)
	if !isUsernameValid {
		log.Printf("username %s is not valid", registrationForm.Username)
		writeErrorResponse(rw, http.StatusBadRequest, "invalid username")
		return
	}

	// password validation
	isPasswordValid := validatePassword(registrationForm.Password)
	if !isPasswordValid {
		log.Println("password is not valid")
		writeErrorResponse(rw, http.StatusBadRequest, "invalid password")
		return
	}

	// check if user exists in DB validation
	_, err = h.userRepo.GetByUserName(registrationForm.Username)
	if err != nil {
		// if any error other than NotFoundError, write an error response
		_, ok := err.(*repository.NotFoundError)
		if !ok {
			writeErrorResponse(rw, http.StatusInternalServerError, "error getting user")
			return
		}
	}

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
	refreshTokenCookie, err := r.Cookie(RefreshTokenCookieName)
	if err == nil {
		// TODO: verify token

		// check if token is not black listed
		isBlacklisted, err := h.checkIfRefreshTokenBlacklisted(refreshTokenCookie.Value)
		if err != nil {
			writeErrorResponse(rw, http.StatusInternalServerError, "error validating refresh token")
			return
		}
		if !isBlacklisted {
			// TODO: create access JWT
			accessJWT := "access-jwt-12345"

			// TODO: create refresh JWT
			refreshJWT := "refresh-jwt-" + strconv.FormatInt(time.Now().Unix(), 10)

			// blacklist old refresh token
			h.blacklistedRefreshTokenRepo.Save(refreshTokenCookie.Value)

			setRefreshTokenCookie(rw, refreshJWT)
			jsonRes, err := createSuccessLoginResponse(accessJWT)
			if err != nil {
				writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			rw.Write(jsonRes)
			return
		}
	}

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

	// username validation
	isUsernameValid := validateUsername(loginForm.Username)
	if !isUsernameValid {
		log.Printf("username %s is not valid", loginForm.Username)
		writeErrorResponse(rw, http.StatusBadRequest, "invalid username")
		return
	}

	// password validation
	isPasswordValid := validatePassword(loginForm.Password)
	if !isPasswordValid {
		log.Println("password is not valid")
		writeErrorResponse(rw, http.StatusBadRequest, "invalid password")
		return
	}

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
	refreshJWT := "refresh-jwt-" + strconv.FormatInt(time.Now().Unix(), 10)

	setRefreshTokenCookie(rw, refreshJWT)
	jsonRes, err := createSuccessLoginResponse(accessJWT)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonRes)
}

// TODO: implement stub
func validateUsername(username string) bool {
	return true
}

// TODO: implement stub
func validatePassword(password string) bool {
	return true
}

func (h *DefaultHander) RefreshHandler(rw http.ResponseWriter, r *http.Request) {
	refreshTokenCookie, err := r.Cookie(RefreshTokenCookieName)
	if err != nil {
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// TODO: validate JWT

	// check if token is not black listed
	isBlacklisted, err := h.checkIfRefreshTokenBlacklisted(refreshTokenCookie.Value)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "error validating")
		return
	}
	if isBlacklisted {
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	log.Printf("auth successful for refresh token")

	// TODO: create access JWT
	accessJWT := "access-jwt-12345"

	// TODO: create refresh JWT
	refreshJWT := "refresh-jwt-" + strconv.FormatInt(time.Now().Unix(), 10)

	// store old refresh token in disallowed refresh tokens DB
	h.blacklistedRefreshTokenRepo.Save(refreshTokenCookie.Value)

	setRefreshTokenCookie(rw, refreshJWT)
	jsonRes, err := createSuccessLoginResponse(accessJWT)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonRes)
}

func (h *DefaultHander) checkIfRefreshTokenBlacklisted(value string) (bool, error) {
	_, err := h.blacklistedRefreshTokenRepo.GetByValue(value)
	if err != nil {
		_, ok := err.(*repository.NotFoundError)
		if !ok {
			return false, err
		}

		return false, nil
	}

	return true, nil
}

func setRefreshTokenCookie(rw http.ResponseWriter, refreshToken string) {
	// create refresh token cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshToken,
		Expires:  time.Now().Add(time.Minute * 30),
		HttpOnly: true,
	})
}

func createSuccessLoginResponse(accessToken string) ([]byte, error) {
	// create access token response
	serverResponse := &AccessTokenServerResponse{
		ServerResponse: ServerResponse{
			Status: "SUCCESS",
		},
		Data: AccessTokenServerResponseData{
			AccessToken: accessToken,
		},
	}
	jsonResponse, err := json.Marshal(serverResponse)
	if err != nil {
		return nil, errors.New("could not create response")
	}

	return jsonResponse, nil
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
