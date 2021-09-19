package handler

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/talhaguy/go-jwt-auth/repository"
	"golang.org/x/crypto/bcrypt"
)

type Handler interface {
	RegistrationHandler(rw http.ResponseWriter, r *http.Request)
	LoginHandler(rw http.ResponseWriter, r *http.Request)
	RefreshHandler(rw http.ResponseWriter, r *http.Request)
}

type DefaultHander struct {
	userRepo                    repository.UserRepository
	blacklistedRefreshTokenRepo repository.BlacklistedRefreshTokenRepository
	accessTokenSecret           []byte
	refreshTokenSecret          []byte
}

func NewDefaultHandler(
	userRepo repository.UserRepository,
	blacklistedRefreshTokenRepo repository.BlacklistedRefreshTokenRepository,
	accessTokenSecret string,
	refreshTokenSecret string,
) *DefaultHander {
	return &DefaultHander{
		userRepo:                    userRepo,
		blacklistedRefreshTokenRepo: blacklistedRefreshTokenRepo,
		accessTokenSecret:           []byte(accessTokenSecret),
		refreshTokenSecret:          []byte(refreshTokenSecret),
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

	// hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registrationForm.Password), 14)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not use password")
		return
	}

	log.Printf("registering user %s", registrationForm.Username)
	err = h.userRepo.Save(registrationForm.Username, string(hashedPassword))
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

	// if already logged in (has refresh valid token header), just give the success response
	refreshTokenString, refreshToken, err := h.validateRequestRefreshToken(r)
	if err == nil {
		claims, err := getClaimsFromToken(refreshToken)
		if err == nil {
			// check if token is not black listed
			isBlacklisted, err := h.checkIfRefreshTokenBlacklisted(refreshTokenString)
			if err != nil {
				writeErrorResponse(rw, http.StatusInternalServerError, "error validating refresh token")
				return
			}
			if !isBlacklisted {
				// create access JWT
				accessJWT, err := createAccessJWT(h.accessTokenSecret, claims.Username)
				if err != nil {
					writeErrorResponse(rw, http.StatusInternalServerError, "could not create access token")
					return
				}

				// create refresh JWT
				refreshJWT, err := createRefreshJWT(h.refreshTokenSecret, claims.Username)
				if err != nil {
					writeErrorResponse(rw, http.StatusInternalServerError, "could not create refresh token")
					return
				}

				// blacklist old refresh token
				h.blacklistedRefreshTokenRepo.Save(refreshTokenString)

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

	// verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(loginForm.Password))
	if err != nil {
		log.Printf("wrong password for user %s", loginForm.Username)
		writeErrorResponse(rw, http.StatusUnauthorized, "wrong credentials")
		return
	}

	log.Printf("auth successful for user %s", loginForm.Username)

	// create access JWT
	accessJWT, err := createAccessJWT(h.accessTokenSecret, loginForm.Username)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create access token")
		return
	}

	// reate refresh JWT
	refreshJWT, err := createRefreshJWT(h.refreshTokenSecret, loginForm.Username)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create refresh token")
		return
	}

	setRefreshTokenCookie(rw, refreshJWT)
	jsonRes, err := createSuccessLoginResponse(accessJWT)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create response")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonRes)
}

func (h *DefaultHander) validateRequestRefreshToken(r *http.Request) (string, *jwt.Token, error) {
	refreshTokenCookie, err := r.Cookie(RefreshTokenCookieName)
	if err != nil {
		return "", nil, err
	}

	isTokenValid, token, err := verifyRefreshToken(string(h.refreshTokenSecret), refreshTokenCookie.Value)
	if err != nil {
		return "", nil, err
	}
	if !isTokenValid {
		return "", nil, errors.New("invalid token")
	}

	return refreshTokenCookie.Value, token, nil
}

func (h *DefaultHander) RefreshHandler(rw http.ResponseWriter, r *http.Request) {
	log.Println("refresh handler")

	refreshTokenString, refreshToken, err := h.validateRequestRefreshToken(r)
	if err != nil {
		log.Println("could not verify refresh token")
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// get claims from refresh token
	claims, err := getClaimsFromToken(refreshToken)
	if err != nil {
		log.Println("could not get claims from refresh token")
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// check if token is not black listed
	isBlacklisted, err := h.checkIfRefreshTokenBlacklisted(refreshTokenString)
	if err != nil {
		log.Println("error checking if refresh token is blacklisted")
		writeErrorResponse(rw, http.StatusInternalServerError, "error validating")
		return
	}
	if isBlacklisted {
		log.Println("refresh token is blacklisted")
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	log.Printf("auth successful for refresh token")

	// create access JWT
	accessJWT, err := createAccessJWT(h.accessTokenSecret, claims.Username)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create access token")
		return
	}

	// reate refresh JWT
	refreshJWT, err := createRefreshJWT(h.refreshTokenSecret, claims.Username)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not create refresh token")
		return
	}

	// store old refresh token in disallowed refresh tokens DB
	h.blacklistedRefreshTokenRepo.Save(refreshTokenString)

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

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
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
