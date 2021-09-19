package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
)

type ContextKey string

const UserContextKey ContextKey = "username"

func (h *DefaultHander) VerifyAccessToken(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Println("verifying access jwt")

	accessTokenHeaderValue, ok := r.Header["Authorization"]
	if !ok {
		log.Println("missing access token")
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	log.Printf("DEBUG - token header val - %s", accessTokenHeaderValue)

	token, err := getTokenFromAuthHeader(accessTokenHeaderValue[0])
	if err != nil {
		log.Println("could not find access token")
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	log.Printf("DEBUG - got token - %s", token)

	// verify access JWT
	isValid, accessToken, err := verifyAccessToken(h.accessTokenSecret, token)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, "could not verify access")
		return
	}
	if !isValid {
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}
	claims, err := getClaimsFromToken(accessToken)
	if err != nil {
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// send user information to next handler
	ctx := r.Context()
	ctx = context.WithValue(ctx, UserContextKey, claims.Username)
	next(rw, r.WithContext(ctx))
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
