package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"
)

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
