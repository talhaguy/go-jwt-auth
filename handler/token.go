package handler

import (
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func createAccessJWT(tokenSecret []byte, username string) (string, error) {
	claims := CustomClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(tokenSecret)
	if err != nil {
		return "", err
	}
	log.Printf("DEBUG: generated access jwt - %s", tokenString)
	return tokenString, nil
}

func createRefreshJWT(tokenSecret []byte, username string) (string, error) {
	claims := CustomClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(tokenSecret)
	if err != nil {
		return "", err
	}
	log.Printf("DEBUG: generated refresh jwt - %s", tokenString)
	return tokenString, nil
}

func getClaimsFromToken(token *jwt.Token) (*CustomClaims, error) {
	log.Printf("DEBUG: getClaimsFromToken %#v", token.Claims)
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return &CustomClaims{}, errors.New("could not get claims from token")
	}

	return claims, nil
}

func verifyAccessToken(tokenSecret string, tokenString string) (bool, *jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenSecret, nil
	})

	return token.Valid, token, err
}

func verifyRefreshToken(tokenSecret string, tokenString string) (bool, *jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenSecret, nil
	})

	return token.Valid, token, err
}
