package handler

import (
	"context"
	"log"
	"net/http"
)

type ContextKey string

const UserContextKey ContextKey = "username"

func (h *DefaultRouteHander) VerifyAccessToken(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Println("verifying access jwt")

	isAccessTokenValid, _, claims, err := h.validateRequestAccessToken(r)
	if !isAccessTokenValid || err != nil {
		log.Println("unauthorized access")
		if err != nil {
			log.Printf("ERROR: %s", err.Error())
		}
		writeErrorResponse(rw, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// send user information to next handler
	ctx := r.Context()
	ctx = context.WithValue(ctx, UserContextKey, claims.Username)
	next(rw, r.WithContext(ctx))
}
