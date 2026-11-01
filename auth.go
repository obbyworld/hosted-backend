package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the claims in the extjwt token
type JWTClaims struct {
	Exp     int64    `json:"exp"`
	Iss     string   `json:"iss"`
	Sub     string   `json:"sub"`
	Account string   `json:"account"`
	Umodes  []string `json:"umodes"`
	Cmodes  []string `json:"cmodes"`
	Channel string   `json:"channel"`
	jwt.RegisteredClaims
}

// AuthMiddleware verifies JWT token and checks for IRCop status
func AuthMiddleware(next http.HandlerFunc, requireIRCOp bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for all responses
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Allow OPTIONS requests for CORS preflight without authentication
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			http.Error(w, "JWT secret not configured", http.StatusInternalServerError)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})

		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Check if IRCop required
		if requireIRCOp {
			isIRCOp := false
			for _, mode := range claims.Umodes {
				if mode == "o" {
					isIRCOp = true
					break
				}
			}
			if !isIRCOp {
				http.Error(w, "IRCop status required", http.StatusForbidden)
				return
			}
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "jwt_claims", claims)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

// ServerAuthMiddleware verifies X-ObsidianIRC-Key header
func ServerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-ObsidianIRC-Key")
		expectedKey := os.Getenv("IRC_SERVER_KEY")
		if expectedKey == "" {
			http.Error(w, "IRC server key not configured", http.StatusInternalServerError)
			return
		}

		if key != expectedKey {
			http.Error(w, "Invalid IRC server key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}