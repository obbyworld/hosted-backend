package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// AuthTokenClaims are what the server hands back from an
// authtoken.validate RPC call (see modules/authtoken.c).
// Empty fields mean "the issuing client didn't have that
// attribute at GENERATE time" — never reuse last-known state.
type AuthTokenClaims struct {
	Service    string `json:"service"`
	URL        string `json:"url"`
	Account    string `json:"account"`
	Nick       string `json:"nick"`
	Scope      string `json:"scope"`
	MemberOf   string `json:"member_of"`
	OperatorOf string `json:"operator_of"`
}

// AuthTokenContextKey is the type used as the context key for stuffed
// AuthTokenClaims. Defining a dedicated type keeps the lookups type-
// safe (no string-collision risk with other middleware).
type authTokenCtxKey struct{}

// AuthTokenFromContext returns the claims attached by AuthTokenMiddleware,
// or nil if the request didn't pass through that middleware.
func AuthTokenFromContext(ctx context.Context) *AuthTokenClaims {
	v, _ := ctx.Value(authTokenCtxKey{}).(*AuthTokenClaims)
	return v
}

// validateBearer runs a single authtoken.validate JSON-RPC call
// against the obbyircd connection.  The token is single-use; the
// server consumes it on the first successful validate.
func validateBearer(token string) (*AuthTokenClaims, error) {
	serviceURL := os.Getenv("FILEHOST_PUBLIC_URL")
	if serviceURL == "" {
		serviceURL = "https://obby.t3ks.com"
	}

	// ircQuery handles a torn-down websocket (e.g. IRCd restart)
	// by reconnecting once before bubbling the error up.
	raw, err := ircQuery("authtoken.validate", map[string]interface{}{
		"service": "filehost",
		"url":     serviceURL,
		"token":   token,
	})
	if err != nil {
		// The RPC layer returns an error for any JSON-RPC error
		// response — most commonly INVALID_PARAMS "token rejected"
		// from the authtoken module.
		return nil, err
	}

	// `raw` is whatever the RPC layer hands back. Marshal-roundtrip
	// is the simplest way to get into a typed struct without
	// depending on the exact wrapper shape the RPC client uses.
	buf, mErr := json.Marshal(raw)
	if mErr != nil {
		return nil, fmt.Errorf("encode RPC result: %w", mErr)
	}
	var wrapper struct {
		Service string          `json:"service"`
		URL     string          `json:"url"`
		Claims  AuthTokenClaims `json:"claims"`
	}
	if uErr := json.Unmarshal(buf, &wrapper); uErr != nil {
		return nil, fmt.Errorf("decode RPC result: %w", uErr)
	}

	claims := wrapper.Claims
	claims.Service = wrapper.Service
	claims.URL = wrapper.URL
	return &claims, nil
}

// AuthTokenMiddleware validates the Bearer token via draft/authtoken's
// authtoken.validate RPC. Successful claims are stuffed into the
// request context for handlers to read with AuthTokenFromContext.
//
// Sister middleware to AuthMiddleware (which validates an EXTJWT) --
// they cover the same ground but a token is single-use and never
// embeds long-lived account state, so this path is cleaner for HTTP
// endpoints that should re-mint per upload.
func AuthTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods",
			"GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required",
				http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader || token == "" {
			http.Error(w, "Bearer token required",
				http.StatusUnauthorized)
			return
		}

		claims, err := validateBearer(token)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(),
				http.StatusUnauthorized)
			return
		}

		// Stash under both the typed key (new handlers) and the
		// legacy "jwt_claims" key (existing upload handlers read
		// JWTClaims.{Sub,Account,Cmodes}) so we don't have to
		// rewrite every uploader at once. The synthetic JWTClaims
		// only carries the fields the legacy handlers actually
		// read; Exp/Umodes are zero/empty since the bearer is
		// already validated by the IRCd and the server-side single-
		// use semantics handle expiry for us.
		legacy := authTokenToLegacyClaims(claims)
		ctx := context.WithValue(r.Context(), authTokenCtxKey{}, claims)
		// nolint:staticcheck — string key matches the upload
		// handlers' existing reads; can be migrated later.
		ctx = context.WithValue(ctx, "jwt_claims", legacy)
		next(w, r.WithContext(ctx))
	}
}

// authTokenToLegacyClaims projects draft/authtoken claims onto the
// JWTClaims shape the existing upload handlers read.  Cmodes is
// synthesised: if the token's `scope` is `channel:#xyz` and #xyz is
// in operator_of, we report ["o"] so the channel-avatar handler's
// "operator/admin/owner permission required" check passes.
func authTokenToLegacyClaims(c *AuthTokenClaims) *JWTClaims {
	out := &JWTClaims{
		Sub:     c.Nick,
		Account: c.Account,
	}
	target, isChannelScope := strings.CutPrefix(c.Scope, "channel:")
	if isChannelScope {
		out.Channel = target
	}
	if isChannelScope && c.OperatorOf != "" {
		for _, ch := range strings.Fields(c.OperatorOf) {
			if strings.EqualFold(ch, target) {
				out.Cmodes = []string{"o"}
				break
			}
		}
	}
	return out
}
