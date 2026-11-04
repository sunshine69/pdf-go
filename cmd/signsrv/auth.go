package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
)

// The auth endpoints: admin password login, machine client key login, refresh,
// logout. All four answer in the same shape, and all of them answer "the
// credential is not good enough" in exactly one way, so the API cannot be used
// to find out whether an email address has an account.

// authBody is the shape every login answer uses. The access token is 15
// minutes; the refresh token is what the SPA keeps, and it is the only value in
// the response that a copied database could not have produced.
type authBody struct {
	Access    string   `json:"access"`
	Refresh   string   `json:"refresh"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	ExpiresIn int64    `json:"expires_in"`
}

// handleLogin verifies an admin password. The response is the same for a
// wrong address and a wrong password, and takes the same time for both,
// because the dummy hash is computed when the address is unknown.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	ip := signauth.ClientIP(r, s.cfg.TrustProxy)
	subject, err := s.sessions.Login(r.Context(), strings.TrimSpace(in.Email), in.Password)
	if err != nil {
		if err == signauth.ErrLoginDenied {
			// The address is logged, never echoed to the caller.
			s.logJSON(slog.LevelWarn, "login refused", "ip", ip,
				"email", in.Email, "request", requestID(r.Context()))
			writeProblem(w, http.StatusUnauthorized, "unauthorized",
				"the email address and password do not match", "")
			return
		}
		s.logJSON(slog.LevelError, "login", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "login failed", "")
		return
	}
	access, refresh, err := s.sessions.MintSession(r.Context(), subject,
		signauth.RoleAdmin, []string{signauth.ScopeAdminRead}, signauth.AccessTTL)
	if err != nil {
		s.logJSON(slog.LevelError, "mint session", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "session mint failed", "")
		return
	}
	s.logJSON(slog.LevelInfo, "login ok", "ip", ip, "request", requestID(r.Context()))
	respondAuth(w, access, refresh, signauth.RoleAdmin, []string{signauth.ScopeAdminRead})
}

// handleClientToken mints an access token from a machine API key. The key is
// presented in the same header shape a JWT uses, so the API keeps one
// verification path for every caller.
func (s *server) handleClientToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key string `json:"key"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	subject, scopes, err := s.sessions.ClientLogin(r.Context(), in.Key)
	if err != nil {
		s.logJSON(slog.LevelWarn, "client token refused", "request", requestID(r.Context()))
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "the key is not valid", "")
		return
	}
	access, refresh, err := s.sessions.MintSession(r.Context(), subject,
		signauth.RoleClient, scopes, signauth.AccessTTL)
	if err != nil {
		s.logJSON(slog.LevelError, "mint client session", "error", err,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "session mint failed", "")
		return
	}
	respondAuth(w, access, refresh, signauth.RoleClient, scopes)
}

// handleRefresh spends the refresh token and answers with the new pair. The jti
// of the access token in hand is revoked on the way, so refreshing a session
// moves it forward instead of stacking tokens.
func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Refresh string `json:"refresh"`
		Access  string `json:"access"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	// The jti of the token in hand is read from the token itself, not from a
	// field a caller could choose.
	var jti string
	if in.Access != "" {
		if claims, err := s.keys.VerifyAccess(in.Access); err == nil {
			jti = claims.JTI
		}
	}
	access, next, err := s.sessions.Refresh(r.Context(), in.Refresh, jti)
	if err != nil {
		// A spent, forged, stale, or revoked-out-of-existence chain: one
		// answer, so the endpoint cannot be used to search for a chain that
		// is still live.
		writeProblem(w, http.StatusUnauthorized, "unauthorized",
			"the refresh token is not valid", "sign in again")
		return
	}
	respondAuth(w, access, next, "", []string{})
}

// handleLogout ends the session. The subject and the jti come from the claims
// the middleware verified, never from the body, so a caller cannot log out
// someone else.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := signauth.ClaimsFrom(r.Context())
	if claims == nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "no session", "")
		return
	}
	if err := s.sessions.Logout(r.Context(), claims.Subject, claims.JTI); err != nil {
		s.logJSON(slog.LevelError, "logout", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "logout failed", "")
		return
	}
	s.logJSON(slog.LevelInfo, "logout", "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// respondAuth writes the pair. The access token's lifetime is echoed as whole
// seconds so the SPA can refresh before it expires, and the scopes are echoed
// so a client can hide the endpoints it cannot use.
func respondAuth(w http.ResponseWriter, access, refresh, role string, scopes []string) {
	if scopes == nil {
		scopes = []string{}
	}
	writeJSON(w, http.StatusOK, authBody{
		Access:    access,
		Refresh:   refresh,
		Role:      role,
		Scopes:    scopes,
		ExpiresIn: int64(signauth.AccessTTL / time.Second),
	})
}

// decodeBody reads a JSON request body and answers 400 when it is not one. The
// body is capped: a login endpoint that reads an unbounded body is a memory
// problem, not a validation problem.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	if err := dec.Decode(v); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"the request body is not JSON", "send a JSON object")
		return false
	}
	return true
}
