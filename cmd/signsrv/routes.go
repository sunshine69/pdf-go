package main

import (
	"log/slog"
	"net/http"

	"github.com/sunshine69/pdf-go/internal/signauth"
)

// routes wires every endpoint. Step 01 delivers /healthz and the static
// shells; the API endpoints of steps 05 to 10 are registered here as they
// are implemented.
func (s *server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Auth. Login is rate limited at 5/min/IP on its own, because every
	// attempt runs argon2id: five verifications a minute is the budget a
	// single address gets.
	s.mux.Handle("POST /api/v1/auth/login",
		s.loginGuard(s.handleLogin, "login", signauth.LoginLimit))
	s.mux.Handle("POST /api/v1/auth/token",
		s.loginGuard(s.handleClientToken, "client-token", signauth.LoginLimit))
	s.mux.Handle("POST /api/v1/auth/refresh",
		s.loginGuard(s.handleRefresh, "refresh", signauth.LoginLimit))

	// Logout is authenticated, so the caller has to hold a live token. Any
	// authenticated caller may end their own session, so no scope is needed:
	// logging out is a right of the holder of a token, not a privilege.
	s.mux.Handle("POST /api/v1/auth/logout", s.api(s.handleLogout))

	// The first two protected endpoints, and the shape every later one uses:
	// rate limit, then the token, then the scope. Envelope listing needs the
	// read scope, the admin counters need the admin scope.
	s.mux.Handle("GET /api/v1/envelopes", s.api(s.handleListEnvelopes, signauth.ScopeEnvelopeRead))
	s.mux.Handle("GET /api/v1/admin/stats", s.api(s.handleAdminStats, signauth.ScopeAdminRead))

	// The envelope endpoints. Create costs the most of any request in the
	// service: a fill, a certification signature, and a TSA round trip. It
	// gets a bucket of its own, so a client that floods create cannot use up
	// the budget of the read endpoints.
	s.mux.Handle("POST /api/v1/envelopes",
		s.apiBucket(s.handleCreateEnvelopes, "create", signauth.CreateLimit,
			signauth.ScopeEnvelopeWrite))
	s.mux.Handle("GET /api/v1/envelopes/{id}", s.api(s.handleGetEnvelope, signauth.ScopeEnvelopeRead))
	s.mux.Handle("GET /api/v1/envelopes/{id}/document", s.api(s.handleGetDocument, signauth.ScopeEnvelopeRead))
	s.mux.Handle("GET /api/v1/envelopes/{id}/revisions/{rid}", s.api(s.handleGetRevision, signauth.ScopeEnvelopeRead))

	// Static faces. The apps are built in steps 08 and 09; the handlers
	// below serve whatever is embedded, so the routes never move again.
	s.mux.HandleFunc("GET /s/{token}", s.handleSignerShell)
	s.mux.HandleFunc("GET /assets/spa/{name}", func(w http.ResponseWriter, r *http.Request) {
		srvStatic(w, r, "/s/")
	})
	s.mux.HandleFunc("GET /admin/", s.handleAdminShell)
	s.mux.HandleFunc("GET /admin/{name}", func(w http.ResponseWriter, r *http.Request) {
		srvStatic(w, r, "/admin/")
	})
	s.mux.HandleFunc("GET /assets/admin/{name}", func(w http.ResponseWriter, r *http.Request) {
		srvStatic(w, r, "/admin/")
	})

	s.mux.HandleFunc("/", s.handleUnknown)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version,
		"request": requestID(r.Context()),
	})
}

// handleSignerShell serves the signing app. The token is not read here: the
// app reads it from the path and the API validates it. Nothing about the
// token is logged, and nothing about the envelope is revealed before claim.
func (s *server) handleSignerShell(w http.ResponseWriter, r *http.Request) {
	s.log.Info("signer shell", "request", requestID(r.Context()),
		"token", "[token:hidden]")
	srvStatic(w, r, "/s/")
}

func (s *server) handleAdminShell(w http.ResponseWriter, r *http.Request) {
	srvStatic(w, r, "/admin/")
}

func (s *server) handleUnknown(w http.ResponseWriter, r *http.Request) {
	s.logJSON(slog.LevelWarn, "route not found", "path", r.URL.Path,
		"request", requestID(r.Context()))
	writeJSON(w, http.StatusNotFound, apiError{
		Error: apiProblem{Code: "not_found", Message: "no such endpoint"},
	})
}

type apiError struct {
	Error apiProblem `json:"error"`
}

type apiProblem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// writeProblem is the error shape every endpoint uses. Handlers use it, and
// the middleware uses the same shape, so a 401 and a 400 look alike.
func writeProblem(w http.ResponseWriter, status int, code, message, hint string) {
	writeJSON(w, status, apiError{Error: apiProblem{Code: code, Message: message, Hint: hint}})
}

// loginGuard wraps an unauthenticated endpoint with a rate bucket of its own,
// keyed per address. The login endpoints are the ones that cost CPU — every
// attempt runs argon2id — so they get separate buckets, and a caller who runs
// out of one cannot borrow from another.
func (s *server) loginGuard(next http.HandlerFunc, name string, limit int) http.Handler {
	if s.auth == nil {
		return noStore()
	}
	return s.auth.RateLimit(next, name, limit, nil)
}

// noStore is the answer of a server that has no database: 503, not 401, so a
// missing store cannot be mistaken for a server that refuses credentials.
func noStore() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusServiceUnavailable, "no_store",
			"the service has no database", "run signsrv migrate")
	})
}

// api is the wrapper every protected route uses: rate limit first, because the
// cost being limited is a CPU burst, then authentication, then the scope. The
// 600/min figure is the generic ceiling for an authenticated caller; the
// endpoints that cost more (a send, a batch trigger) get their own buckets.
func (s *server) api(next http.HandlerFunc, scopes ...string) http.Handler {
	if s.auth == nil {
		return noStore()
	}
	return s.auth.RateLimit(s.auth.RequireAPI(next, scopes...), "api", 600, nil)
}

// apiBucket is the same chain with a named bucket of its own, keyed per
// address. The endpoints that cost more than a read (a create, a send) use it,
// so their cost is limited on its own terms and cannot exhaust the generic
// budget the reads share.
func (s *server) apiBucket(next http.HandlerFunc, name string, limit int, scope string) http.Handler {
	if s.auth == nil {
		return noStore()
	}
	return s.auth.RateLimit(s.auth.RequireAPI(next, scope), name, limit, nil)
}
