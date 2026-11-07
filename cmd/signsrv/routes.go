package main

import (
	"log/slog"
	"net/http"
	"time"

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
	s.mux.Handle("POST /api/v1/envelopes/{id}/send",
		s.apiBucket(s.handleSendEnvelope, "send", signauth.SendLimit,
			signauth.ScopeEnvelopeWrite))
	s.mux.Handle("GET /api/v1/envelopes/{id}", s.api(s.handleGetEnvelope, signauth.ScopeEnvelopeRead))
	s.mux.Handle("GET /api/v1/envelopes/{id}/document", s.api(s.handleGetDocument, signauth.ScopeEnvelopeRead))
	s.mux.Handle("GET /api/v1/envelopes/{id}/revisions/{rid}", s.api(s.handleGetRevision, signauth.ScopeEnvelopeRead))

	// The admin endpoints of step 09. The audit log, the settings, the machine
	// clients and the admin logout live under /admin and need the admin
	// scope; the envelope actions sit on the envelope and ride the envelope
	// scopes, the same way send does, so a machine client that may write an
	// envelope may also remind, cancel, reissue and trigger its batch.
	s.mux.Handle("GET /api/v1/admin/events", s.api(s.handleAdminEvents, signauth.ScopeAdminRead))
	s.mux.Handle("GET /api/v1/admin/settings", s.api(s.handleSettingsGet, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/settings", s.api(s.handleSettingsPost, signauth.ScopeAdminRead))
	// The settings page writes with PATCH, so the verb says "these fields
	// change" rather than "the whole settings document is replaced": a page
	// that only knows two of the four values must not blank the other two.
	s.mux.Handle("PATCH /api/v1/admin/settings", s.api(s.handleSettingsPatch, signauth.ScopeAdminRead))
	// The client list is how the operator finds the id to revoke. The key is
	// never in it.
	s.mux.Handle("GET /api/v1/admin/clients", s.api(s.handleClientsList, signauth.ScopeAdminRead))
	s.mux.Handle("DELETE /api/v1/admin/clients/{id}", s.api(s.handleClientRevoke, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/clients", s.api(s.handleClientCreate, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/clients/{id}/revoke", s.api(s.handleClientRevoke, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/logout", s.api(s.handleAdminLogout, signauth.ScopeAdminRead))

	// The service chores: the questions an operator asks of a server they are not
	// standing next to. Every one of them is a `signsrv` verb, and every one of
	// them is also a route, so the runbook step is the same on both sides of the
	// network.
	//
	// The reads are GET under admin:read. The writes are POST under the same
	// scope: the scope is the admin surface, and a token that may read the audit
	// chain must be able to verify it. The POSTs that touch disk or send mail get
	// a named bucket, so a loop cannot burn the CPU of the read endpoints.
	s.mux.Handle("GET /api/v1/admin/dbstatus", s.api(s.handleDBStatus, signauth.ScopeAdminRead))
	s.mux.Handle("GET /api/v1/admin/schema", s.api(s.handleSchemaStatus, signauth.ScopeAdminRead))
	s.mux.Handle("GET /api/v1/admin/configcheck", s.api(s.handleConfigCheck, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/sweep",
		s.apiBucket(s.handleSweep, "sweep", signauth.SendLimit, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/audit/verify",
		s.api(s.handleAuditVerify, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/audit/write",
		s.apiBucket(s.handleAuditWrite, "audit-write", signauth.SendLimit, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/mail-test",
		s.apiBucket(s.handleMailTest, "mail-test", choreMailLimit, signauth.ScopeAdminRead))
	s.mux.Handle("GET /api/v1/admin/users", s.api(s.handleUsersList, signauth.ScopeAdminRead))
	s.mux.Handle("DELETE /api/v1/admin/users/{id}",
		s.api(s.handleUserRevoke, signauth.ScopeAdminRead))
	s.mux.Handle("POST /api/v1/admin/users/{id}/revoke",
		s.api(s.handleUserRevoke, signauth.ScopeAdminRead))

	s.mux.Handle("POST /api/v1/envelopes/{id}/remind",
		s.envelopeBucket(s.handleEnvelopeRemind, "remind", signauth.RemindLimit,
			signauth.RemindWindow, signauth.ScopeEnvelopeWrite))
	s.mux.Handle("POST /api/v1/envelopes/{id}/cancel",
		s.apiBucket(s.handleEnvelopeCancel, "cancel", signauth.SendLimit,
			signauth.ScopeEnvelopeWrite))
	s.mux.Handle("POST /api/v1/envelopes/{id}/reissue",
		s.apiBucket(s.handleEnvelopeReissue, "reissue", signauth.SendLimit,
			signauth.ScopeEnvelopeWrite))
	s.mux.Handle("POST /api/v1/envelopes/{id}/sign",
		s.apiBucket(s.handleEnvelopeSign, "sign", signauth.SendLimit,
			signauth.ScopeEnvelopeWrite))
	s.mux.Handle("GET /api/v1/envelopes/{id}/report",
		s.api(s.handleEnvelopeReport, signauth.ScopeEnvelopeRead))
	s.mux.Handle("GET /api/v1/envelopes/{id}/audit.zip",
		s.api(s.handleEnvelopeAuditZip, signauth.ScopeEnvelopeRead))
	// The public signing endpoints. A link token is the credential, so these
	// are guarded by the signer chain, not by a bearer token. Claim is
	// rate-limited per address (10/min) because it runs the address check;
	// consent and decline are limited per envelope (10/min), which is the
	// limit a party cannot escape by changing source address. The view and
	// the document are per address, which is what a forwarded link saturates.
	s.mux.Handle("POST "+signAPI+"/claim",
		s.signGuard(s.handleSignerClaim, "claim", signauth.ClaimLimit, false))
	s.mux.Handle("GET "+signAPI+"/envelope",
		s.signGuard(s.handleSignerEnvelope, "link-read", signauth.LinkLimit, false))
	s.mux.Handle("GET "+signAPI+"/document",
		s.signGuard(s.handleSignerDocument, "link-doc", signauth.LinkLimit, true))
	s.mux.Handle("POST "+signAPI+"/consent",
		s.signGuard(s.handleSignerConsent, "consent", signauth.ConsentLimit, true))
	s.mux.Handle("POST "+signAPI+"/decline",
		s.signGuard(s.handleSignerDecline, "consent", signauth.ConsentLimit, true))

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

// choreMailLimit is the per-minute budget of the mail-test route. Six is enough
// for an operator checking a relay, and small enough that a leaked admin token
// cannot turn the service into a spam relay.
const choreMailLimit = 6

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
// envelopeBucket is the envelope-keyed bucket: the cost being limited is the
// mail the endpoint queues for one envelope's parties, so the budget belongs
// to the envelope, not to the address that called. The remind limit is also on
// a slower clock than every other bucket (two per ten minutes), which is why
// it takes its window as a parameter.
func (s *server) envelopeBucket(next http.HandlerFunc, name string, limit int, window time.Duration, scope string) http.Handler {
	if s.auth == nil {
		return noStore()
	}
	keyOf := func(r *http.Request) string { return r.PathValue("id") }
	return s.auth.RateLimitWindow(s.auth.RequireAPI(next, scope), name, limit, window, keyOf)
}

func (s *server) apiBucket(next http.HandlerFunc, name string, limit int, scope string) http.Handler {
	if s.auth == nil {
		return noStore()
	}
	return s.auth.RateLimit(s.auth.RequireAPI(next, scope), name, limit, nil)
}

// signAPI is the path prefix of the party-facing endpoints. The token is a path
// value, so every route of the family is this prefix plus its verb.
const signAPI = "/api/v1/sign/{token}"

// signGuard wraps a signing endpoint in its rate bucket and, for the routes
// that need a claim, the signer chain. The claim route is deliberately not
// behind RequireSigner: the claim is what mints the session, so it cannot
// require one.
func (s *server) signGuard(next http.HandlerFunc, name string, limit int, claimed bool) http.Handler {
	if s.auth == nil {
		return noStore()
	}
	h := http.Handler(http.HandlerFunc(next))
	if claimed {
		h = s.auth.RequireSigner(h)
	}
	keyOf := func(r *http.Request) string { return signauth.ClientIP(r, s.cfg.TrustProxy) }
	if name == "consent" {
		// Per envelope: a party behind a shared address cannot be starved by
		// its neighbours, and consent is the action that must not be farmed.
		keyOf = func(r *http.Request) string { return r.PathValue("token") }
	}
	return s.auth.RateLimit(h, name, limit, keyOf)
}
