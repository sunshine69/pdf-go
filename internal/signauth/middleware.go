package signauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Middleware. Order for every protected route: rate limit -> authentication ->
// scope -> handler. A handler receives a party only through the context, so no
// endpoint can be talked into acting on a party id it was given in a body.

// CookieName is the signer session cookie. Its Path is the signing API
// subtree, so an API token for the admin app is never sent to a signer route
// and a signer cookie is never sent to an admin route.
const (
	CookieName = "signsrv_s"
	CookiePath = "/api/v1/sign/"
)

// Verifier is the token source: it checks the signature and the claims.
type Verifier interface {
	VerifyAccess(token string) (*Claims, error)
	KeyID() string
}

// Revocations is the jti list, implemented by signstore.Store.
type Revocations interface {
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)
}

// PartyStore is the slice of the store the middleware needs. A party is
// resolved from a token hash or a session hash, never from a request.
type PartyStore interface {
	GetPartyByTokenHash(ctx context.Context, hash string) (*signstore.Party, error)
	GetPartyBySessionHash(ctx context.Context, hash string) (*signstore.Party, error)
	GetEnvelope(ctx context.Context, id string) (*signstore.Envelope, error)
}

// Epochs reports the moment the credential behind a subject last stopped being
// valid: a password change, or a client revocation. A token minted before that
// moment was minted under a credential that has since been replaced, and must
// stop working. This is the one thing a user can do when a token is stolen.
type Epochs interface {
	AuthEpoch(ctx context.Context, subject string) (int64, error)
}

// UserRows is the users table, as the API gate needs it. A caller-minted
// (HS256) token carries a username in sub; the row behind that name decides
// three things the token does not get to decide for itself:
//
//   - whether the account is revoked at all (a token the service never minted
//     has no jti to revoke, so the row is the only state there is)
//   - the scopes granted (the token claims scopes, the row grants them)
//   - the role (so a secret cannot mint "role":"admin")
type UserRows interface {
	GetByUsername(ctx context.Context, username string) (*signstore.User, error)
}

// Auth bundles what the middleware needs. The fields are interfaces so a test
// can supply a stub, and so the HTTP layer never reaches into the database.
type Auth struct {
	Verifier   Verifier
	Revoked    Revocations
	Store      PartyStore
	Epochs     Epochs
	Users      UserRows
	Limits     *Limiter
	TrustProxy bool

	// Budgets are the per-route request budgets the routes are wrapped with.
	// It is a value, not a pointer, because a zero Budgets is meaningful: it
	// means "the defaults", which is what a hand-built Auth in a test wants.
	// The server fills it from the config file.
	Budgets Limits

	// now is the clock the signing guard reads. It is nil-safe: a zero Auth
	// uses the wall clock, so a test that builds Auth by hand gets the same
	// behaviour as the server.
	now func() time.Time
}

// SetClock installs the clock the signing guard reads. The server passes the
// clock it was built with, so a test that runs the guard on a fixed time can
// prove that a request whose deadline has passed is refused before any rule
// that touches the database is reached.
func (a *Auth) SetClock(c func() time.Time) {
	if c != nil {
		a.now = c
	}
}

// clock is the clock, defaulted.
func (a *Auth) clock() func() time.Time {
	if a.now == nil {
		return time.Now
	}
	return a.now
}

// Problem is the error shape the API returns. The middleware builds it so a
// 401 and a 429 look the same as every other error in the service.
type Problem struct {
	Code    string
	Message string
	Hint    string
	Status  int
}

type ctxKeyRequest struct{}
type ctxKeyClaims struct{}
type ctxKeyParty struct{}

// RequireAPI guards the machine/admin audience: Authorization: Bearer, aud=api,
// scopes ⊆ claims. Scopes are ANDed: a route that needs two scopes is granted
// only to a token that carries both.
func (a *Auth) RequireAPI(next http.Handler, scopes ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			a.writeProblem(w, r, 401, "unauthorized", "no bearer token")
			return
		}
		// Two token kinds, two verifiers, chosen by the token's header. Each
		// verifier pins its own algorithm, so this is routing and not trust:
		// an EdDSA token can never be checked with an HMAC secret, and an
		// HS256 token can never be checked with the service's public key.
		if a.Users != nil && IsHS256Token(token) {
			a.requireUserToken(w, r, next, token, scopes)
			return
		}
		claims, err := a.Verifier.VerifyAccess(token)
		if err != nil {
			// Expired and invalid are distinguished: the SPA refreshes on
			// "expired" and shows a login screen on "unauthorized".
			code, status := "unauthorized", http.StatusUnauthorized
			if err == ErrTokenExpired {
				code, status = "token_expired", http.StatusUnauthorized
			}
			a.writeProblem(w, r, status, code, "token rejected")
			return
		}
		if a.Revoked != nil {
			revoked, err := a.Revoked.IsJTIRevoked(r.Context(), claims.JTI)
			if err != nil {
				a.writeProblem(w, r, 500, "internal", "revocation check failed")
				return
			}
			if revoked {
				a.writeProblem(w, r, 401, "token_revoked", "token was revoked")
				return
			}
		}
		// A token minted before the subject's credential was replaced is
		// refused. Two things set the epoch: a password change, and a client
		// revocation. Both mean the same thing here — the token in hand must
		// stop working — so there is one check.
		if a.Epochs != nil {
			epoch, err := a.Epochs.AuthEpoch(r.Context(), claims.Subject)
			if err != nil {
				a.writeProblem(w, r, 500, "internal", "credential epoch check failed")
				return
			}
			// Strictly before. pw_changed_at is recorded to the second, so a
			// token minted in the same second as the change survives: the
			// login and the change cannot be ordered inside one second. The
			// window is one second, and a user who changes their password and
			// signs in straight away gets a working token, which is the
			// behaviour that has to hold.
			if epoch > 0 && claims.IssuedAt < epoch {
				a.writeProblem(w, r, 401, "credential_expired",
					"the credential behind this token was replaced; sign in again")
				return
			}
		}
		for _, scope := range scopes {
			if !claims.HasScope(scope) {
				a.writeProblem(w, r, 403, "insufficient_scope",
					"this endpoint needs the scope "+scope)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyClaims{}, claims)))
	})
}

// RequireAdmin is role=admin and aud=api.
func (a *Auth) RequireAdmin(next http.Handler) http.Handler {
	return a.RequireAPI(next, ScopeAdminRead)
}

// MaxUserTokenTTL is the longest validity a caller-minted token may carry. The
// CLI caps its own tokens at AccessTTL and the guard enforces the same cap: a
// leaked secret then buys 15 minutes, not a year, because the server refuses a
// longer window rather than trusting the caller to ask for a short one.
const MaxUserTokenTTL = AccessTTL

// requireUserToken checks a caller-minted (HS256) token against the users row
// named by sub, then answers the scope check with the row's scopes.
//
// Order matters. The row is read before the secret is used, so the secret is
// never chosen by anything the caller signed; the signature is checked with
// that row's secret. A revoked row is refused before the signature is
// considered: a revoked account is refused whether or not its token is well
// formed.
func (a *Auth) requireUserToken(w http.ResponseWriter, r *http.Request, next http.Handler, token string, scopes []string) {
	// A first read of the payload, to learn the subject only. Nothing is
	// trusted from it: the signature is checked below with the row's secret.
	name, err := peekSubject(token)
	if err != nil {
		a.writeProblem(w, r, 401, "unauthorized", "token rejected")
		return
	}
	row, err := a.Users.GetByUsername(r.Context(), name)
	// The admin scope is not reachable with a caller-minted token, whatever
	// the row grants. The admin surface is the whole system (clients, settings,
	// audit, every envelope's document), and its tokens are minted by the
	// service with the EdDSA key. Keeping that surface EdDSA-only means a
	// leaked dispatch secret cannot become an administrator, and means the
	// scopes column can never be widened into a takeover by a typo in an
	// UPDATE.
	for _, scope := range scopes {
		if scope == ScopeAdminRead {
			a.writeProblem(w, r, 403, "insufficient_scope",
				"this endpoint needs a token minted by the service, not one signed by a client secret")
			return
		}
	}

	if err != nil || row == nil {
		// No row: the same answer as a bad signature. Whether a username
		// exists is not this endpoint's to say.
		a.writeProblem(w, r, 401, "unauthorized", "token rejected")
		return
	}
	if row.RevokedAt != "" {
		a.writeProblem(w, r, 401, "token_revoked", "this account was revoked")
		return
	}
	claims, err := VerifyUserToken(row.JWTSecret, token)
	if err != nil {
		code, status := "unauthorized", http.StatusUnauthorized
		if err == ErrTokenExpired {
			code, status = "token_expired", http.StatusUnauthorized
		}
		a.writeProblem(w, r, status, code, "token rejected")
		return
	}
	// The validity window is capped by the server, not agreed with the caller.
	if claims.Expires-claims.IssuedAt > int64(MaxUserTokenTTL/time.Second) {
		a.writeProblem(w, r, 401, "token_ttl",
			"the token asks for a validity longer than the service allows")
		return
	}
	// The password stamp is the epoch, exactly as for an admin session: a
	// password change stops every token minted before it. Strictly before, so
	// a token minted in the same second as the change survives.
	epoch, err := unixOf(row.PWChangedAt)
	if err != nil {
		a.writeProblem(w, r, 500, "internal", "credential epoch check failed")
		return
	}
	if epoch > 0 && claims.IssuedAt < epoch {
		a.writeProblem(w, r, 401, "credential_expired",
			"the credential behind this token was replaced; mint a new one")
		return
	}
	// The grant comes from the row: the token is signed by whoever holds the
	// secret, and holding a secret is not a grant. Role is pinned to user, so
	// a secret cannot reach an admin route.
	claims.Role = RoleUser
	claims.Scopes = signstore.ScopeList(row.Scopes)
	for _, scope := range scopes {
		if !claims.HasScope(scope) {
			a.writeProblem(w, r, 403, "insufficient_scope",
				"this endpoint needs the scope "+scope)
			return
		}
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyClaims{}, claims)))
}

// peekSubject decodes the "sub" of a compact token without checking anything.
// It exists to find the row whose secret is needed to check the signature, and
// it is the only place in this package that reads an unverified payload.
func peekSubject(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrTokenInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrTokenInvalid
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Subject == "" {
		return "", ErrTokenInvalid
	}
	return claims.Subject, nil
}

// unixOf turns a stored RFC 3339 stamp into seconds. Empty is 0, which the
// epoch check reads as "no epoch".
func unixOf(stamp string) (int64, error) {
	if stamp == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// Scopes. The vocabulary is fixed: a route names the scope it needs, a client
// token is minted with a subset of these names, and an admin token carries
// all of them. A route with no scope in the list is not granted, so the
// default answer for an unknown route is 403.
const (
	ScopeAdminRead     = "admin:read"
	ScopeEnvelopeRead  = "envelope:read"
	ScopeEnvelopeWrite = "envelope:write"
)

// RequireSigner guards the public signing routes. The link token comes from the
// path, the session from the cookie, and the two must resolve to the same
// party: a link forwarded to a third party reaches the claim screen, not the
// consent screen.
func (a *Auth) RequireSigner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := PathToken(r)
		if token == "" {
			a.writeProblem(w, r, 404, "not_found", "no signing link in this path")
			return
		}
		party, err := a.Store.GetPartyByTokenHash(r.Context(), HashToken(token))
		if err != nil || party == nil {
			a.writeProblem(w, r, 404, "not_found", "this link is not valid")
			return
		}
		// The link's own facts come first, in the order the API table lists
		// them, because they are facts about the link and not about the caller:
		// a party that never claimed can still be told the link is gone.
		// A failure to read the envelope is not itself a 404 (the party resolved
		// fine); the guard falls through to the session check and lets the flow
		// layer give the definitive answer.
		if env, err := a.Store.GetEnvelope(r.Context(), party.EnvelopeID); err == nil && env != nil {
			if ClosedStatus(string(env.Status)) {
				a.writeProblem(w, r, 410, "request_closed", "this signing request is closed")
				return
			}
			if a.linkExpired(party, env) {
				a.writeProblem(w, r, 410, "link_expired", "this link has expired")
				return
			}
		}
		cookie, err := r.Cookie(CookieName)
		if err != nil || cookie.Value == "" {
			a.writeProblem(w, r, 401, "claim_required",
				"claim this link with your email address first")
			return
		}
		// The party's own state comes before its credentials, because the action
		// that closes a party is the one that destroys its session: a party that
		// has already consented is refused on its state, not on the cookie the
		// consent spent.
		if string(party.Status) == "expired" {
			a.writeProblem(w, r, 410, "link_expired", "this link has expired")
			return
		}
		if ClosedParty(string(party.Status)) {
			a.writeProblem(w, r, 409, "state_conflict",
				"this party cannot act in its current state")
			return
		}
		session, err := a.Store.GetPartyBySessionHash(r.Context(), HashToken(cookie.Value))
		if err != nil || session == nil {
			a.writeProblem(w, r, 401, "claim_required",
				"claim this link with your email address first")
			return
		}
		// The session belongs to this party and to this envelope. A session
		// cookie minted for one link cannot open another.
		if session.ID != party.ID || session.EnvelopeID != party.EnvelopeID {
			a.writeProblem(w, r, 403, "session_mismatch",
				"this session belongs to a different signing link")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyParty{}, party)))
	})
}

// window is the span a bucket counts, for the routes that use the standard
// one. The limits themselves are resolved once, when the routes are wired;
// this is the per-request half, and it stays cheap so a refused request does
// not pay for rebuilding the budget set.
func (a *Auth) window() time.Duration {
	if a.Budgets.Window > 0 {
		return a.Budgets.Window
	}
	return Window
}

// RateLimit guards one route with one limit. keyOf builds the bucket key:
// per-address for login/claim/link opens, per-envelope for consent, which is
// the limit a party cannot escape by changing source address.
// RateLimitWindow is RateLimit with a window of its own, for the buckets the
// standard window cannot express: the remind limit is two per ten minutes per
// envelope, which is a slower clock than the one every other bucket counts on.
func (a *Auth) RateLimitWindow(next http.Handler, name string, limit int, window time.Duration, keyOf func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Limits != nil {
			key := name + ":"
			if keyOf != nil {
				key += keyOf(r)
			} else {
				key += ClientIP(r, a.TrustProxy)
			}
			if ok, retry := a.Limits.Allow(key, limit, window); !ok {
				w.Header().Set("Retry-After", retryAfter(retry))
				a.writeProblem(w, r, http.StatusTooManyRequests, "rate_limited",
					"too many requests, retry later")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) RateLimit(next http.Handler, name string, limit int, keyOf func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Limits != nil {
			key := name + ":"
			if keyOf != nil {
				key += keyOf(r)
			} else {
				key += ClientIP(r, a.TrustProxy)
			}
			// The window is read outside the Allow call so a request that is
			// refused does not pay for a second look at the budget set.
			if ok, retry := a.Limits.Allow(key, limit, a.window()); !ok {
				w.Header().Set("Retry-After", retryAfter(retry))
				a.writeProblem(w, r, http.StatusTooManyRequests, "rate_limited",
					"too many requests, retry later")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// PathToken is the link token of a signing route, "/api/v1/sign/{token}/...".
// It is read from the path and never from the query string, so it does not end
// up in a proxy log line.
func PathToken(r *http.Request) string {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "sign" {
			return parts[i+1]
		}
	}
	return ""
}

func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// ClaimsFrom returns the claims the middleware installed.
func ClaimsFrom(ctx context.Context) *Claims {
	if c, ok := ctx.Value(ctxKeyClaims{}).(*Claims); ok {
		return c
	}
	return nil
}

// PartyFrom returns the party the signer middleware resolved. Handlers must
// take the party from here and nowhere else.
func PartyFrom(ctx context.Context) *signstore.Party {
	if p, ok := ctx.Value(ctxKeyParty{}).(*signstore.Party); ok {
		return p
	}
	return nil
}

// NewSessionCookie builds the signer session cookie. HttpOnly, Secure outside
// dev, SameSite=Strict, Path scoped to the signing API, Max-Age bound to the
// link expiry.
func NewSessionCookie(value string, ttl time.Duration, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     CookiePath,
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// retryAfter renders a Retry-After delay as whole seconds, rounding up:
// telling a client to wait 0.4 seconds is telling it to retry immediately.
func retryAfter(d time.Duration) string {
	seconds := int(d.Seconds())
	if d.Seconds() > float64(seconds) {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

// writeProblem answers in the shape every error in the service uses,
// {"error":{code,message,hint}}. A middleware never explains why a token was
// rejected beyond the code: which check failed is information a caller can use
// to search for the one check that passes.
func (a *Auth) writeProblem(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	body := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint,omitempty"`
		} `json:"error"`
	}{}
	body.Error.Code = code
	body.Error.Message = message
	body.Error.Hint = "authenticated requests only"
	if code == "rate_limited" {
		body.Error.Hint = "retry after the window"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ClosedStatus reports the envelope states that close every link on them: a
// request that has failed, been cancelled, expired, or is already finished is
// over, and a live token into it is a dead link.
func ClosedStatus(status string) bool {
	switch status {
	case "failed", "cancelled", "expired", "completed", "delivered",
		"consented", "declined":
		return true
	}
	return false
}

// ClosedParty reports the party states that have had their say: consented,
// declined and expired are all closed, and on the API's table they are a 409
// for consented and declined and a 410 for expired, because an expired
// party's link is expired too.
func ClosedParty(status string) bool {
	switch status {
	case "consented", "declined", "expired":
		return true
	}
	return false
}

// linkExpired reports whether the link or its envelope is past its deadline,
// read off rows the guard already holds.
func (a *Auth) linkExpired(p *signstore.Party, env *signstore.Envelope) bool {
	now := a.clock()
	for _, at := range []string{p.TokenExpires, env.ExpiresAt} {
		if at == "" {
			continue
		}
		if exp, err := time.Parse(time.RFC3339, at); err == nil && exp.Before(now()) {
			return true
		}
	}
	return false
}
