package signauth

import (
	"context"
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
}

// Epochs reports the moment the credential behind a subject last stopped being
// valid: a password change, or a client revocation. A token minted before that
// moment was minted under a credential that has since been replaced, and must
// stop working. This is the one thing a user can do when a token is stolen.
type Epochs interface {
	AuthEpoch(ctx context.Context, subject string) (int64, error)
}

// Auth bundles what the middleware needs. The fields are interfaces so a test
// can supply a stub, and so the HTTP layer never reaches into the database.
type Auth struct {
	Verifier   Verifier
	Revoked    Revocations
	Store      PartyStore
	Epochs     Epochs
	Limits     *Limiter
	TrustProxy bool
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
		cookie, err := r.Cookie(CookieName)
		if err != nil || cookie.Value == "" {
			a.writeProblem(w, r, 401, "claim_required",
				"claim this link with your email address first")
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
		if party.Status == signstore.PartyExpired {
			a.writeProblem(w, r, 410, "link_expired", "this link has expired")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyParty{}, party)))
	})
}

// RateLimit guards one route with one limit. keyOf builds the bucket key:
// per-address for login/claim/link opens, per-envelope for consent, which is
// the limit a party cannot escape by changing source address.
func (a *Auth) RateLimit(next http.Handler, name string, limit int, keyOf func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Limits != nil {
			key := name + ":"
			if keyOf != nil {
				key += keyOf(r)
			} else {
				key += ClientIP(r, a.TrustProxy)
			}
			if ok, retry := a.Limits.Allow(key, limit, Window); !ok {
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
