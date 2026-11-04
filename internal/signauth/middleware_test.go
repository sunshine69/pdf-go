package signauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// stubStore is a PartyStore keyed by the hashes the middleware computes, so a
// middleware test does not need a database.
type stubStore struct {
	byToken   map[string]*signstore.Party
	bySession map[string]*signstore.Party
}

func (s *stubStore) GetPartyByTokenHash(_ context.Context, hash string) (*signstore.Party, error) {
	if p, ok := s.byToken[hash]; ok {
		return p, nil
	}
	return nil, signstore.ErrNotFound
}

func (s *stubStore) GetPartyBySessionHash(_ context.Context, hash string) (*signstore.Party, error) {
	if p, ok := s.bySession[hash]; ok {
		return p, nil
	}
	return nil, signstore.ErrNotFound
}

type stubRevoked struct{ set map[string]bool }

func (s *stubRevoked) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	return s.set[jti], nil
}

// stubEpochs returns a fixed epoch for a subject of a given kind.
type stubEpochs struct {
	epoch  int64
	prefix string
}

func (s *stubEpochs) AuthEpoch(_ context.Context, subject string) (int64, error) {
	if s.epoch > 0 && strings.HasPrefix(subject, s.prefix) {
		return s.epoch, nil
	}
	return 0, nil
}

func newAuth(t *testing.T) (*Auth, *Keyring, *stubStore) {
	t.Helper()
	k := newTestKeyring(t)
	store := &stubStore{byToken: map[string]*signstore.Party{}, bySession: map[string]*signstore.Party{}}
	return &Auth{Verifier: k, Revoked: &stubRevoked{set: map[string]bool{}}, Store: store}, k, store
}

// okHandler reports the subject the middleware put on its context, so the
// tests can assert that a handler sees the authenticated actor.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if c := ClaimsFrom(r.Context()); c != nil {
		w.Header().Set("X-Claims-Sub", c.Subject)
	}
	if p := PartyFrom(r.Context()); p != nil {
		w.Header().Set("X-Party-Id", p.ID)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

// decodeClaims reads the payload of a token so a test can re-sign a modified
// claim set with the same key: the signature is then valid and the claim is
// the only thing that can make the token fail.
func decodeClaims(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func doRequest(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequireAPIValid(t *testing.T) {
	a, k, _ := newAuth(t)
	token, err := k.MintAccess(&Claims{Subject: "7", Role: RoleClient,
		Scopes: []string{"envelope:read", "envelope:write"}}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	h := a.RequireAPI(okHandler, "envelope:read", "envelope:write")
	rec := doRequest(t, h, bearerRequest(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	// The handler sees the claims, so it can log the actor.
	if c := claimsIn(rec); c == nil || c.Subject != "7" {
		t.Fatalf("claims not on context: %+v", c)
	}
}

func bearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/envelopes", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// claimsIn reads the claims the middleware installed. The test handler records
// them on the recorder.
func claimsIn(rec *httptest.ResponseRecorder) *Claims {
	if v := rec.Header().Get("X-Claims-Sub"); v != "" {
		return &Claims{Subject: v}
	}
	return nil
}

func TestRequireAPIMissingBearer(t *testing.T) {
	a, _, _ := newAuth(t)
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"),
		httptest.NewRequest(http.MethodGet, "/api/v1/envelopes", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("body %s", rec.Body)
	}
}

func TestRequireAPIWrongScheme(t *testing.T) {
	a, k, _ := newAuth(t)
	token, err := k.MintAccess(clientClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/envelopes", nil)
	// The same token under a scheme that is not Bearer must not authenticate.
	r.Header.Set("Authorization", "Basic "+token)
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 for a non-Bearer scheme", rec.Code)
	}
}

func TestRequireAPIMissingScope(t *testing.T) {
	a, k, _ := newAuth(t)
	token, err := k.MintAccess(&Claims{Subject: "7", Role: RoleClient,
		Scopes: []string{"envelope:read"}}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	// Authenticated, but not allowed: 403, not 401.
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:write"), bearerRequest(token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Fatalf("body %s", rec.Body)
	}
	// An admin token passes every scope.
	adminToken, err := k.MintAccess(adminClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, a.RequireAdmin(okHandler), bearerRequest(adminToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status %d, want 200", rec.Code)
	}
}

func TestRequireAPIExpired(t *testing.T) {
	a, k, _ := newAuth(t)
	c := clientClaims()
	token, err := k.MintAccess(c, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the same key with a past expiry, so the signature is valid and
	// the expiry is the only thing that can reject it.
	claims, err := decodeClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	claims.IssuedAt = time.Now().Add(-3 * time.Hour).Unix()
	claims.Expires = time.Now().Add(-2 * time.Hour).Unix()
	expired, err := k.sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(expired))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "token_expired") {
		t.Fatalf("body %s, want the SPA to be able to refresh", rec.Body)
	}
}

func TestRequireAPIRevokedJTI(t *testing.T) {
	a, k, _ := newAuth(t)
	token, err := k.MintAccess(clientClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := decodeClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	// Logout revokes the jti: the token is well formed and in date, and must
	// still be refused.
	a.Revoked.(*stubRevoked).set[claims.JTI] = true
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "token_revoked") {
		t.Fatalf("body %s", rec.Body)
	}
}

func TestRequireAPIPasswordEpoch(t *testing.T) {
	a, k, _ := newAuth(t)
	// The password is changed after the token is minted, so the recorded
	// change time is later than the token's iat. This is the shape of the real
	// race: a token in hand when a user changes their password.
	a.Epochs = &stubEpochs{epoch: time.Now().Add(time.Minute).Unix(), prefix: "admin:"}

	// A token minted before the password change is refused, even though its
	// signature, audience and expiry are all fine.
	token, err := k.MintAccess(&Claims{Subject: "admin:1", Role: RoleAdmin}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAdmin(okHandler), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "credential_expired") {
		t.Fatalf("body %s, want the SPA to go back to the login screen", rec.Body)
	}

	// A client with no revocation has no epoch, so it keeps working.
	clientToken, err := k.MintAccess(&Claims{Subject: "client:3", Role: RoleClient,
		Scopes: []string{"envelope:read"}}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(clientToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("client status %d, want 200", rec.Code)
	}

	// Revoking the client sets its epoch, and a token minted before the
	// revocation is refused. The middleware must catch the token in hand, not
	// only the refresh path: a revoked client key must stop being usable.
	a.Epochs = &stubEpochs{epoch: time.Now().Add(time.Minute).Unix(), prefix: "client:"}
	rec = doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(clientToken))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked client status %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "credential_expired") {
		t.Fatalf("body %s", rec.Body)
	}
}

func TestRequireSignerCookieFlags(t *testing.T) {
	cookie := NewSessionCookie("session-value", 24*time.Hour, true)
	if cookie.Name != CookieName {
		t.Fatalf("cookie name %q", cookie.Name)
	}
	if cookie.Path != "/api/v1/sign/" {
		t.Fatalf("cookie path %q, must be scoped to the signing API", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Fatal("cookie is readable from JavaScript")
	}
	if !cookie.Secure {
		t.Fatal("cookie is sent over plain HTTP")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite %v, want Strict", cookie.SameSite)
	}
	if cookie.MaxAge <= 0 {
		t.Fatalf("Max-Age %d, must expire with the link", cookie.MaxAge)
	}
}

func TestRequireSignerClaimRequired(t *testing.T) {
	a, _, store := newAuth(t)
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	store.byToken[HashToken(token)] = &signstore.Party{ID: "p1", EnvelopeID: "e1",
		Status: signstore.PartyInvited}

	// A forwarded link reaches the claim screen: no cookie, so the party must
	// identify with their email address.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sign/"+token+"/envelope", nil)
	rec := doRequest(t, a.RequireSigner(okHandler), r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "claim_required") {
		t.Fatalf("body %s", rec.Body)
	}
}

func TestRequireSignerSessionMatch(t *testing.T) {
	a, _, store := newAuth(t)
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	party := &signstore.Party{ID: "p1", EnvelopeID: "e1", Status: signstore.PartyClaimed}
	store.byToken[HashToken(token)] = party
	store.bySession[HashToken(session)] = party

	r := httptest.NewRequest(http.MethodPost, "/api/v1/sign/"+token+"/consent", nil)
	r.AddCookie(NewSessionCookie(session, time.Hour, true))
	rec := doRequest(t, a.RequireSigner(okHandler), r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("X-Party-Id"); got != "p1" {
		t.Fatalf("party %q on context, want p1", got)
	}
}

func TestRequireSignerSessionCrossLink(t *testing.T) {
	a, _, store := newAuth(t)
	tokenA, _ := NewToken()
	tokenB, _ := NewToken()
	session, _ := NewToken()
	store.byToken[HashToken(tokenA)] = &signstore.Party{ID: "pA", EnvelopeID: "eA",
		Status: signstore.PartyClaimed}
	store.byToken[HashToken(tokenB)] = &signstore.Party{ID: "pB", EnvelopeID: "eB",
		Status: signstore.PartyClaimed}
	// The session belongs to envelope eB. Opening link A with it is refused.
	store.bySession[HashToken(session)] = &signstore.Party{ID: "pB", EnvelopeID: "eB",
		Status: signstore.PartyClaimed}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sign/"+tokenA+"/document", nil)
	r.AddCookie(NewSessionCookie(session, time.Hour, true))
	rec := doRequest(t, a.RequireSigner(okHandler), r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 for a session minted on another link", rec.Code)
	}
}

func TestRequireSignerExpiredLink(t *testing.T) {
	a, _, store := newAuth(t)
	token, _ := NewToken()
	session, _ := NewToken()
	expired := &signstore.Party{ID: "p1", EnvelopeID: "e1", Status: signstore.PartyExpired}
	store.byToken[HashToken(token)] = expired
	store.bySession[HashToken(session)] = expired

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sign/"+token+"/envelope", nil)
	r.AddCookie(NewSessionCookie(session, time.Hour, true))
	rec := doRequest(t, a.RequireSigner(okHandler), r)
	if rec.Code != http.StatusGone {
		t.Fatalf("status %d, want 410", rec.Code)
	}
}

func TestRateLimit429(t *testing.T) {
	a, _, _ := newAuth(t)
	a.Limits = NewLimiter()
	h := a.RateLimit(okHandler, "login", LoginLimit, nil)

	// Five attempts pass, the sixth is refused with a Retry-After.
	for i := 0; i < LoginLimit; i++ {
		rec := doRequest(t, h, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d status %d, want 200", i+1, rec.Code)
		}
	}
	rec := doRequest(t, h, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	retry := rec.Header().Get("Retry-After")
	if retry == "" {
		t.Fatal("429 without Retry-After")
	}
	if retry == "0" {
		t.Fatal("Retry-After 0 asks the client to retry immediately")
	}

	// The limit is per address: a second address has its own window.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "192.0.2.10:5000"
	rec = doRequest(t, h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second address status %d, want 200", rec.Code)
	}
}

func TestRateLimitPerEnvelope(t *testing.T) {
	a, _, _ := newAuth(t)
	a.Limits = NewLimiter()
	keyOf := func(r *http.Request) string { return PathToken(r) }
	h := a.RateLimit(okHandler, "consent", ConsentLimit, keyOf)

	// Parties of one envelope share the bucket: the limit counts requests to
	// the envelope, which is the resource being protected.
	linkA := strings.Repeat("a", 32)
	for i := 0; i < ConsentLimit; i++ {
		rec := doRequest(t, h, httptest.NewRequest(http.MethodPost,
			"/api/v1/sign/"+linkA+"/consent", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("consent %d status %d", i+1, rec.Code)
		}
	}
	rec := doRequest(t, h, httptest.NewRequest(http.MethodPost,
		"/api/v1/sign/"+linkA+"/consent", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 for the envelope bucket", rec.Code)
	}
	rec = doRequest(t, h, httptest.NewRequest(http.MethodPost,
		"/api/v1/sign/"+strings.Repeat("b", 32)+"/consent", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 for a different envelope", rec.Code)
	}
}

func TestClientIPTrustProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:51234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")

	if ip := ClientIP(r, false); ip != "198.51.100.7" {
		t.Fatalf("untrusted proxy: %q, want the peer address", ip)
	}
	if ip := ClientIP(r, true); ip != "203.0.113.9" {
		t.Fatalf("trusted proxy: %q, want the left-most forwarded address", ip)
	}
}

func TestPathToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sign/abc123/consent", nil)
	if tok := PathToken(r); tok != "abc123" {
		t.Fatalf("token %q", tok)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/envelopes/1", nil)
	if tok := PathToken(r); tok != "" {
		t.Fatalf("token %q on a non-signing route", tok)
	}
}
