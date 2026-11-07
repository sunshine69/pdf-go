package signauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The caller-minted (HS256) path through RequireAPI. These are the tests for
// the shape the operator asked for: the CLI signs its own token with a secret
// that is in the users row, and the service answers with what its rows say, not
// with what the token claims.
//
// Every case here is a way the shape could be abused. A test that only shows a
// good token passing would prove nothing about a credential the server never
// issued.

// stubUsers is the users table as the gate sees it: one read, by username.
type stubUsers struct {
	byName map[string]*signstore.User
	calls  int // how many times the row was read, to prove the order of checks
}

func (s *stubUsers) GetByUsername(_ context.Context, username string) (*signstore.User, error) {
	s.calls++
	if u, ok := s.byName[username]; ok {
		return u, nil
	}
	return nil, signstore.ErrNotFound
}

// userAuth is the gate with a users table wired. The Keyring is real, so the
// EdDSA path works in the same tests: one gate, two token kinds.
func userAuth(t *testing.T, users map[string]*signstore.User) (*Auth, *Keyring, *stubUsers) {
	t.Helper()
	k := newTestKeyring(t)
	u := &stubUsers{byName: users}
	return &Auth{Verifier: k, Revoked: &stubRevoked{set: map[string]bool{}},
		Store: &stubStore{byToken: map[string]*signstore.Party{}}, Users: u}, k, u
}

// mintWith signs a caller's token exactly as MintUserToken does, with the ttl
// taken literally. MintUserToken caps the window — that cap is one of the
// things under test — so a test that needs a 30-day token has to sign it here.
func mintWith(t *testing.T, secret, username string, scopes []string, ttl time.Duration) string {
	t.Helper()
	now := time.Now().Unix()
	payload, err := json.Marshal(&Claims{
		Issuer: Issuer, Subject: username, Audience: AudienceAPI, Role: RoleUser,
		Scopes: scopes, IssuedAt: now, Expires: now + int64(ttl/time.Second), JTI: "cli-jti",
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]string{"alg": AlgHS256, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(hmacSHA(secret, body))
}

const cliSecret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNl" // 32 bytes, raw url b64

func userRow(scopes, revokedAt, pwChangedAt string) *signstore.User {
	return &signstore.User{
		ID: 7, Username: "dispatch", JWTSecret: cliSecret,
		Scopes: scopes, Role: RoleUser, RevokedAt: revokedAt, PWChangedAt: pwChangedAt,
	}
}

// 1. The happy path: the CLI's own token, granted the row's scopes.
func TestUserTokenGrantedFromRow(t *testing.T) {
	a, _, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	token, err := MintUserToken(cliSecret, "dispatch", []string{"envelope:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	// The subject on the context is the username, so the audit line names the
	// account and not a client id.
	if c := claimsIn(rec); c == nil || c.Subject != "dispatch" {
		t.Fatalf("claims not on context: %+v", c)
	}
}

// 2. Scopes come from the row. A token that claims envelope:write over a row
// that grants only reads gets 403: holding the secret is not the grant.
func TestUserTokenCannotGrantItselfAScope(t *testing.T) {
	a, _, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	token, err := MintUserToken(cliSecret, "dispatch", []string{"envelope:read", "envelope:write"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:write"), bearerRequest(token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403, body %s", rec.Code, rec.Body)
	}
	if !jsonContains(rec, "insufficient_scope") {
		t.Fatalf("body %s: want the code insufficient_scope", rec.Body)
	}
}

// 3. The admin surface is not reachable with a caller-minted token, even for a
// row whose scopes say admin:read. A leaked dispatch secret must not be the
// whole system, and a typo in an UPDATE must not be a takeover.
func TestUserTokenNeverReachesAdmin(t *testing.T) {
	a, _, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read,admin:read", "", "")})
	token, err := MintUserToken(cliSecret, "dispatch", []string{"admin:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAdmin(okHandler), bearerRequest(token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403, body %s", rec.Code, rec.Body)
	}
	if !jsonContains(rec, "insufficient_scope") {
		t.Fatalf("body %s: want the code insufficient_scope", rec.Body)
	}
	// The row was never read: the answer is about the token kind, and it is
	// given before the database is touched.
}

// 4. The same admin route, with a token the service minted: 200. The rule is
// about who signed the token, not about the scopes column.
func TestAdminTokenFromKeyringReachesAdmin(t *testing.T) {
	a, k, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	token, err := k.MintAccess(&Claims{Subject: "admin:1", Role: RoleAdmin,
		Scopes: []string{ScopeAdminRead}}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAdmin(okHandler), bearerRequest(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
}

// 5. A token signed with a secret that is not the row's: refused, with the same
// answer as an unknown username, so the gate does not confirm that a name exists.
func TestUserTokenWrongSecret(t *testing.T) {
	a, _, u := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	token, err := MintUserToken("some-other-secret", "dispatch", []string{"envelope:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401, body %s", rec.Code, rec.Body)
	}
	// The row is read before the signature is checked: the secret that verifies
	// a token is chosen by the database, never by the token.
	if u.calls != 1 {
		t.Fatalf("row reads = %d, want 1", u.calls)
	}
}

// 6. No row for the subject. The answer is the 401 of a bad signature.
func TestUserTokenUnknownUsername(t *testing.T) {
	a, _, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	token, err := MintUserToken(cliSecret, "nobody", []string{"envelope:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401, body %s", rec.Code, rec.Body)
	}
}

// 7. The revoked row. This is the answer to "there is nothing to look up for a
// token the server never minted": the row is the lookup, so revocation exists.
func TestUserTokenRevokedRow(t *testing.T) {
	a, _, _ := userAuth(t, map[string]*signstore.User{
		"dispatch": userRow("envelope:read", "2026-11-07T10:00:00Z", "")})
	token, err := MintUserToken(cliSecret, "dispatch", []string{"envelope:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401, body %s", rec.Code, rec.Body)
	}
	if !jsonContains(rec, "token_revoked") {
		t.Fatalf("body %s: want the code token_revoked", rec.Body)
	}
}

// 8. A window longer than the service allows. The cap is the server's, so a
// secret leaked today buys fifteen minutes and not a year.
func TestUserTokenTTLIsCappedByServer(t *testing.T) {
	a, _, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	// MintUserToken caps the ttl it is given, so the long token is signed here.
	token := mintWith(t, cliSecret, "dispatch", []string{"envelope:read"}, 30*24*time.Hour)
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401, body %s", rec.Code, rec.Body)
	}
	if !jsonContains(rec, "token_ttl") {
		t.Fatalf("body %s: want the code token_ttl", rec.Body)
	}
	// And the CLI's own mint is capped at the same figure, so the cap is not a
	// rule the caller can honour by asking politely.
	short, err := MintUserToken(cliSecret, "dispatch", []string{"envelope:read"}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeClaims(short)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(c.Expires-c.IssuedAt) * time.Second; got != MaxUserTokenTTL {
		t.Fatalf("MintUserToken window = %v, want %v", got, MaxUserTokenTTL)
	}
}

// 9. The password epoch. A token minted under the old password stops when the
// password changes, which is the user's one action after a leak.
func TestUserTokenPasswordEpoch(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-time.Hour).Format(time.RFC3339)
	a, _, _ := userAuth(t, map[string]*signstore.User{
		"dispatch": userRow("envelope:read", "", now.Format(time.RFC3339))})

	// A token minted an hour before the change: refused.
	// Minted two minutes before the change, inside its own window: the token in
	// hand is not expired, it is only from before the password.
	stale := mintWith(t, cliSecret, "dispatch", []string{"envelope:read"}, AccessTTL)
	stale = reissueAt(t, stale, now.Add(-2*time.Minute).Unix())
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(stale))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401, body %s", rec.Code, rec.Body)
	}
	if !jsonContains(rec, "credential_expired") {
		t.Fatalf("body %s: want the code credential_expired", rec.Body)
	}
	// A token minted after the change, over the same row stamped "old": works.
	a2, _, _ := userAuth(t, map[string]*signstore.User{
		"dispatch": userRow("envelope:read", "", old)})
	fresh, err := MintUserToken(cliSecret, "dispatch", []string{"envelope:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, a2.RequireAPI(okHandler, "envelope:read"), bearerRequest(fresh))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200, body %s", rec.Code, rec.Body)
	}
}

// 10. Algorithm confusion. The service's EdDSA public key, used as an HMAC
// secret, is the classic break when one verifier switches on alg. Here the row
// secret is the verifier: the public key is not it, and the token is refused.
func TestUserTokenSignedWithPublicKeyIsRefused(t *testing.T) {
	a, k, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read,admin:read", "", "")})
	asSecret := base64.RawURLEncoding.EncodeToString(k.PublicKey())
	token := mintWith(t, asSecret, "dispatch", []string{"admin:read"}, AccessTTL)
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401, body %s", rec.Code, rec.Body)
	}
}

// 11. An EdDSA token is never verified with an HMAC secret and the other way
// round: the gate routes on the header, and each verifier pins its algorithm.
// A compact token whose header says HS256 must not be checked against the
// Keyring, and a Keyring token must not be checked against a row secret.
func TestTokenKindIsRoutedByHeader(t *testing.T) {
	a, k, _ := userAuth(t, map[string]*signstore.User{"dispatch": userRow("envelope:read", "", "")})
	eddsa, err := k.MintAccess(&Claims{Subject: "dispatch", Role: RoleUser,
		Scopes: []string{"envelope:read"}}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	if IsHS256Token(eddsa) {
		t.Fatal("an EdDSA token reads as HS256")
	}
	hs, err := MintUserToken(cliSecret, "dispatch", []string{"envelope:read"}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	if !IsHS256Token(hs) {
		t.Fatal("an HS256 token does not read as HS256")
	}
	// The EdDSA token over the users table: the Keyring path, 200.
	rec := doRequest(t, a.RequireAPI(okHandler, "envelope:read"), bearerRequest(eddsa))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	// The HS256 token, verified against the Keyring: refused on algorithm.
	if _, err := k.VerifyAccess(hs); err == nil {
		t.Fatal("the Keyring accepted an HS256 token")
	}
}

// reissueAt re-signs a token with a new iat, keeping the signature honest: the
// only thing that changes is the claim under test.
func reissueAt(t *testing.T, token string, iat int64) string {
	t.Helper()
	c, err := decodeClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	c.IssuedAt = iat
	c.Expires = iat + int64(AccessTTL/time.Second)
	c.JTI = "cli-jti"
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]string{"alg": AlgHS256, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(hmacSHA(cliSecret, body))
}

// jsonContains reports a code inside a problem document.
func jsonContains(rec *httptest.ResponseRecorder, code string) bool {
	return strings.Contains(rec.Body.String(), code)
}
