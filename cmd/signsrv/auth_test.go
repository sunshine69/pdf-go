package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// authServer builds a server with a real store, so the auth endpoints run
// against the real schema. The admin is seeded with the same hash the CLI
// writes, so the login path is exercised exactly as it works in production.
func authServer(t *testing.T, cfg *Config) (*httptest.Server, *signstore.Store) {
	t.Helper()
	ctx := context.Background()
	db, err := signstore.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signstore.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := signstore.NewStore(db, cfg.StorageDir)
	t.Cleanup(func() { store.Close() })

	hash, err := signauth.HashPassword("test-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddAdmin(ctx, "admin@example.test", hash, "admin"); err != nil {
		t.Fatal(err)
	}

	s := newServer(cfg, logger(cfg), store)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)
	return ts, store
}

// post sends a JSON body and decodes the answer. The status is returned so a
// test can assert on the shape of the answer as well as on the fields.
func post(t *testing.T, ts *httptest.Server, path, body string, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("POST %s: body is not JSON: %s", path, raw)
		}
	}
	return res.StatusCode, out
}

func getJSON(t *testing.T, ts *httptest.Server, path, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("GET %s: body is not JSON: %s", path, raw)
		}
	}
	return res.StatusCode, out
}

func code(t *testing.T, body map[string]any) string {
	t.Helper()
	e, ok := body["error"].(map[string]any)
	if !ok {
		return ""
	}
	c, _ := e["code"].(string)
	return c
}

func TestLoginThenProtectedEndpoint(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := authServer(t, cfg)

	status, body := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"test-admin-password"}`, "")
	if status != http.StatusOK {
		t.Fatalf("login status %d, want 200; body %v", status, body)
	}
	access, _ := body["access"].(string)
	refresh, _ := body["refresh"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("login did not return the pair: %v", body)
	}
	if body["role"] != "admin" {
		t.Fatalf("role %v, want admin", body["role"])
	}
	if body["expires_in"].(float64) <= 0 {
		t.Fatalf("expires_in %v, want a positive number", body["expires_in"])
	}
	scopes, _ := body["scopes"].([]any)
	if len(scopes) == 0 {
		t.Fatalf("scopes must be echoed, got %v", body["scopes"])
	}

	// A protected endpoint answers with the token.
	status, list := getJSON(t, ts, "/api/v1/envelopes", access)
	if status != http.StatusOK {
		t.Fatalf("list status %d, want 200; body %v", status, list)
	}

	// The admin scope is carried by the admin token, so the counters answer.
	status, stats := getJSON(t, ts, "/api/v1/admin/stats", access)
	if status != http.StatusOK {
		t.Fatalf("stats status %d, want 200; body %v", status, stats)
	}
	counts, ok := stats["counts"].(map[string]any)
	if !ok {
		t.Fatalf("stats has no table counts: %v", stats)
	}
	if n, _ := counts["admins"].(float64); n != 1 {
		t.Fatalf("admins count %v, want 1", counts["admins"])
	}

	// No token: 401, in the same problem shape the rest of the API uses.
	status, body = getJSON(t, ts, "/api/v1/envelopes", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", status)
	}
	if code(t, body) != "unauthorized" {
		t.Fatalf("no token: code %q, want unauthorized", code(t, body))
	}

	// A token signed by a different key, in the right shape: the signature
	// check is what refuses it, so the answer is 401, not 403.
	forged := strings.Split(access, ".")[0] + ".eyJzdWIiOiJBIn0.0123456789abcdef"
	status, _ = getJSON(t, ts, "/api/v1/envelopes", forged)
	if status != http.StatusUnauthorized {
		t.Fatalf("forged token: status %d, want 401", status)
	}
}

func TestLoginWrongPasswordAndUnknownAddress(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := authServer(t, cfg)

	// A wrong password and an unknown address get the same answer: the same
	// status, the same code, the same message. A caller cannot use this
	// endpoint to find out which addresses have accounts.
	badStatus, badBody := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"wrong-password-here"}`, "")
	unknownStatus, unknownBody := post(t, ts, "/api/v1/auth/login",
		`{"email":"nobody@example.test","password":"wrong-password-here"}`, "")

	if badStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
		t.Fatalf("status %d and %d, want 401 for both", badStatus, unknownStatus)
	}
	if code(t, badBody) != "unauthorized" || code(t, unknownBody) != "unauthorized" {
		t.Fatalf("codes %q and %q, want unauthorized", code(t, badBody), code(t, unknownBody))
	}
	badMsg, _ := badBody["error"].(map[string]any)
	unknownMsg, _ := unknownBody["error"].(map[string]any)
	if badMsg["message"] != unknownMsg["message"] {
		t.Fatalf("the two answers differ: %v vs %v", badBody, unknownBody)
	}

	// A body that is not JSON is a 400, not a login attempt.
	status, body := post(t, ts, "/api/v1/auth/login", `not json`, "")
	if status != http.StatusBadRequest || code(t, body) != "invalid_body" {
		t.Fatalf("bad body: status %d code %q, want 400 invalid_body", status, code(t, body))
	}
}

func TestRefreshSpendsTheToken(t *testing.T) {
	cfg := testConfig(t)
	ts, store := authServer(t, cfg)

	_, body := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"test-admin-password"}`, "")
	access, _ := body["access"].(string)
	refresh, _ := body["refresh"].(string)

	status, next := post(t, ts, "/api/v1/auth/refresh",
		`{"refresh":"`+refresh+`","access":"`+access+`"}`, "")
	if status != http.StatusOK {
		t.Fatalf("refresh status %d, want 200; body %v", status, next)
	}
	newAccess, _ := next["access"].(string)
	newRefresh, _ := next["refresh"].(string)
	if newAccess == access || newRefresh == refresh {
		t.Fatalf("refresh echoed the pair: %v", next)
	}

	// The token in hand is spent: the second answer is the same as the answer
	// to a forged token.
	status, body = post(t, ts, "/api/v1/auth/refresh",
		`{"refresh":"`+refresh+`"}`, "")
	if status != http.StatusUnauthorized || code(t, body) != "unauthorized" {
		t.Fatalf("replay: status %d code %q, want 401 unauthorized", status, code(t, body))
	}

	// The access token that was refreshed is revoked, so it stops working
	// before its stated expiry.
	status, _ = getJSON(t, ts, "/api/v1/envelopes", access)
	if status != http.StatusUnauthorized {
		t.Fatalf("refreshed-out access token: status %d, want 401", status)
	}
	// The new access token works.
	status, _ = getJSON(t, ts, "/api/v1/envelopes", newAccess)
	if status != http.StatusOK {
		t.Fatalf("new access token: status %d, want 200", status)
	}

	live, _, err := store.CountRefresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("live refresh rows %d, want 1", live)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	cfg := testConfig(t)
	ts, store := authServer(t, cfg)

	_, body := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"test-admin-password"}`, "")
	access, _ := body["access"].(string)
	refresh, _ := body["refresh"].(string)

	status, out := post(t, ts, "/api/v1/auth/logout", `{}`, access)
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("logout: status %d body %v, want 200 ok", status, out)
	}

	// The chain is gone, so the refresh token cannot be used again.
	status, _ = post(t, ts, "/api/v1/auth/refresh", `{"refresh":"`+refresh+`"}`, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: status %d, want 401", status)
	}

	live, _, err := store.CountRefresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("live refresh rows %d after logout, want 0", live)
	}

	// Logout with no token is refused.
	status, _ = post(t, ts, "/api/v1/auth/logout", `{}`, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("logout with no token: status %d, want 401", status)
	}
}

// TestClientTokenFlow exercises the machine caller: the key hashes to a row,
// the token it gets carries the scopes the row names, and a scope the row does
// not name is refused.
func TestClientTokenFlow(t *testing.T) {
	cfg := testConfig(t)
	ts, store := authServer(t, cfg)

	key := randomKey()
	sum := sha256Of([]byte(key))
	if _, err := store.AddClient(context.Background(), "ops", sum,
		signauth.ScopeEnvelopeRead); err != nil {
		t.Fatal(err)
	}

	status, body := post(t, ts, "/api/v1/auth/token", `{"key":"`+key+`"}`, "")
	if status != http.StatusOK {
		t.Fatalf("client token: status %d, want 200; body %v", status, body)
	}
	if body["role"] != "client" {
		t.Fatalf("role %v, want client", body["role"])
	}
	access, _ := body["access"].(string)

	// The scope the client has.
	status, _ = getJSON(t, ts, "/api/v1/envelopes", access)
	if status != http.StatusOK {
		t.Fatalf("client with envelope:read: status %d, want 200", status)
	}

	// The scope it does not have: 403, not 401. The token is valid, the
	// privilege is missing, and the API must say which one it is.
	status, out := getJSON(t, ts, "/api/v1/admin/stats", access)
	if status != http.StatusForbidden {
		t.Fatalf("client on an admin route: status %d, want 403", status)
	}
	if code(t, out) != "insufficient_scope" {
		t.Fatalf("client on an admin route: code %q, want insufficient_scope", code(t, out))
	}

	// A wrong key is refused, and the answer does not say whether the key
	// exists.
	status, _ = post(t, ts, "/api/v1/auth/token", `{"key":"deadbeefdeadbeefdeadbeefdeadbeef"}`, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong key: status %d, want 401", status)
	}
}

// TestPasswordChangeEndsTokens is the CLI behaviour checked through the store:
// after SetAdminPassword, a token minted before the change is refused.
func TestPasswordChangeEndsTokens(t *testing.T) {
	cfg := testConfig(t)
	ts, store := authServer(t, cfg)

	_, body := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"test-admin-password"}`, "")
	access, _ := body["access"].(string)
	if status, _ := getJSON(t, ts, "/api/v1/envelopes", access); status != http.StatusOK {
		t.Fatalf("before the change the token works: status %d", status)
	}

	hash, err := signauth.HashPassword("a-new-long-password")
	if err != nil {
		t.Fatal(err)
	}
	// pw_changed_at has one-second resolution. The change has to land in a
	// later second than the token's iat, or the check cannot see the ordering.
	time.Sleep(1100 * time.Millisecond)
	if err := store.SetAdminPassword(context.Background(), 1, hash); err != nil {
		t.Fatal(err)
	}

	// The token in hand is refused: it was minted under the old password.
	status, out := getJSON(t, ts, "/api/v1/envelopes", access)
	if status != http.StatusUnauthorized {
		t.Fatalf("after the password change: status %d, want 401; body %v", status, out)
	}

	// The new password works, and the token it mints is accepted.
	status, body = post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"a-new-long-password"}`, "")
	if status != http.StatusOK {
		t.Fatalf("login with the new password: status %d, want 200", status)
	}
	fresh, _ := body["access"].(string)
	if status, _ := getJSON(t, ts, "/api/v1/envelopes", fresh); status != http.StatusOK {
		t.Fatalf("new token: status %d, want 200", status)
	}
}

// TestLoginRateLimit: the login endpoint is the one that costs CPU, so it has
// its own bucket. The limit is 5 per minute per address, so the sixth request
// from the same address answers 429.
func TestLoginRateLimit(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := authServer(t, cfg)

	var last int
	for i := 1; i <= 6; i++ {
		status, _ := post(t, ts, "/api/v1/auth/login",
			`{"email":"admin@example.test","password":"wrong-password-here"}`, "")
		last = status
		if status == http.StatusTooManyRequests {
			break
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("six login attempts ended with status %d, want 429", last)
	}
}

// TestStoreMissingAnswers503: a server started without a database does not
// pretend to refuse credentials. It says it has no database.
func TestStoreMissingAnswers503(t *testing.T) {
	cfg := testConfig(t)
	ts := newTestServer(t, cfg)

	status, body := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"test-admin-password"}`, "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("no store: status %d, want 503", status)
	}
	if code(t, body) != "no_store" {
		t.Fatalf("no store: code %q, want no_store", code(t, body))
	}
}

// TestRandomKeyShape keeps the CLI's key generation honest: the key is a
// prefix, so it is recognisable in a log, plus 256 bits of entropy in hex,
// from the system random source.
func TestRandomKeyShape(t *testing.T) {
	for i := 0; i < 20; i++ {
		k := randomKey()
		rest, ok := strings.CutPrefix(k, "key_")
		if !ok {
			t.Fatalf("key %q has no key_ prefix", k)
		}
		if len(rest) != 64 {
			t.Fatalf("key %q carries %d hex characters, want 64 (256 bits)", k, len(rest))
		}
		raw, err := hex.DecodeString(rest)
		if err != nil {
			t.Fatalf("key %q is not hex: %v", k, err)
		}
		if len(raw) != 32 {
			t.Fatalf("key decodes to %d bytes, want 32", len(raw))
		}
	}
	// The key comes from the system random source, so two calls differ.
	if randomKey() == randomKey() {
		t.Fatal("two keys are equal")
	}
}
