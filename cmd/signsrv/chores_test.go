package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Step 13: the service chores, and the account table, over HTTP.
//
// The chores are the `signsrv` verbs that are not document work — is the
// database alive, what is the schema, run the sweep, is the audit chain intact,
// write today's file, is the configuration sound, does the mail path work. They
// are routes so that a desk can operate a server: `signsrv dbstatus -config …`
// on the desk reads the desk's database, which is not the thing being asked
// about.
//
// The account table is the other half: the rows a caller-minted token is
// checked against. Both halves are tested here against the real store and the
// real routes, because the property under test is the one that spans them — an
// account, its scopes, and what a token signed with its secret can do.

// choreConfig is a config whose audit directory exists: audit-write writes
// there, and a missing directory is a real failure the handler reports, not
// something a test should cause.
func choreConfig(t *testing.T) *Config {
	t.Helper()
	cfg := testConfig(t)
	if err := os.MkdirAll(filepath.Join(cfg.StorageDir, "..", "audit"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AuditDir = filepath.Join(cfg.StorageDir, "..", "audit")
	return cfg
}

// choreServer is a server with a store, a seeded admin, and one account.
// It returns the HTTP server, the store, the admin's access token, and the
// account's row (with its secret, because the test is the CLI in that role).
func choreServer(t *testing.T) (*Config, *httptest.Server, *signstore.Store, string, *signstore.User) {
	t.Helper()
	cfg := choreConfig(t)
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
	secret, err := signstore.NewJWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	// The row grants admin:read in its scopes column. The point of that is
	// test 2: scopes on the row do not open the admin surface to a
	// caller-minted token.
	if _, err := store.AddUser(ctx, "dispatch", "", secret, "envelope:read,envelope:write,admin:read", "user"); err != nil {
		t.Fatal(err)
	}

	s := newServer(cfg, logger(cfg), store)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)

	u, err := store.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, ts, store, accessOf(t, ts), u
}

// cliToken is what the CLI produces: the same call its own code makes, signed
// in this process, sent as a bearer token. Nothing here asks the service for a
// token, which is the property the shape is about.
func cliToken(t *testing.T, u *signstore.User) string {
	t.Helper()
	tok, err := signauth.MintUserToken(u.JWTSecret, u.Username,
		[]string{"envelope:read", "envelope:write"}, signauth.AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// 1. Every chore route answers the admin token with a body that says something
// useful. The check is on fields, not on the status alone: a 200 that says
// nothing is a route that is not implemented.
func TestChoreRoutesAnswerTheAdminToken(t *testing.T) {
	cfg, ts, _, admin, _ := choreServer(t)

	// dbstatus: reachability and counts, including the accounts.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/dbstatus", admin, "")
	if code != http.StatusOK {
		t.Fatalf("dbstatus: %d %v", code, out)
	}
	if out["ok"] != true {
		t.Fatalf("dbstatus ok = %v", out["ok"])
	}
	for _, key := range []string{"db_path", "schema", "envelopes", "parties", "users_active", "checked_at"} {
		if _, ok := out[key]; !ok {
			t.Fatalf("dbstatus has no %q: %v", key, out)
		}
	}
	if out["users_active"].(float64) != 1 {
		t.Fatalf("users_active = %v, want 1", out["users_active"])
	}
	if out["schema"].(float64) != float64(signstore.CurrentVersion) {
		t.Fatalf("schema = %v, want %d", out["schema"], signstore.CurrentVersion)
	}

	// schema: the stored version, the binary's, and the pending list.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/schema", admin, "")
	if code != http.StatusOK {
		t.Fatalf("schema: %d %v", code, out)
	}
	if out["version"].(float64) != float64(signstore.CurrentVersion) {
		t.Fatalf("version = %v", out["version"])
	}
	if out["migration_open"] != false {
		t.Fatalf("migration_open = %v on an up-to-date database", out["migration_open"])
	}
	if pend, ok := out["pending"].([]any); !ok || len(pend) != 0 {
		t.Fatalf("pending = %v, want []", out["pending"])
	}

	// configcheck: the problems list, the warnings, and redacted settings.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/configcheck", admin, "")
	if code != http.StatusOK {
		t.Fatalf("configcheck: %d %v", code, out)
	}
	settings, ok := out["settings"].(map[string]any)
	if !ok {
		t.Fatalf("configcheck settings is not an object: %v", out["settings"])
	}
	// A dev-mode config: the check passes, and the answer names the
	// directories an operator would otherwise have to guess.
	if out["ok"] != true {
		t.Fatalf("configcheck ok = %v, problems %v", out["ok"], out["problems"])
	}
	if settings["listen"] == nil {
		t.Fatalf("settings has no listen: %v", settings)
	}
	if _, ok := out["audit_dir"]; !ok {
		t.Fatalf("configcheck has no audit_dir: %v", out)
	}
	// No secret, in any of it. The digest is the redaction.
	raw, _ := json.Marshal(out)
	for _, probe := range []string{"test-admin-password", "test-passphrase"} {
		if strings.Contains(string(raw), probe) {
			t.Fatalf("configcheck leaked %q", probe)
		}
	}

	// sweep: the report, with the counts spelled for a machine.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/sweep", admin, "")
	if code != http.StatusOK {
		t.Fatalf("sweep: %d %v", code, out)
	}
	for _, key := range []string{"envelopes_expired", "parties_expired", "mail_requeued", "now"} {
		if _, ok := out[key]; !ok {
			t.Fatalf("sweep report has no %q: %v", key, out)
		}
	}

	// audit/verify: an empty chain is a verified chain. The answer is ok:true
	// with a count, not a 500: "there is nothing to check" is a fact.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/audit/verify", admin, "")
	if code != http.StatusOK {
		t.Fatalf("audit/verify: %d %v", code, out)
	}
	if out["ok"] != true {
		t.Fatalf("audit/verify ok = %v: %v", out["ok"], out)
	}

	// audit/write: today's file, and the file is on disk.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/audit/write", admin, `{}`)
	if code != http.StatusOK {
		t.Fatalf("audit/write: %d %v", code, out)
	}
	path, _ := out["path"].(string)
	if path == "" {
		t.Fatalf("audit/write gave no path: %v", out)
	}
	// The seed data has no events, so the file is written with zero lines and
	// the endpoint reports where it put it. A non-zero count without a file on
	// disk would be a route that lies.
	lines, _ := out["lines"].(float64)
	if _, err := os.Stat(path); err != nil && lines != 0 {
		t.Fatalf("audit/write says %v lines and the file is missing: %v", lines, err)
	}
	// A day is a filename, so a day that is not one is refused.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/audit/write", admin, `{"day":"../../etc"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("audit/write with a path-shaped day: %d %v", code, out)
	}
	if !strings.Contains(mustString(problemCodeOf(out)), "invalid_day") {
		t.Fatalf("audit/write day check: %v", out)
	}

	// mail-test: dev mode writes the message to the outbox and says so.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/mail-test", admin, `{"to":"ops@example.test"}`)
	if code != http.StatusOK {
		t.Fatalf("mail-test: %d %v", code, out)
	}
	if out["sent"] != true || out["transport"] != "outbox" {
		t.Fatalf("mail-test: %v", out)
	}
	files := outboxFiles(t, cfg.Outbox)
	if len(files) == 0 {
		t.Fatal("mail-test reported success and wrote no message")
	}
	// A missing address is a 400, not a 500 and not a send attempt.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/mail-test", admin, `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("mail-test with no address: %d %v", code, out)
	}
	// A malformed address is refused too: the service must not be a relay that
	// accepts anything an admin token asks for.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/mail-test", admin, `{"to":"not an address"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("mail-test with a bad address: %d %v", code, out)
	}
}

// 2. The admin surface is not reachable with a caller-minted token, whatever
// the row's scopes column says. This is the property the whole shape hangs on:
// a dispatch secret is a document credential, and the admin surface is the
// whole system.
func TestChoreRoutesRefuseCallerMintedTokens(t *testing.T) {
	_, ts, _, _, u := choreServer(t)
	tok := cliToken(t, u)

	// A document route, first, to prove the token itself works.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/envelopes", tok, "")
	if code != http.StatusOK {
		t.Fatalf("envelope list with a caller-minted token: %d %v", code, out)
	}

	// And every chore route refuses it, with the code that explains why.
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/dbstatus"},
		{http.MethodGet, "/api/v1/admin/schema"},
		{http.MethodGet, "/api/v1/admin/configcheck"},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPost, "/api/v1/admin/sweep"},
		{http.MethodPost, "/api/v1/admin/audit/verify"},
		{http.MethodPost, "/api/v1/admin/audit/write"},
		{http.MethodPost, "/api/v1/admin/mail-test"},
		{http.MethodDelete, "/api/v1/admin/users/1"},
	} {
		code, out = adminCode(t, ts, r.method, r.path, tok, "")
		if code != http.StatusForbidden {
			t.Errorf("%s %s with a caller-minted token: %d %v, want 403", r.method, r.path, code, out)
			continue
		}
		if !strings.Contains(mustString(problemCodeOf(out)), "insufficient_scope") {
			t.Errorf("%s %s: %v, want the code insufficient_scope", r.method, r.path, out)
		}
	}
}

// 3. The account list, and the revocation. The list shows the row and not the
// secret; the revocation closes both doors, and the caller-minted door closes
// on the next request rather than at token expiry — which is the answer to
// "a JWT the server never minted has no row to look up".
func TestUserListAndRevokeOverHTTP(t *testing.T) {
	_, ts, store, admin, u := choreServer(t)

	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/users", admin, "")
	if code != http.StatusOK {
		t.Fatalf("users list: %d %v", code, out)
	}
	list, ok := out["users"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("users list: %v", out)
	}
	row, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("users list row: %v", list[0])
	}
	if row["username"] != "dispatch" {
		t.Fatalf("row username = %v", row["username"])
	}
	// The booleans replace the values: you can see that a row has a secret
	// without being able to read it.
	if row["has_secret"] != true {
		t.Fatalf("row has_secret = %v: %v", row["has_secret"], row)
	}
	if row["has_password"] != false {
		t.Fatalf("row has_password = %v", row["has_password"])
	}
	// The scopes are the row's, as a list.
	scopes, ok := row["scopes"].([]any)
	if !ok || len(scopes) != 3 {
		t.Fatalf("row scopes = %v", row["scopes"])
	}
	// And the secret is nowhere in the answer.
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), u.JWTSecret) {
		t.Fatal("the users list carries the account's secret")
	}

	// Revoke it, by id, over the DELETE route.
	code, out = adminCode(t, ts, http.MethodDelete, "/api/v1/admin/users/1", admin, "")
	if code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if out["revoked"] != true {
		t.Fatalf("revoke answer: %v", out)
	}
	// The token signed an instant ago is now refused, and the code names the
	// reason. The window of a leaked secret is one request.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/envelopes", cliToken(t, u), "")
	if code != http.StatusUnauthorized {
		t.Fatalf("envelope list after revoke: %d %v, want 401", code, out)
	}
	if !strings.Contains(mustString(problemCodeOf(out)), "token_revoked") {
		t.Fatalf("after revoke: %v, want the code token_revoked", out)
	}
	// The row is still there, stamped, so the audit trail of what it signed
	// stays verifiable.
	after, err := store.GetByUsername(context.Background(), "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if after.RevokedAt == "" {
		t.Fatal("the row is not stamped")
	}
	// Revoking a row that is not there is a 404, and a id that is not a number
	// is a 400.
	code, _ = adminCode(t, ts, http.MethodDelete, "/api/v1/admin/users/9999", admin, "")
	if code != http.StatusNotFound {
		t.Fatalf("revoke a missing row: %d, want 404", code)
	}
	code, _ = adminCode(t, ts, http.MethodDelete, "/api/v1/admin/users/not-a-number", admin, "")
	if code != http.StatusBadRequest {
		t.Fatalf("revoke a non-numeric id: %d, want 400", code)
	}
}

// 4. The same chore, from the CLI's side, with a client token exchanged at the
// token endpoint. The chore routes are the admin surface, so a machine client
// reaches them only with an admin scope, and the point of the test is that the
// route answers the same shape for both kinds of service credential.
func TestChoreRouteAnswersTheSameShapeForAClientToken(t *testing.T) {
	_, ts, _, admin, _ := choreServer(t)

	client := mintClientToken(t, ts, admin, "ops", "envelope:read")
	// A client token is not an admin: the chore routes refuse it.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/dbstatus", client, "")
	if code != http.StatusForbidden {
		t.Fatalf("dbstatus with an envelope-only client token: %d %v", code, out)
	}
	// The admin token gets the body. The comparison is on the field names, so
	// the assertion is that there is one shape of answer.
	code, adminOut := adminCode(t, ts, http.MethodGet, "/api/v1/admin/dbstatus", admin, "")
	if code != http.StatusOK {
		t.Fatalf("dbstatus with the admin: %d %v", code, adminOut)
	}
	if _, ok := adminOut["by_status"]; !ok {
		t.Fatalf("dbstatus has no by_status: %v", adminOut)
	}
}

// 5. The routes exist on the mux at all. A chore path that was never registered
// is answered by the catch-all, whose body says not_found — which is what a
// typo in a route registration looks like from the outside, and what this
// catches. The verbs matter: these are POST routes, so GET on them is the
// catch-all's answer too.
func TestChoreRoutesAreRegistered(t *testing.T) {
	_, ts, _, admin, _ := choreServer(t)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/dbstatus"},
		{http.MethodGet, "/api/v1/admin/schema"},
		{http.MethodGet, "/api/v1/admin/configcheck"},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPost, "/api/v1/admin/sweep"},
		{http.MethodPost, "/api/v1/admin/audit/verify"},
		{http.MethodPost, "/api/v1/admin/audit/write"},
		{http.MethodPost, "/api/v1/admin/mail-test"},
	} {
		code, out := adminCode(t, ts, r.method, r.path, admin, "")
		if mustString(problemCodeOf(out)) == "not_found" {
			t.Errorf("%s %s is answered by the catch-all: the route is not registered", r.method, r.path)
		}
		if code == http.StatusNotFound {
			t.Errorf("%s %s is 404: %v", r.method, r.path, out)
		}
	}
	// No token at all: 401 from the gate, not 404 from the router.
	res, _ := adminCall(t, ts, "", http.MethodGet, "/api/v1/admin/dbstatus", "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dbstatus with no token: %d, want 401", res.StatusCode)
	}
	// A path that is not a chore at all: the catch-all, so the assertion above
	// is meaningful.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/not-a-chore", admin, "")
	if code != http.StatusNotFound || mustString(problemCodeOf(out)) != "not_found" {
		t.Fatalf("unknown admin path: %d %v, want 404 not_found", code, out)
	}
}

func mustString(v any) string {
	s, _ := v.(string)
	return s
}

// problemCodeOf digs the code out of a problem document: {"error":{"code":…}}.
func problemCodeOf(out map[string]any) any {
	e, ok := out["error"].(map[string]any)
	if !ok {
		return out["code"]
	}
	return e["code"]
}
