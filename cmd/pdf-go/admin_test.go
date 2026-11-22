package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/signauth"
)

// The CLI side of step 13: the `admin` verb group. These tests are about the
// three properties the shape depends on — that the CLI signs its own token and
// never asks for one, that each verb calls the route the service registers, and
// that the service's answer is what reaches the operator.
//
// The stub below is the service, reduced to a recorder: it keeps every request
// and answers with a body the test chooses. The real routes are tested in
// cmd/signsrv against the real store; what is checked here is the client.

type adminStub struct {
	mu    sync.Mutex
	hits  []adminHit
	reply func(r *http.Request) (int, string)
}

type adminHit struct {
	method, path, body, bearer string
}

func (s *adminStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.hits = append(s.hits, adminHit{method: r.Method, path: r.URL.Path, body: string(b), bearer: r.Header.Get("Authorization")})
	reply := s.reply
	s.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
		// The token endpoint. Reaching it at all is the failure this suite
		// guards against, so it answers loudly.
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, `{"error":{"code":"should_not_be_called"}}`)
		return
	}
	code, body := http.StatusOK, `{"ok":true}`
	if reply != nil {
		code, body = reply(r)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func (s *adminStub) requests() []adminHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]adminHit(nil), s.hits...)
}

func (s *adminStub) reset() {
	s.mu.Lock()
	s.hits = nil
	s.mu.Unlock()
}

// adminStubServer starts the recorder and returns it.
func adminStubServer(t *testing.T) (*httptest.Server, *adminStub) {
	t.Helper()
	stub := &adminStub{}
	ts := httptest.NewServer(stub)
	t.Cleanup(ts.Close)
	return ts, stub
}

const stubSecret = "dGVzdC1zZWNyZXQtdGhhdC1pcy1sb25nLWVub3VnaC0zMmJ5dGVz"

// cliAdminArgs is the flag set every verb test shares: the stub as the service,
// -insecure because the stub is plain HTTP, and the credential in an
// environment variable, which is the documented way.
func cliAdminArgs(ts *httptest.Server, verb string, extra ...string) []string {
	args := []string{"admin", verb, "--server", ts.URL, "-insecure", "--username", "dispatch"}
	if stubSecret != "" {
		args = append(args, "--jwt-secret", stubSecret)
	}
	return append(args, extra...)
}

// 1. The token the CLI sends is its own, and it is a real one: the algorithm is
// HS256, the claims are the row's shape, the validity is capped, and the secret
// verifies it. Nothing was asked of the service.
func TestAdminVerbSignsItsOwnToken(t *testing.T) {
	ts, stub := adminStubServer(t)
	os.Setenv("JWT_SECRET", stubSecret)
	defer os.Unsetenv("JWT_SECRET")

	code, out := runCLI(t, cliAdminArgs(ts, "dbstatus")...)
	if code != report.OK {
		t.Fatalf("dbstatus exit %d: %s", code, out)
	}
	hits := stub.requests()
	if len(hits) != 1 {
		t.Fatalf("the CLI made %d requests, want exactly one: %v", len(hits), hits)
	}
	if hits[0].method != http.MethodGet || hits[0].path != "/api/v1/admin/dbstatus" {
		t.Fatalf("the CLI called %s %s", hits[0].method, hits[0].path)
	}
	bearer := strings.TrimPrefix(hits[0].bearer, "Bearer ")
	if bearer == "" {
		t.Fatal("the request carried no bearer token")
	}
	claims, err := signauth.VerifyUserToken(stubSecret, bearer)
	if err != nil {
		t.Fatalf("the token the CLI sent does not verify with the shared secret: %v", err)
	}
	if claims.Subject != "dispatch" {
		t.Fatalf("sub = %q", claims.Subject)
	}
	if claims.Issuer != signauth.Issuer || claims.Audience != signauth.AudienceAPI {
		t.Fatalf("iss/aud = %q/%q", claims.Issuer, claims.Audience)
	}
	if claims.Role != signauth.RoleUser {
		t.Fatalf("role = %q, want user", claims.Role)
	}
	if claims.JTI == "" {
		t.Fatal("the token has no jti, so the service cannot revoke it")
	}
	ttl := claims.Expires - claims.IssuedAt
	if ttl <= 0 || ttl > int64(signauth.MaxUserTokenTTL) {
		t.Fatalf("validity = %d seconds, want 0 < t <= %d", ttl, int64(signauth.MaxUserTokenTTL))
	}
	// admin:read is the scope the route needs. The CLI asks for it, the row has
	// it, and the guard is the thing that decides — see the server-side suite.
	if len(claims.Scopes) == 0 {
		t.Fatal("the token carries no scopes")
	}
	// The secret never travels.
	if strings.Contains(hits[0].body, stubSecret) || strings.Contains(hits[0].path, stubSecret) {
		t.Fatal("the shared secret left the machine")
	}
}

// 2. Every verb calls the route the service registers, with the method and body
// that route expects. A verb pointing at a path that does not exist is the
// failure this catches, and it is invisible until someone types it.
func TestEveryAdminVerbCallsItsRoute(t *testing.T) {
	ts, stub := adminStubServer(t)
	defer os.Unsetenv("JWT_SECRET")
	os.Setenv("JWT_SECRET", stubSecret)

	cases := []struct {
		verb   string
		extra  []string
		method string
		path   string
		body   string // substring of the body sent, "" for none
	}{
		{"dbstatus", nil, http.MethodGet, "/api/v1/admin/dbstatus", ""},
		{"schema", nil, http.MethodGet, "/api/v1/admin/schema", ""},
		{"config-check", nil, http.MethodGet, "/api/v1/admin/configcheck", ""},
		{"users", nil, http.MethodGet, "/api/v1/admin/users", ""},
		{"sweep", nil, http.MethodPost, "/api/v1/admin/sweep", ""},
		{"audit-verify", nil, http.MethodPost, "/api/v1/admin/audit/verify", ""},
		{"audit-write", nil, http.MethodPost, "/api/v1/admin/audit/write", ""},
		{"audit-write", []string{"-day", "2026-01-02"}, http.MethodPost, "/api/v1/admin/audit/write", `"day":"2026-01-02"`},
		{"mail-test", []string{"-to", "ops@example.test"}, http.MethodPost, "/api/v1/admin/mail-test", `"to":"ops@example.test"`},
		{"revoke-user", []string{"-id", "7"}, http.MethodDelete, "/api/v1/admin/users/7", ""},
	}
	for _, c := range cases {
		stub.reset()
		args := cliAdminArgs(ts, c.verb, c.extra...)
		code, out := runCLI(t, args...)
		if code != report.OK {
			t.Errorf("admin %s %v: exit %d: %s", c.verb, c.extra, code, out)
			continue
		}
		hits := stub.requests()
		if len(hits) != 1 {
			t.Errorf("admin %s: %d requests, want 1", c.verb, len(hits))
			continue
		}
		h := hits[0]
		if h.method != c.method || h.path != c.path {
			t.Errorf("admin %s called %s %s, want %s %s", c.verb, h.method, h.path, c.method, c.path)
		}
		if c.body != "" && !strings.Contains(h.body, c.body) {
			t.Errorf("admin %s sent body %q, want it to contain %s", c.verb, h.body, c.body)
		}
	}
}

// 3. The service's answer reaches the operator, and its status becomes the exit
// code. A 403 that exits 0 would be a script that reports success on a refusal.
func TestAdminVerbReportsTheAnswerAndTheStatus(t *testing.T) {
	ts, stub := adminStubServer(t)
	os.Setenv("JWT_SECRET", stubSecret)
	defer os.Unsetenv("JWT_SECRET")

	body := `{"ok":false,"problems":["audit_dir is not writable"],"warnings":[]}`
	stub.reply = func(*http.Request) (int, string) { return http.StatusOK, body }
	code, out := runCLI(t, cliAdminArgs(ts, "config-check")...)
	if code != report.OK {
		t.Fatalf("exit %d on a 200", code)
	}
	// The service's own words, not a summary of them.
	for _, want := range []string{"audit_dir is not writable", "warnings"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("the answer printed lacks %q: %s", want, out)
		}
	}

	// A refusal is a non-zero exit, and the reason is printed.
	stub.reply = func(*http.Request) (int, string) {
		return http.StatusForbidden, `{"error":{"code":"insufficient_scope","message":"this endpoint needs a token minted by the service"}}`
	}
	code, out = runCLI(t, cliAdminArgs(ts, "dbstatus")...)
	if code == report.OK {
		t.Fatal("a 403 exited 0")
	}
	if !strings.Contains(string(out), "insufficient_scope") {
		t.Fatalf("the refusal was not printed: %s", out)
	}
}

// 4. A verb that needs a value says so without touching the network. The rate
// bucket of an endpoint is finite; spending it on a typo is rude.
func TestAdminVerbsCheckTheirArgumentsFirst(t *testing.T) {
	ts, stub := adminStubServer(t)
	os.Setenv("JWT_SECRET", stubSecret)
	defer os.Unsetenv("JWT_SECRET")

	for _, args := range [][]string{
		{"admin", "mail-test", "--server", ts.URL, "-insecure", "--username", "dispatch", "--jwt-secret", stubSecret},
		{"admin", "revoke-user", "--server", ts.URL, "-insecure", "--username", "dispatch", "--jwt-secret", stubSecret},
		{"admin", "nonsense", "--server", ts.URL, "-insecure", "--username", "dispatch", "--jwt-secret", stubSecret},
	} {
		code, out := runCLI(t, args...)
		if code == report.OK {
			t.Errorf("%v exited 0", args[1])
		}
		if len(stub.requests()) != 0 {
			t.Errorf("%v made %d requests: %v", args[1], len(stub.requests()), stub.requests())
		}
		if len(out) == 0 {
			t.Errorf("%v printed nothing", args[1])
		}
		stub.reset()
	}
}

// 5. The flag set is the documented one: the secret is read from an environment
// variable by default, so a shell can hand it over without a command line.
func TestAdminVerbReadsTheSecretFromTheEnvironment(t *testing.T) {
	ts, stub := adminStubServer(t)
	os.Setenv("JWT_SECRET", stubSecret)
	os.Setenv("USERNAME", "dispatch")
	os.Setenv("URL", ts.URL)
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("USERNAME")
		os.Unsetenv("URL")
	}()

	code, out := runCLI(t, "admin", "users", "-insecure")
	if code != report.OK {
		t.Fatalf("exit %d: %s", code, out)
	}
	hits := stub.requests()
	if len(hits) != 1 {
		t.Fatalf("%d requests", len(hits))
	}
	tok := strings.TrimPrefix(hits[0].bearer, "Bearer ")
	if _, err := signauth.VerifyUserToken(stubSecret, tok); err != nil {
		t.Fatalf("the environment secret did not sign the token: %v", err)
	}
	// The answer is JSON the caller can read, which is the whole point of -json.
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("the answer is not JSON: %v\n%s", err, out)
	}
}
