package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// This file is the proof for the signoff item "tokens and bearer secrets are
// redacted in logs". The rule the code enforces is that the server may log the
// shape of a credential (the cookie name, the auth scheme, the path minus the
// token segment) and never the value. A log line that carries a link token is
// a log line that carries a signature: reading it is signing.
//
// The tests are written against the real request pipeline, so they check what
// is written to the log, not what a handler claims it writes.

// logCapture is a slog handler that keeps the lines as JSON text, which is
// exactly the shape the server writes to var/log/signsrv.jsonl.
type logCapture struct {
	lines []string
}

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	b := bytes.NewBuffer(nil)
	enc := json.NewEncoder(b)
	m := map[string]any{"msg": r.Message, "level": r.Level.String()}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	if err := enc.Encode(m); err != nil {
		return err
	}
	c.lines = append(c.lines, b.String())
	return nil
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) WithAttrs(attrs []slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(name string) slog.Handler       { return c }

func (c *logCapture) text() string {
	return strings.Join(c.lines, "\n")
}

// captureServer builds a server with a real store whose log is a capture, so a
// test can read every line the request pipeline wrote.
func captureServer(t *testing.T, cfg *Config) (*httptest.Server, *signstore.Store, *logCapture) {
	t.Helper()
	cfg.TSAURL = testTSA(t)
	cfg.LogPath = ""
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

	cap := &logCapture{}
	s := newServer(cfg, slog.New(cap), store)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)
	return ts, store, cap
}

// claimSession claims a link and returns the session cookie the server set. The
// value is kept in the test, never printed: the test asserts it is absent from
// the log.
func claimSession(t *testing.T, ts *httptest.Server, token, email string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sign/"+token+"/claim",
		strings.NewReader(`{"email":"`+email+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("claim = %d, want 200", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == "signsrv_s" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("the claim answer carries no session cookie")
	return ""
}

// sendRequest posts a body and returns the status. The cookie and authorization
// headers are set as given, so a test can hand the server a real credential.
func sendRequest(t *testing.T, ts *httptest.Server, method, path, body, cookie, auth string) int {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

// TestSecretsNeverReachTheLog runs the requests that carry credentials:
// opening a signing page, opening the envelope behind a link, logging in,
// creating an envelope with a bearer token, claiming with a session cookie, and
// declining with a cookie. It then reads every line written and asserts no
// credential value appears in any of them.
func TestSecretsNeverReachTheLog(t *testing.T) {
	cfg := testConfig(t)
	cfg.LogLevel = "debug"
	ts, _, cap := captureServer(t, cfg)

	template := sample1(t)
	access := accessOf(t, ts)

	// A link token in the path, and the shell endpoint that logs the request.
	token := "3f8a21bd9c7e0a5b6431de87fa90c2bb"
	longToken := strings.Repeat("ab12", 12) // 48 chars, the length of a link token
	opened := sendRequest(t, ts, http.MethodGet, "/s/"+longToken, "", "", "")
	if opened != http.StatusOK {
		t.Fatalf("GET /s/<token> = %d, want 200", opened)
	}

	// A bearer token on an authenticated endpoint.
	created, out := createRequest(t, ts, access, template,
		createFields(t, template, `[{"email":"ann@example.test","name":"Ann","order":1}]`))
	if created != http.StatusCreated {
		t.Fatalf("create = %d, want 201: %v", created, out)
	}
	links, _ := out["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1", len(links))
	}
	link, _ := links[0].(map[string]any)
	signerToken, _ := link["token"].(string)
	if len(signerToken) < 32 {
		t.Fatalf("the link token is too short to be a real one: %q", signerToken)
	}

	// A session cookie, obtained by claiming.
	claimed := sendRequest(t, ts, http.MethodPost, "/api/v1/sign/"+signerToken+"/claim",
		`{"email":"ann@example.test"}`, "", "")
	if claimed != http.StatusOK {
		t.Fatalf("claim = %d, want 200", claimed)
	}
	session := claimSession(t, ts, signerToken, "ann@example.test")

	// The endpoints that carry every kind of credential in one request.
	sendRequest(t, ts, http.MethodGet, "/api/v1/sign/"+signerToken+"/envelope", "", "", "Bearer "+access)
	sendRequest(t, ts, http.MethodPost, "/api/v1/sign/"+signerToken+"/decline", `{}`, "signsrv_s="+session, "")
	sendRequest(t, ts, http.MethodPost, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"test-admin-password"}`, "", "")
	sendRequest(t, ts, http.MethodPost, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"wrong"}`, "", "")
	sendRequest(t, ts, http.MethodPost, "/api/v1/auth/client-token",
		`{"key":""}`, "", "")
	sendRequest(t, ts, http.MethodGet, "/api/v1/envelopes", "", "", "Bearer "+access)

	// The access log runs, so a line must exist. If the log wrote nothing, the
	// assertion below would pass by vacuity.
	if len(cap.lines) == 0 {
		t.Fatal("the server wrote no log lines at all")
	}

	text := cap.text()
	secrets := []string{access, session, signerToken, longToken, token,
		"test-admin-password", "test-admin-password"}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Errorf("secret %q appears in the log:\n%s", secret, text)
		}
	}

	// The redaction is present, not just the absence: the path is marked.
	if !strings.Contains(text, "[token]") {
		t.Errorf("the log does not mark the redacted path segment, want [token] in:\n%s", text)
	}
	if !strings.Contains(text, "Bearer [credential]") {
		t.Errorf("the log does not mark the bearer value as [credential] in:\n%s", text)
	}
	if !strings.Contains(text, "signsrv_s") {
		t.Errorf("the log does not keep the cookie name, want signsrv_s in:\n%s", text)
	}
	if strings.Contains(text, "signsrv_s=") {
		t.Errorf("the log keeps a cookie value, want the name only in:\n%s", text)
	}
}

// TestRedactionHelpersAreHonest pins the rules the redaction is built on, so a
// later change that loosens them is visible.
func TestRedactionHelpersAreHonest(t *testing.T) {
	// The redaction is positional: it knows where a token sits in this service's
	// routes, so a short token is redacted and a word is left alone.
	for p, want := range map[string]string{
		"/s/7b3f2a91c4d5e6f7":                                           "/s/[token]",
		"/s/3f8a21bd9c7e0a5b6431de87fa90c2bb":                           "/s/[token]",
		"/api/v1/sign/3f8a21bd9c7e0a5b6431de87fa90c2bb/consent":         "/api/v1/sign/[token]/consent",
		"/api/v1/sign/shorttoken/claim":                                 "/api/v1/sign/[token]/claim",
		"/api/v1/envelopes":                                             "/api/v1/envelopes",
		"/api/v1/envelopes/abc123def456abc123def456abc123def456/cancel": "/api/v1/envelopes/abc123def456abc123def456abc123def456/cancel",
		"/admin/":            "/admin/",
		"/healthz":           "/healthz",
		"/assets/spa/app.js": "/assets/spa/app.js",
		"":                   "/",
	} {
		if got := redactPath(p); got != want {
			t.Errorf("redactPath(%q) = %q, want %q", p, got, want)
		}
	}

	if got := redactCookie("signsrv_s=3f8a21bd9c7e0a5b6431de87fa90c2bb; other=7"); got != "signsrv_s,other" {
		t.Errorf("redactCookie = %q, want the names only", got)
	}
	if got := redactCookie(""); got != "" {
		t.Errorf("redactCookie of no cookie = %q", got)
	}

	if got := redactAuthorization("Bearer 3f8a21bd9c7e0a5b6431de87fa90c2bb"); got != "Bearer [credential]" {
		t.Errorf("redactAuthorization = %q", got)
	}
	if got := redactAuthorization(""); got != "" {
		t.Errorf("redactAuthorization of no header = %q", got)
	}
}

// TestAccessLogShape keeps the useful part of the request log: the line says
// the method, the status, the duration, the address, and the request id. A
// server that redacts everything is a server that cannot debug a request.
func TestAccessLogShape(t *testing.T) {
	cfg := testConfig(t)
	cfg.LogLevel = "debug"
	ts, _, cap := captureServer(t, cfg)

	if status := sendRequest(t, ts, http.MethodGet, "/api/v1/health", "", "", ""); status != http.StatusOK {
		t.Fatalf("health = %d", status)
	}
	if len(cap.lines) == 0 {
		t.Fatal("no request line written")
	}
	line := cap.lines[len(cap.lines)-1]
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("the request line is not JSON: %v\n%s", err, line)
	}
	if m["msg"] != "request" {
		t.Fatalf("msg = %v, want request", m["msg"])
	}
	for _, key := range []string{"method", "path", "status", "dur_ms", "ip", "cookies", "auth", "request"} {
		if _, ok := m[key]; !ok {
			t.Errorf("the request line has no %q: %s", key, line)
		}
	}
	if m["method"] != "GET" || m["path"] != "/api/v1/health" {
		t.Errorf("method/path = %v/%v", m["method"], m["path"])
	}
}
