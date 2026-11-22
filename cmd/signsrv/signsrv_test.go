package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	return &Config{
		Listen:     "127.0.0.1:0",
		PublicURL:  "http://127.0.0.1:8080",
		Dev:        true,
		DBPath:     filepath.Join(dir, "signsrv.db"),
		StorageDir: filepath.Join(dir, "storage"),
		Keystore:   filepath.Join(dir, "keystore"),
		Outbox:     filepath.Join(dir, "outbox"),
		TSAURL:     "https://tsa.example/tsr",
		MailFrom:   "signsrv@example.test",
		SMTPHost:   "127.0.0.1",
		MaxPDFMB:   25,
		LogLevel:   "debug",
		jwtFile:    filepath.Join(dir, "jwt.ed25519.key"),
		env:        map[string]string{"keystore_pass": "test-passphrase", "admin_password": "test-admin-password"},
	}
}

// newTestServer builds a server with no store: the static and health routes
// work without a database, which is what the shell tests exercise.
func newTestServer(t *testing.T, cfg *Config) *httptest.Server {
	t.Helper()
	s := newServer(cfg, logger(cfg), nil)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)
	return ts
}

func status(t *testing.T, ts *httptest.Server, path string) (int, http.Header) {
	t.Helper()
	res, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	return res.StatusCode, res.Header
}

func TestStaticRoutes(t *testing.T) {
	ts := newTestServer(t, testConfig(t))
	want := map[string]int{
		"/s/7b3f2a91c4d5e6f7":       http.StatusOK, // SPA shell, token not validated here
		"/s/anything":               http.StatusOK,
		"/admin/":                   http.StatusOK,
		"/assets/spa/index.html":    http.StatusOK,
		"/assets/spa/app.js":        http.StatusOK,
		"/assets/spa/app.css":       http.StatusOK,
		"/assets/admin/index.html":  http.StatusOK,
		"/assets/admin/app.js":      http.StatusOK,
		"/assets/admin/app.css":     http.StatusOK,
		"/healthz":                  http.StatusOK,
		"/api/v1/health":            http.StatusOK,
		"/nope":                     http.StatusNotFound,
		"/assets/spa/../app.js":     http.StatusNotFound,
		"/assets/spa/%2e%2e/app.js": http.StatusNotFound,
	}
	for path, code := range want {
		got, _ := status(t, ts, path)
		if got != code {
			t.Errorf("GET %s = %d, want %d", path, got, code)
		}
	}
}

func TestCSPHeaders(t *testing.T) {
	ts := newTestServer(t, testConfig(t))

	_, h := status(t, ts, "/s/7b3f2a91c4d5e6f7")
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self'") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("signer CSP = %q", csp)
	}
	if strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("signer CSP must allow self frames: %q", csp)
	}

	_, h = status(t, ts, "/assets/spa/app.js")
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-src 'self'") {
		t.Error("assets of the signer app must carry the signer CSP")
	}

	_, h = status(t, ts, "/admin/")
	csp = h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("admin CSP = %q", csp)
	}
	if strings.Contains(csp, "frame-src") {
		t.Errorf("admin CSP must not allow frames: %q", csp)
	}
	if h.Get("X-Frame-Options") == "" {
		t.Error("admin shell must set X-Frame-Options")
	}

	_, h = status(t, ts, "/healthz")
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Error("baseline security headers missing")
	}
}

func TestSignerShellHidesTheToken(t *testing.T) {
	cfg := testConfig(t)
	logPath := filepath.Join(t.TempDir(), "signsrv.jsonl")
	cfg.LogPath = logPath

	ts := newTestServer(t, cfg)
	const token = "deadbeefcafe1234"
	if code, _ := status(t, ts, "/s/"+token); code != http.StatusOK {
		t.Fatalf("GET /s/<token> = %d", code)
	}

	line, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(line), token) {
		t.Errorf("token leaked into the log:\n%s", line)
	}
	for _, secret := range []string{"test-passphrase", "test-admin-password"} {
		if strings.Contains(string(line), secret) {
			t.Errorf("secret %q leaked into the log", secret)
		}
	}
	for _, rec := range strings.Split(strings.TrimSpace(string(line)), "\n") {
		if !strings.HasPrefix(rec, "{") {
			t.Errorf("log record is not JSON: %q", rec)
		}
	}
}

func TestConfigValidates(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "cfg-"+t.Name()+".env")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := "listen=127.0.0.1:8080\npublic_url=https://sign.example.org\n" +
		"keystore_pass=p\nadmin_password=p\nsmtp_host=smtp.example.org\nmail_from=a@b.c\n"

	t.Run("good config is usable", func(t *testing.T) {
		cfg, err := LoadConfig(write(base))
		if err != nil {
			t.Fatalf("want usable, got: %v", err)
		}
		if len(cfg.Problems()) != 0 {
			t.Fatalf("want no problems, got %v", cfg.Problems())
		}
	})

	t.Run("broken config lists every problem", func(t *testing.T) {
		cfg, err := LoadConfig(write("listen=0.0.0.0:8080\ndev=false\n"))
		if err == nil {
			t.Fatal("want an error")
		}
		problems := strings.Join(cfg.Problems(), "\n")
		for _, want := range []string{"public_url", "smtp_host", "mail_from", "keystore_pass", "admin_password"} {
			if !strings.Contains(problems, want) {
				t.Errorf("problem for %q missing:\n%s", want, problems)
			}
		}
	})

	t.Run("malformed line is refused", func(t *testing.T) {
		if _, err := LoadConfig(write("listen 127.0.0.1:8080\n")); err == nil {
			t.Fatal("want an error for a line without =")
		}
	})

	t.Run("unknown key is refused", func(t *testing.T) {
		_, err := LoadConfig(write(base + "publicl_url=https://x.example.org\n"))
		if err == nil || !strings.Contains(err.Error(), "publicl_url") {
			t.Fatalf("want the typo reported, got %v", err)
		}
	})

	// Dev mode does not restrict the listener either. It matters more in dev
	// than elsewhere: serve generates the keystore passphrase and the admin
	// password at start and prints them to the log, so a listener that reaches
	// the network plus a readable log is enough to sign. The listener itself is
	// still the operator's call, so this is a warning rather than a refusal.
	t.Run("dev mode on a public listener warns", func(t *testing.T) {
		cfg, err := LoadConfig(write(base + "dev=true\nlisten=0.0.0.0:8080\n"))
		if err != nil {
			t.Fatalf("a public listener is allowed: %v", err)
		}
		if !strings.Contains(strings.Join(cfg.Warnings(), "\n"), "binds outside loopback") {
			t.Fatalf("want a plain-HTTP warning, got %v", cfg.Warnings())
		}
	})

	t.Run("http public_url refused outside dev", func(t *testing.T) {
		if _, err := LoadConfig(write(base + "public_url=http://sign.example.org\n")); err == nil {
			t.Fatal("signing links carry a token: https is required")
		}
	})

	t.Run("environment wins over the file", func(t *testing.T) {
		t.Setenv("LISTEN", "127.0.0.1:9999")
		t.Setenv("ADMIN_PASSWORD", "from-env")
		cfg, err := LoadConfig(write(base + "listen=127.0.0.1:1234\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:9999" {
			t.Errorf("Listen = %q", cfg.Listen)
		}
		if cfg.AdminPassword() != "from-env" {
			t.Error("secret must come from the environment")
		}
	})
}

func TestRedactedNeverLeaksSecrets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.env")
	if err := os.WriteFile(p, []byte(
		"listen=127.0.0.1:8080\npublic_url=https://sign.example.org\n"+
			"keystore_pass=super-secret-passphrase\nadmin_password=super-secret-admin\n"+
			"smtp_host=smtp.example.org\nsmtp_pass=super-secret-smtp\nmail_from=a@b.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	out := cfg.Redacted()
	for _, secret := range []string{"super-secret-passphrase", "super-secret-admin", "super-secret-smtp"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q present in Redacted():\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "keystore_pass=sha256:") {
		t.Error("secrets must appear as digests")
	}
}

func TestLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080":  true,
		"localhost:8080":  true,
		"[::1]:8080":      true,
		"127.0.0.53:8080": true,
		// :8080 is every interface, not the local one. The helper this
		// replaced called it loopback, so listen=:8080 was accepted while
		// binding the whole host.
		":8080":          false,
		"0.0.0.0:8080":   false,
		"192.168.1.5:80": false,
		"[::]:8080":      false,
	} {
		if got := bindsLoopbackOnly(addr); got != want {
			t.Errorf("bindsLoopbackOnly(%q) = %v, want %v", addr, got, want)
		}
	}
}
