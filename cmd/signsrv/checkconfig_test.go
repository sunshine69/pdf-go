package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkConfigServer writes a config into a temp dir, with a keystore
// directory and a JWT key file, and returns the path. The JWT key mode is
// set here so each test can choose it.
func checkConfigServer(t *testing.T, body string, jwtMode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	keystore := filepath.Join(dir, "keystore")
	if err := os.MkdirAll(keystore, 0o750); err != nil {
		t.Fatal(err)
	}
	jwt := filepath.Join(dir, "jwt.ed25519.key")
	if err := os.WriteFile(jwt, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(jwt, jwtMode); err != nil {
		t.Fatal(err)
	}
	cfg := strings.ReplaceAll(body, "$DIR", dir)
	p := filepath.Join(dir, "c.env")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// goodBase is a usable config on a loopback listener.
const goodBase = "listen=127.0.0.1:8080\n" +
	"public_url=https://sign.example.org\n" +
	"keystore_dir=$DIR/keystore\n" +
	"jwt_secret_file=$DIR/jwt.ed25519.key\n" +
	"keystore_pass=secret-keystore\n" +
	"admin_password=secret-admin\n" +
	"smtp_host=smtp.example.org\n" +
	"mail_from=a@b.c\n"

func TestCheckConfigAcceptsLoopbackConfig(t *testing.T) {
	p := checkConfigServer(t, goodBase, 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("want usable, got: %v\nproblems: %v", err, cfg.Problems())
	}
	if len(cfg.Problems()) != 0 {
		t.Fatalf("want no problems, got %v", cfg.Problems())
	}
	if got := checkConfig(p); got != 0 {
		t.Fatalf("checkconfig exit = %d, want 0", got)
	}
}

// Where the listener sits is the operator's infrastructure decision, so a
// public bind is not a problem: the service runs it. It is a warning, because
// the service speaks plain HTTP and the tradeoff deserves saying out loud.
// The check is that the run is allowed and the warning is present — a silent
// yes would be worse than a no, and a hard stop would be the application
// claiming a decision it does not own.
func TestCheckConfigWarnsOnNonLoopbackListener(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", "[::]:8080", "192.168.1.5:8080", ":8080"} {
		p := checkConfigServer(t, strings.Replace(goodBase, "listen=127.0.0.1:8080", "listen="+addr, 1), 0o600)
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("%s: want the config to load, got %v\n%s", addr, err, strings.Join(cfg.Problems(), "\n"))
		}
		if got := checkConfig(p); got != 0 {
			t.Fatalf("%s: checkconfig exit = %d, want 0 (a public bind is the operator's call)", addr, got)
		}
		warnings := strings.Join(cfg.Warnings(), "\n")
		if !strings.Contains(warnings, "plain HTTP") {
			t.Fatalf("%s: no warning about plain HTTP:\n%s", addr, warnings)
		}
		if strings.Contains(strings.Join(cfg.Problems(), "\n"), "loopback") {
			t.Fatalf("%s: still reported as a problem:\n%s", addr, cfg.Problems())
		}
	}
}

// A loopback bind carries no warning: the common shape must stay quiet, or the
// warning stops being read.
func TestCheckConfigQuietOnLoopbackListener(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.53:8080"} {
		p := checkConfigServer(t, strings.Replace(goodBase, "listen=127.0.0.1:8080", "listen="+addr, 1), 0o600)
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if got := checkConfig(p); got != 0 {
			t.Fatalf("%s: checkconfig exit = %d, want 0", addr, got)
		}
		if len(cfg.Warnings()) != 0 {
			t.Fatalf("%s: want no warnings, got %v", addr, cfg.Warnings())
		}
	}
}

// The JWT key mints admin tokens. A key that any user on the machine can read
// is a key that any user on the machine can mint with.
func TestCheckConfigRefusesLooseJWTKeyMode(t *testing.T) {
	p := checkConfigServer(t, goodBase, 0o644)
	cfg, err := LoadConfig(p)
	if err == nil {
		t.Fatal("want an error for a JWT key readable by others")
	}
	problems := strings.Join(cfg.Problems(), "\n")
	if !strings.Contains(problems, "0600") {
		t.Fatalf("the problem does not name the mode:\n%s", problems)
	}
}

// The keystore holds the CA private key. A missing directory is caught here,
// not at the first signature.
func TestCheckConfigRefusesMissingKeystore(t *testing.T) {
	body := strings.ReplaceAll(goodBase, "keystore_dir=$DIR/keystore",
		"keystore_dir=$DIR/no-keystore")
	p := checkConfigServer(t, body, 0o600)
	cfg, err := LoadConfig(p)
	if err == nil {
		t.Fatal("want an error for a missing keystore")
	}
	problems := strings.Join(cfg.Problems(), "\n")
	if !strings.Contains(problems, "keystore_dir") {
		t.Fatalf("the problem does not name keystore_dir:\n%s", problems)
	}
}

// A plain HTTP timestamp authority lets a man in the middle choose the time
// written into a signature. This is reported as a warning: the service runs,
// and the operator is told.
func TestCheckConfigWarnsOnPlainTSA(t *testing.T) {
	body := strings.ReplaceAll(goodBase,
		"keystore_pass=secret-keystore",
		"tsa_url=http://freetsa.org/tsr\nkeystore_pass=secret-keystore")
	p := checkConfigServer(t, body, 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("a warning must not stop the config: %v", err)
	}
	warnings := strings.Join(cfg.Warnings(), "\n")
	if !strings.Contains(warnings, "tsa_url") {
		t.Fatalf("no warning about the timestamp authority:\n%s", warnings)
	}
	if got := checkConfig(p); got != 0 {
		t.Fatalf("checkconfig exit = %d, want 0: a warning does not stop the service", got)
	}
}

// The report is the line an operator pastes into an issue. A secret must not
// be in it, and a secret must not be reachable by walking the struct.
func TestCheckConfigReportHasNoSecrets(t *testing.T) {
	p := checkConfigServer(t, goodBase, 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	report := cfg.Redacted()
	for _, secret := range []string{"secret-keystore", "secret-admin"} {
		if strings.Contains(report, secret) {
			t.Fatalf("the report leaks a secret:\n%s", report)
		}
	}
	if !strings.Contains(report, "keystore_pass=sha256:") {
		t.Fatalf("the keystore passphrase is not shown as a digest:\n%s", report)
	}
	if !strings.Contains(report, "admin_password=sha256:") {
		t.Fatalf("the admin password is not shown as a digest:\n%s", report)
	}
}
