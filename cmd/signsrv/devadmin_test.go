package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// devEphemeralConfig loads a dev config with no admin_password, so the
// ephemeral one LoadConfig synthesises is the one under test.
func devEphemeralConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "signsrv.env")
	body := "dev=true\n" +
		"listen=127.0.0.1:8080\n" +
		"public_url=http://127.0.0.1:8080\n" +
		"db=" + filepath.Join(dir, "signsrv.db") + "\n" +
		"storage_dir=" + filepath.Join(dir, "storage") + "\n" +
		"keystore_dir=" + filepath.Join(dir, "keystore") + "\n" +
		"outbox_dir=" + filepath.Join(dir, "outbox") + "\n" +
		"jwt_secret_file=" + filepath.Join(dir, "jwt.ed25519.key") + "\n" +
		"keystore_pass=secret-keystore\n" +
		"smtp_host=smtp.example.org\n" +
		"mail_from=a@b.c\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v\nproblems: %v", err, cfg.Problems())
	}
	return cfg
}

// Small wrappers so the assertions read as intent rather than as a call into
// another package.
func signauthValidate(pw, hash string) error {
	ok, err := signauth.VerifyPassword(pw, hash)
	if err != nil {
		return err
	}
	if !ok {
		return errPasswordMismatch
	}
	return nil
}

func signauthHash(pw string) (string, error) { return signauth.HashPassword(pw) }

var errPasswordMismatch = errors.New("password does not match the stored hash")

// devStore builds the server with a migrated store, which is what
// ensureDevAdmin needs. It does not start an HTTP server: the behaviour under
// test is what lands in the admins table.
func devStore(t *testing.T, cfg *Config) (*server, *signstore.Store) {
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newServer(cfg, log, store), store
}

// An empty database in dev mode must end up with an account the logged
// password actually unlocks. Before this existed the service printed a password
// with no account behind it, and the only way in was the CLI.
func TestEnsureDevAdminCreatesAnAccount(t *testing.T) {
	cfg := testConfig(t)
	s, store := devStore(t, cfg)
	ctx := context.Background()

	s.ensureDevAdmin(ctx)

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 1 {
		t.Fatalf("got %d admins, want the dev account to have been created", len(admins))
	}
	if admins[0].Email != devAdminEmail {
		t.Errorf("email = %q, want %q", admins[0].Email, devAdminEmail)
	}
	if admins[0].Role != "admin" {
		t.Errorf("role = %q, want admin", admins[0].Role)
	}

	// The hash written must be the config's password, not something else that
	// happens to be a valid hash.
	a, err := store.GetAdminByEmail(ctx, devAdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	if err := signauthValidate(cfg.AdminPassword(), a.PWHash); err != nil {
		t.Errorf("the logged password does not unlock the account it created: %v", err)
	}
}

// The password is generated per start when the config has none, so an account
// created from it must still be a real login. This is case B of the operator
// run: the only copy of the credential is the log line.
func TestEnsureDevAdminWithEphemeralPassword(t *testing.T) {
	// Loaded through the real config path, not by hand: the ephemeral password
	// is synthesised during LoadConfig, so a hand-built Config would not show
	// the thing this test is about.
	cfg := devEphemeralConfig(t)
	s, store := devStore(t, cfg)
	ctx := context.Background()

	pw := cfg.AdminPassword()
	if pw == "" {
		t.Fatal("dev mode is expected to derive an admin password")
	}
	s.ensureDevAdmin(ctx)

	a, err := store.GetAdminByEmail(ctx, devAdminEmail)
	if err != nil {
		t.Fatalf("no dev account after ensureDevAdmin: %v", err)
	}
	if err := signauthValidate(pw, a.PWHash); err != nil {
		t.Errorf("the logged password does not unlock the account: %v", err)
	}
}

// An operator who has already run `admin add` must not find a second account,
// and must not have their choice of address shadowed.
func TestEnsureDevAdminLeavesAnExistingAdminAlone(t *testing.T) {
	cfg := testConfig(t)
	s, store := devStore(t, cfg)
	ctx := context.Background()

	hash, err := signauthHash("some-real-password-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddAdmin(ctx, "real@example.test", hash, "admin"); err != nil {
		t.Fatal(err)
	}

	s.ensureDevAdmin(ctx)

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 1 {
		t.Fatalf("got %d admins, want the existing one left alone", len(admins))
	}
	if admins[0].Email != "real@example.test" {
		t.Errorf("email = %q, want the existing admin untouched", admins[0].Email)
	}
}

// Production must never get a backdoor account. cfg.Dev is the only gate, so
// the same call with Dev off has to be a no-op even on an empty database.
func TestEnsureDevAdminIsHarmlessWhenNotDev(t *testing.T) {
	cfg := testConfig(t)
	cfg.Dev = false
	s, store := devStore(t, cfg)
	ctx := context.Background()

	s.ensureDevAdmin(ctx)

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 0 {
		t.Fatalf("got %d admins on a non-dev empty database, want none", len(admins))
	}
}
