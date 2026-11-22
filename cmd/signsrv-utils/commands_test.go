package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// testStore opens a real SQLite database in a temp dir and migrates it, so the
// commands run against the same schema the service uses. The file has to be
// created here: the production path refuses to create one, and a test that
// relied on that behaviour would be testing the wrong thing.
func testStore(t *testing.T) (*signstore.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signsrv.db")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	db, err := signstore.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signstore.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return signstore.NewStore(db, ""), path
}

// capture runs fn with stdout and stderr redirected, so the assertions are
// about what the operator actually sees.
func capture(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	so, se := os.Stdout, os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout, os.Stderr = w, w
	done := make(chan string, 1)
	go func() {
		var sb bytes.Buffer
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	code := fn()
	w.Close()
	os.Stdout, os.Stderr = so, se
	out := <-done
	t.Logf("rc=%d\n%s", code, out)
	return out, code
}

func TestAdminAddListAndPasswd(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	t.Setenv("ADMIN_PASSWORD", "a-long-enough-pass-1")

	out, code := capture(t, func() int {
		return adminCmd(ctx, store, []string{"add", "Ops@Example.ORG"})
	})
	if code != 0 {
		t.Fatalf("admin add rc=%d: %s", code, out)
	}
	// The email is stored lower-cased: login compares on the stored value, and
	// an operator typing Ops@Example.org must reach the same account.
	if !strings.Contains(out, "ops@example.org") {
		t.Fatalf("email not normalised: %s", out)
	}

	out, code = capture(t, func() int { return adminCmd(ctx, store, []string{"list"}) })
	if code != 0 || !strings.Contains(out, "ops@example.org") || !strings.Contains(out, "role=admin") {
		t.Fatalf("admin list rc=%d: %s", code, out)
	}

	// Adding the same address twice is the common mistake. The error has to say
	// what to do instead, because the alternative is the operator concluding the
	// account does not exist and trying a third time.
	out, code = capture(t, func() int { return adminCmd(ctx, store, []string{"add", "ops@example.org"}) })
	if code == 0 {
		t.Fatal("duplicate add must fail")
	}
	if !strings.Contains(out, "admin passwd ops@example.org") {
		t.Fatalf("duplicate add should name the fix: %s", out)
	}

	out, code = capture(t, func() int {
		return adminCmd(ctx, store, []string{"passwd", "ops@example.org"})
	})
	if code != 0 || !strings.Contains(out, "password changed") {
		t.Fatalf("admin passwd rc=%d: %s", code, out)
	}

	// Unknown address: the operator needs to be told to look, not just failed.
	out, code = capture(t, func() int { return adminCmd(ctx, store, []string{"passwd", "nobody@example.org"}) })
	if code == 0 || !strings.Contains(out, "admin list") {
		t.Fatalf("unknown email should point at admin list: rc=%d %s", code, out)
	}
}

func TestAdminPasswordFloor(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	// The 12-character floor is the server's, and this tool writes the same
	// column. If it accepted shorter, an operator would set a password the
	// service then refuses to let them log in with — the worst kind of surprise.
	t.Setenv("ADMIN_PASSWORD", "short")
	out, code := capture(t, func() int { return adminCmd(ctx, store, []string{"add", "weak@example.org"}) })
	if code == 0 || !strings.Contains(out, "12") {
		t.Fatalf("short password must be refused with the floor stated: rc=%d %s", code, out)
	}

	if _, err := store.ListAdmins(ctx); err != nil {
		t.Fatal(err)
	}
	admins, _ := store.ListAdmins(ctx)
	if len(admins) != 0 {
		t.Fatalf("a rejected add must not leave an account behind, got %d", len(admins))
	}
}

func TestAdminAddRejectsMalformedEmail(t *testing.T) {
	store, _ := testStore(t)
	for _, bad := range []string{"notanemail", "at@end", "x@"} {
		out, code := capture(t, func() int { return adminCmd(ctx0(), store, []string{"add", bad}) })
		if code == 0 {
			t.Errorf("%q accepted: %s", bad, out)
		}
	}
}

func ctx0() context.Context { return context.Background() }

func TestClientAddListRevoke(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	out, code := capture(t, func() int {
		return clientCmd(ctx, store, []string{"add", "batch", "envelope:write", "envelope:read"})
	})
	if code != 0 {
		t.Fatalf("client add rc=%d: %s", code, out)
	}
	// The key is printed exactly once, because it is the only time it exists in
	// recoverable form.
	if n := strings.Count(out, "sk_"); n != 1 {
		t.Fatalf("key should appear once, appears %d: %s", n, out)
	}
	if !strings.Contains(out, "cannot be recovered") {
		t.Fatalf("should warn the key is one-time: %s", out)
	}

	out, code = capture(t, func() int { return clientCmd(ctx, store, []string{"list"}) })
	if code != 0 || !strings.Contains(out, "envelope:write,envelope:read") {
		t.Fatalf("client list rc=%d: %s", code, out)
	}
	// A listed client must not leak the key hash: it is a credential.
	if strings.Contains(out, "sha256:") || strings.Contains(out, "sk_") {
		t.Fatalf("client list should not print key material: %s", out)
	}

	out, code = capture(t, func() int { return clientCmd(ctx, store, []string{"revoke", "1"}) })
	if code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("client revoke rc=%d: %s", code, out)
	}

	out, code = capture(t, func() int { return clientCmd(ctx, store, []string{"revoke", "not-a-number"}) })
	if code == 0 || !strings.Contains(out, "not a client id") {
		t.Fatalf("non-numeric id should be rejected clearly: rc=%d %s", code, out)
	}
}

func TestStatusReportsEveryTable(t *testing.T) {
	store, _ := testStore(t)
	out, code := capture(t, func() int { return statusCmd(ctx0(), store, nil) })
	if code != 0 {
		t.Fatalf("status rc=%d: %s", code, out)
	}
	for _, want := range []string{"schema_version", "admins", "clients", "users", "envelopes"} {
		if !strings.Contains(out, want) {
			t.Errorf("status should report %q: %s", want, out)
		}
	}
}

func TestDispatchRejectsUnknown(t *testing.T) {
	store, _ := testStore(t)
	if _, code := capture(t, func() int { return dispatch(ctx0(), store, []string{"frobnicate"}) }); code != 2 {
		t.Fatal("unknown command should exit 2 with usage")
	}
	if _, code := capture(t, func() int { return dispatch(ctx0(), store, []string{"admin", "nope"}) }); code == 0 {
		t.Fatal("unknown admin subcommand should fail")
	}
}

// openAndMigrate must never create a database: a typo in -db would otherwise
// produce an empty one, "no admins", and a directory that did not exist before.
func TestOpenRefusesToCreate(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.db")
	if _, err := openAndMigrate(ctx0(), missing); err == nil {
		t.Fatal("must refuse to create a missing database")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("the failed attempt must not have created the file")
	}

	dir := t.TempDir()
	if _, err := openAndMigrate(ctx0(), dir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("a directory should be named as such, got %v", err)
	}
}

// The service supports postgres DSNs in db=. This build cannot open one, and
// silently passing it to the SQLite driver produces a nonsense error, so the
// refusal has to say what is going on.
func TestOpenRefusesPostgres(t *testing.T) {
	for _, dsn := range []string{"postgres://u@h/db", "postgresql://u@h/db"} {
		_, err := openAndMigrate(ctx0(), dsn)
		if err == nil || !strings.Contains(err.Error(), "postgres") {
			t.Fatalf("%q should be refused with a clear reason, got %v", dsn, err)
		}
	}
}
