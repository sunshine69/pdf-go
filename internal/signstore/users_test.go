package signstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The account table. One row, three things in it: the password for the web
// portal that does not exist yet, the shared secret a caller signs its own API
// tokens with, and the grant that decides what those tokens may do.
//
// The tests below are the properties the auth gate leans on. The gate reads
// this table on every caller-minted request, so a property that does not hold
// here is a property the gate does not have.

func TestUserMigrationCreatesTheTable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	// v5 is the migration that adds the table. A fresh database is at the
	// binary's version, and the version is the one the migrations list ends on.
	v, err := SchemaVersion(ctx, s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if v != CurrentVersion {
		t.Fatalf("schema version = %d, want %d", v, CurrentVersion)
	}
	// And the table answers, with no rows.
	if _, err := s.ListUsers(ctx); err != nil {
		t.Fatalf("ListUsers on an empty table: %v", err)
	}
}

func TestUserAddReadRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	secret, err := NewJWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.AddUser(ctx, "dispatch", "argon2id$stub", secret, "envelope:read", "")
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Fatalf("id = %d", id)
	}
	u, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	// The secret is stored verbatim: the server needs the string to verify an
	// HMAC, so there is nothing to hash it into.
	if u.JWTSecret != secret {
		t.Fatal("the secret read back is not the one written")
	}
	// The role is defaulted, so a row cannot be inserted without one and read
	// back as an empty role — the gate refuses an empty role.
	if u.Role != "user" {
		t.Fatalf("role = %q, want user", u.Role)
	}
	// The grant is the string it was given.
	if u.Scopes != "envelope:read" {
		t.Fatalf("scopes = %q", u.Scopes)
	}
	// The password stamp is set on insert: the epoch of a row is never zero,
	// so a token minted before the row existed cannot pass.
	if u.PWChangedAt == "" {
		t.Fatal("pw_changed_at is empty on a fresh row")
	}
	// Not revoked, so the row is usable.
	if u.RevokedAt != "" {
		t.Fatalf("revoked_at = %q on a fresh row", u.RevokedAt)
	}
	byID, err := s.GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if byID.Username != u.Username || byID.JWTSecret != u.JWTSecret {
		t.Fatal("the row read by id is not the row read by name")
	}
}

// A duplicate username is refused with the store's own error, so the CLI can
// say "the name is taken" rather than echoing a driver message.
func TestUserDuplicateUsername(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.AddUser(ctx, "dispatch", "h", "s1", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser(ctx, "dispatch", "h", "s2", "", ""); !errors.Is(err, ErrDuplicateUsername) {
		t.Fatalf("second add: %v, want ErrDuplicateUsername", err)
	}
	// The first row is untouched: a refused insert did not replace the secret.
	u, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if u.JWTSecret != "s1" {
		t.Fatalf("the second insert changed the secret to %q", u.JWTSecret)
	}
}

// Rotation is the answer to a leaked secret. The old string stops verifying
// because the row now holds a different one; the row is otherwise intact.
func TestUserRotateJWTSecret(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.AddUser(ctx, "dispatch", "h", "old-secret", "envelope:read", ""); err != nil {
		t.Fatal(err)
	}
	u, secret, err := s.RotateJWTSecretByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "old-secret" || secret == "" {
		t.Fatalf("new secret = %q", secret)
	}
	if len(secret) < 40 {
		t.Fatalf("the new secret is short: %d characters", len(secret))
	}
	after, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if after.JWTSecret != secret {
		t.Fatal("the row does not hold the new secret")
	}
	// The grant and the password survive: rotating a secret is not a reset of
	// the account, and a CLI that rotates must not silently widen or narrow
	// the scopes.
	if after.Scopes != "envelope:read" || after.Password != "h" {
		t.Fatalf("rotation changed the row: scopes %q password %q", after.Scopes, after.Password)
	}
	if u.Username != "dispatch" {
		t.Fatalf("the returned row is %q", u.Username)
	}
}

// Revocation is a stamp, not a delete. The row stays, so the audit trail of
// what the secret signed stays verifiable, and every lookup of the name finds a
// row that says "revoked" rather than nothing at all.
func TestUserRevokeIsAStamp(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id, err := s.AddUser(ctx, "dispatch", "h", "s", "", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.RevokeUserByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if u.RevokedAt == "" {
		t.Fatal("the returned row is not stamped")
	}
	after, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if after.RevokedAt == "" {
		t.Fatal("the row is not stamped in the table")
	}
	if after.JWTSecret != "s" {
		t.Fatal("revocation cleared the secret: the audit trail of what it signed must stay checkable")
	}
	// Revoking twice is a not-found, not a silent success: the CLI says so.
	if err := s.RevokeUser(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v, want ErrNotFound", err)
	}
	// A revoked row is still in the list, because the operator's question is
	// "who has an account, and which are closed".
	all, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("list length = %d, want 1", len(all))
	}
}

// A password change moves the epoch. The gate refuses a token minted before
// the stamp, so this is the user's one action after a leak.
func TestUserSetPasswordMovesTheEpoch(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id, err := s.AddUser(ctx, "dispatch", "old-hash", "s", "", "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	// The stamp is to the second, which is what the epoch check compares
	// against iat. A change inside the row's own second cannot be ordered, and
	// the gate's rule is that a token minted in the same second survives — so
	// the test waits for a second to pass, as a real operator does.
	time.Sleep(1100 * time.Millisecond)
	if err := s.SetUserPassword(ctx, id, "new-hash"); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if after.Password != "new-hash" {
		t.Fatal("the password is not the new hash")
	}
	if after.PWChangedAt == before.PWChangedAt {
		t.Fatal("pw_changed_at did not move: every token minted under the old password keeps working")
	}
	// The stamp is a time, so the gate can compare it with iat.
	if _, err := time.Parse(time.RFC3339, after.PWChangedAt); err != nil {
		if _, err := time.Parse("2006-01-02 15:04:05", after.PWChangedAt); err != nil {
			t.Fatalf("pw_changed_at is not a timestamp the gate can read: %q", after.PWChangedAt)
		}
	}
}

// TouchUserLastLogin is the operator's "is this account in use" column. It must
// not disturb the epoch: a login is not a credential change, and stamping
// pw_changed_at on login would kill the token that was just minted.
func TestUserLastLoginLeavesTheEpoch(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id, err := s.AddUser(ctx, "dispatch", "h", "s", "", "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.TouchUserLastLogin(ctx, id); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if after.LastLogin == "" {
		t.Fatal("last_login is empty after a login")
	}
	if after.PWChangedAt != before.PWChangedAt {
		t.Fatal("a login moved the credential epoch")
	}
}

func TestScopeList(t *testing.T) {
	cases := map[string][]string{
		"":               nil,
		"envelope:read":  {"envelope:read"},
		"a,b":            {"a", "b"},
		" a , b ,, c ":   {"a", "b", "c"},
		"envelope:read,": {"envelope:read"},
		",,":             nil,
		"admin:read":     {"admin:read"},
	}
	for in, want := range cases {
		got := ScopeList(in)
		if len(got) != len(want) {
			t.Errorf("ScopeList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("ScopeList(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// The grant is editable, and the edit is the only way a caller-minted token
// gains a scope. The token's own claims are cosmetic; this column is the grant.
func TestUserSetScopes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id, err := s.AddUser(ctx, "dispatch", "h", "s", "envelope:read", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserScopes(ctx, id, "envelope:read,envelope:write"); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetByUsername(ctx, "dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if len(ScopeList(u.Scopes)) != 2 {
		t.Fatalf("scopes = %q", u.Scopes)
	}
	if err := s.SetUserScopes(ctx, 1<<40, "envelope:read"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scopes on a missing row: %v, want ErrNotFound", err)
	}
}

// A sweep must not touch the accounts. It expires envelopes and mail leases; an
// account has no expiry, and a sweep that closed accounts would log people out
// on a schedule.
func TestSweepLeavesAccountsAlone(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.AddUser(ctx, "dispatch", "h", "s", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Sweep(ctx, s.DB()); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].RevokedAt != "" {
		t.Fatalf("the sweep changed the accounts: %+v", all)
	}
}

// The list is the admin surface's read of the table. It carries every row, in a
// stable order, and the secret is in the struct — which is why the endpoint
// that answers a desk must strip it.
func TestListUsersOrderAndCompleteness(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, name := range []string{"zeta", "alpha", "mid"} {
		if _, err := s.AddUser(ctx, name, "h", name+"-secret", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("list length = %d, want 3", len(all))
	}
	// The list carries no secret. The endpoint that answers a desk renders
	// this result, and a list that can be read is a list that leaks. What it
	// does carry is the presence of each credential, which is all an operator
	// needs to know.
	for _, u := range all {
		if u.JWTSecret != "" || u.Password != "" {
			t.Fatalf("row %q carries secret %q and password %q", u.Username, u.JWTSecret, u.Password)
		}
		if !u.HasSecret || !u.HasPassword {
			t.Fatalf("row %q reports has_secret %v has_password %v", u.Username, u.HasSecret, u.HasPassword)
		}
	}
	// Two reads give the same order, so a page that shows ids next to names
	// cannot shuffle between refreshes.
	again, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range all {
		if all[i].ID != again[i].ID {
			t.Fatalf("the order moved at %d: %d then %d", i, all[i].ID, again[i].ID)
		}
	}
}

// A username with no row is the store's not-found, which the gate turns into
// the same answer as a bad signature.
func TestGetByUsernameMissing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.GetByUsername(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ghost: %v, want ErrNotFound", err)
	}
}

// PendingMigrations is the schema endpoint's answer to "should I run migrate?".
func TestPendingMigrations(t *testing.T) {
	if got := PendingMigrations(CurrentVersion); len(got) != 0 {
		t.Fatalf("at the binary's version, pending = %v", got)
	}
	got := PendingMigrations(CurrentVersion - 1)
	if len(got) != 1 || got[0] != CurrentVersion {
		t.Fatalf("one behind: %v, want [%d]", got, CurrentVersion)
	}
	if got := PendingMigrations(0); len(got) != CurrentVersion {
		t.Fatalf("from nothing: %v, want %d entries", got, CurrentVersion)
	}
}
