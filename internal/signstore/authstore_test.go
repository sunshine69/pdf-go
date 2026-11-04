package signstore

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The refresh chain is the part of the login state that a copied database must
// not be able to use: rows are hashes, spending is single-use, and a chain is
// deleted as a unit.

func expires(days int) string {
	return formatTime(time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour))
}

func TestRefreshSingleUse(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.CreateRefresh(ctx, "admin:7", "hash-a", expires(12)); err != nil {
		t.Fatalf("create: %v", err)
	}

	subject, err := s.ConsumeRefresh(ctx, "hash-a")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if subject != "admin:7" {
		t.Fatalf("subject %q, want admin:7", subject)
	}
	// Spending hands back the owner, and the replacement is issued by the
	// caller; the chain continues.
	if err := s.CreateRefresh(ctx, subject, "hash-b", expires(12)); err != nil {
		t.Fatal(err)
	}

	// The token that was spent cannot be spent again: this is the replay case,
	// where the same refresh value is presented a second time.
	if _, err := s.ConsumeRefresh(ctx, "hash-a"); err != ErrNotFound {
		t.Fatalf("second consume of a spent token: %v, want ErrNotFound", err)
	}

	// Spending hash-b hands back the owner, and its replacement is live.
	if _, err := s.ConsumeRefresh(ctx, "hash-b"); err != nil {
		t.Fatalf("consume of the replacement: %v", err)
	}
	if err := s.CreateRefresh(ctx, "admin:7", "hash-c", expires(12)); err != nil {
		t.Fatal(err)
	}

	live, consumed, err := s.CountRefresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// hash-a and hash-b were spent; hash-c is the live head of the chain.
	if live != 1 || consumed != 2 {
		t.Fatalf("live %d, consumed %d; want 1 live, 2 consumed", live, consumed)
	}
	if _, err := s.ConsumeRefresh(ctx, "hash-c"); err != nil {
		t.Fatalf("consume of the head: %v", err)
	}
}

func TestRefreshUnknownAndExpired(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// A forged hash and a chain past its own deadline answer the same way, so
	// the API cannot be used to search for a subject that exists.
	if _, err := s.ConsumeRefresh(ctx, strings.Repeat("0", 64)); err != ErrNotFound {
		t.Fatalf("forged hash: %v, want ErrNotFound", err)
	}

	if err := s.CreateRefresh(ctx, "admin:1", "hash-old", expires(-1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRefresh(ctx, "hash-old"); err != ErrNotFound {
		t.Fatalf("expired chain: %v, want ErrNotFound", err)
	}
}

func TestRefreshChainDeletedAsAUnit(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, h := range []string{"h1", "h2", "h3"} {
		if err := s.CreateRefresh(ctx, "admin:4", h, expires(12)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateRefresh(ctx, "admin:5", "other", expires(12)); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteRefreshChain(ctx, "admin:4")
	if err != nil {
		t.Fatalf("delete chain: %v", err)
	}
	if n != 3 {
		t.Fatalf("deleted %d rows, want 3", n)
	}
	// The other subject's chain survives: a logout does not end anyone else's
	// session.
	if _, err := s.ConsumeRefresh(ctx, "other"); err != nil {
		t.Fatalf("the other chain must survive a logout: %v", err)
	}
}

func TestRefreshSweepDeletesStaleChains(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.CreateRefresh(ctx, "admin:2", "live", expires(12)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRefresh(ctx, "admin:3", "stale", expires(-1)); err != nil {
		t.Fatal(err)
	}

	r, err := Sweep(ctx, s.DB())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if r.RefreshDeleted != 1 {
		t.Fatalf("sweep deleted %d refresh rows, want 1", r.RefreshDeleted)
	}
	// The sweep is idempotent.
	r2, err := Sweep(ctx, s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if r2.RefreshDeleted != 0 {
		t.Fatalf("second sweep deleted %d refresh rows, want 0", r2.RefreshDeleted)
	}
	live, _, err := s.CountRefresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("%d live chains after the sweep, want 1", live)
	}
}

func TestAdminPasswordEpochRefusesOlderTokens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	id, err := s.AddAdmin(ctx, "epoch@sign.test", "$argon2id$placeholder", "admin")
	if err != nil {
		t.Fatal(err)
	}

	// Before any password change, the epoch is 0: every token is allowed.
	if e, err := s.AuthEpoch(ctx, "admin:"+strconv.Itoa(int(id))); err != nil || e != 0 {
		t.Fatalf("epoch %d, %v; want 0 for an admin that never changed a password", e, err)
	}

	if err := s.SetAdminPassword(ctx, id, "$argon2id$second-hash"); err != nil {
		t.Fatal(err)
	}
	e, err := s.AuthEpoch(ctx, "admin:"+strconv.Itoa(int(id)))
	if err != nil {
		t.Fatal(err)
	}
	if e == 0 {
		t.Fatal("the epoch must move when the password changes")
	}

	// The row is readable by the id the token carries.
	a, err := s.GetAdminByID(ctx, strconv.Itoa(int(id)))
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if a.PWHash != "$argon2id$second-hash" {
		t.Fatalf("hash %q, want the new one", a.PWHash)
	}

	// A subject that is not an admin has no epoch.
	if e, err := s.AuthEpoch(ctx, "client:3"); err != nil || e != 0 {
		t.Fatalf("client epoch %d, %v; want 0", e, err)
	}
	// A client id that does not exist resolves to nothing, not to a row.
	if _, err := s.GetAdminByID(ctx, "9999"); err != ErrNotFound {
		t.Fatalf("unknown admin id: %v, want ErrNotFound", err)
	}
}

func TestClientByIDScopesAreReadable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	id, err := s.AddClient(ctx, "billing", strings.Repeat("a", 64), "envelope:read envelope:write")
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetClientByID(ctx, strconv.Itoa(int(id)))
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if c.Name != "billing" || c.RevokedAt != "" {
		t.Fatalf("client %+v", c)
	}

	if err := s.RevokeClient(ctx, id); err != nil {
		t.Fatal(err)
	}
	c, err = s.GetClientByID(ctx, strconv.Itoa(int(id)))
	if err != nil {
		t.Fatal(err)
	}
	if c.RevokedAt == "" {
		t.Fatal("a revoked client must read as revoked, so a refresh can refuse it")
	}
}
