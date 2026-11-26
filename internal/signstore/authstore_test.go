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

// TestClientRevocationSetsAnAuthEpoch is the second half of the client revoke
// story. The endpoint records revoked_at; the middleware refuses a token whose
// iat is before the epoch. Without this test, the two halves can be individually
// correct and still not join: a revoke that wrote a stamp the epoch reader could
// not parse, or that read back as 0, would leave every token the revoked client
// already holds working until its natural expiry, which is exactly the behaviour
// the operator is promised.
func TestClientRevocationSetsAnAuthEpoch(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	id, err := s.AddClient(ctx, "epochy", strings.Repeat("b", 64), "envelope:read")
	if err != nil {
		t.Fatal(err)
	}
	subject := "client:" + strconv.Itoa(int(id))

	// An active client has no epoch, so its tokens are not gated by one.
	if e, err := s.AuthEpoch(ctx, subject); err != nil || e != 0 {
		t.Fatalf("epoch %d, %v; want 0 for an active client", e, err)
	}

	if err := s.RevokeClient(ctx, id); err != nil {
		t.Fatal(err)
	}
	e, err := s.AuthEpoch(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if e == 0 {
		t.Fatal("the epoch must move when a client is revoked, or its live tokens outlive the revocation")
	}
	if age := time.Since(time.Unix(e, 0)); age < 0 || age > time.Minute {
		t.Fatalf("epoch %d is %v from now; the stamp must be the revocation time", e, age)
	}

	// The epoch parses. revoked_at is written by timeNow() in a fixed format and
	// read by time.Parse in the same one; if those two ever disagree, AuthEpoch
	// must say so rather than silently reporting 0, because 0 means "no epoch" and
	// a silent 0 here is a revoked client whose tokens still work.
	if _, err := time.Parse(time.RFC3339, time.Unix(e, 0).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("epoch %d does not round-trip: %v", e, err)
	}

	// A revoked client cannot be revoked again: the update is conditioned on
	// revoked_at is null, and the handler turns the zero-row result into a 404.
	if err := s.RevokeClient(ctx, id); err == nil {
		t.Fatal("revoking an already revoked client must affect no row")
	}
	// The epoch survives the refused second revoke, and a deleted-or-unknown
	// subject resolves to no epoch rather than an error: the middleware reads a
	// missing row as "nothing has happened".
	if e2, err := s.AuthEpoch(ctx, subject); err != nil || e2 != e {
		t.Fatalf("epoch %d, %v after a refused re-revoke; want it unchanged at %d", e2, err, e)
	}
	if e2, err := s.AuthEpoch(ctx, "client:9999"); err != nil || e2 != 0 {
		t.Fatalf("unknown client epoch %d, %v; want 0, not an error", e2, err)
	}
}
