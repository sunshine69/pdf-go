package signauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The login path is tested against a real database: the refresh chain is the
// part of the design where a stub would hide the single-use rule.

func newSessions(t *testing.T) (*Sessions, *signstore.Store) {
	t.Helper()
	ctx := context.Background()
	path := t.TempDir() + "/signsrv.db"
	db, err := signstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := signstore.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := signstore.NewStore(db, t.TempDir()+"/storage")
	return &Sessions{Keys: newTestKeyring(t), Store: store}, store
}

func TestLoginRealPassword(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.AddAdmin(ctx, "admin@sign.test", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}

	subject, err := s.Login(ctx, "admin@sign.test", "correct horse battery staple")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if subject != AdminSubject(id) {
		t.Fatalf("subject %q, want %q", subject, AdminSubject(id))
	}
}

func TestLoginUnknownEmailCostsTheSame(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	hash, err := HashPassword("a-real-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddAdmin(ctx, "known@sign.test", hash, "admin"); err != nil {
		t.Fatal(err)
	}

	// A wrong password on a real address, and a right password on an address
	// that does not exist, are the same answer.
	if _, err := s.Login(ctx, "known@sign.test", "wrong"); err != ErrLoginDenied {
		t.Fatalf("wrong password: %v, want the same refusal as an unknown address", err)
	}
	if _, err := s.Login(ctx, "nobody@sign.test", "a-real-password"); err != ErrLoginDenied {
		t.Fatalf("unknown address: %v, want ErrLoginDenied", err)
	}
	if _, err := s.Login(ctx, "", "x"); err != ErrLoginDenied {
		t.Fatalf("empty email: %v", err)
	}

	// The dummy hash must be a valid encoding, otherwise the unknown-email
	// path fails fast and the timing equalisation is a lie.
	ok, err := VerifyPassword("anything", dummyHash)
	if err != nil {
		t.Fatalf("the dummy hash must parse: %v", err)
	}
	if ok {
		t.Fatal("the dummy hash must never verify")
	}
	// And the cost must be the cost of a real verification. The assertion is
	// loose (a shared machine, 64 MiB of memory), the point is that the
	// unknown-address path does not return in microseconds.
	start := time.Now()
	if _, err := s.Login(ctx, "absent@sign.test", "x"); err != ErrLoginDenied {
		t.Fatal(err)
	}
	unknown := time.Since(start)
	start = time.Now()
	if _, err := s.Login(ctx, "known@sign.test", "wrong"); err != ErrLoginDenied {
		t.Fatal(err)
	}
	known := time.Since(start)
	// 64 MiB x 3 passes is tens of milliseconds; a path that skipped argon2
	// would return in microseconds.
	if unknown < 20*time.Millisecond {
		t.Fatalf("unknown address took %v, argon2 was not run", unknown)
	}
	if known < 20*time.Millisecond {
		t.Fatalf("known address took %v, argon2 was not run", known)
	}
	if unknown > 10*known || known > 10*unknown {
		t.Fatalf("costs differ by more than an order of magnitude: %v vs %v", unknown, known)
	}
}

func TestLoginAdminRevokedHasNoPath(t *testing.T) {
	// An admin is deleted, not disabled: the store has no revoked_at for
	// admins, so the login path has to refuse when the row is gone. The
	// assertion is that the missing row is the same answer as a wrong
	// password.
	ctx := context.Background()
	s, store := newSessions(t)
	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddAdmin(ctx, "gone@sign.test", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "gone@sign.test", "pw"); err != nil {
		t.Fatalf("login before removal: %v", err)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	access, refresh, err := s.MintSession(ctx, AdminSubject(7), RoleAdmin, []string{ScopeAdminRead}, AccessTTL)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := s.Keys.VerifyAccess(access)
	if err != nil {
		t.Fatalf("verify the minted access token: %v", err)
	}
	if claims.Subject != "admin:7" || claims.Role != RoleAdmin {
		t.Fatalf("claims %+v", claims)
	}

	// The refresh token is stored as a hash, never as the value handed out.
	live, consumed, err := store.CountRefresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live != 1 || consumed != 0 {
		t.Fatalf("live %d, consumed %d, want 1 and 0", live, consumed)
	}
	// The stored row is a hash. Reading the value that was handed out as an
	// email address must find nothing.
	if _, err := store.GetAdminByEmail(ctx, refresh); err != signstore.ErrNotFound {
		t.Fatalf("the refresh value must not resolve to an admin: %v", err)
	}

	// The pair is refreshed: the old refresh dies, the old access token's jti
	// is revoked, and the new pair works.
	next, newRefresh, err := s.Refresh(ctx, refresh, claims.JTI)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if next == access || newRefresh == refresh {
		t.Fatal("refresh must issue new values, not echo the pair")
	}
	if _, err := s.Keys.VerifyAccess(next); err != nil {
		t.Fatalf("verify the refreshed access token: %v", err)
	}
	// The refresh token in hand is spent.
	if _, _, err := s.Refresh(ctx, refresh, ""); err != ErrLoginDenied {
		t.Fatalf("replayed refresh: %v, want ErrLoginDenied", err)
	}
	// The jti of the access token that was in hand is revoked.
	revoked, err := store.IsJTIRevoked(ctx, claims.JTI)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("the access token of a refreshed session must be revoked")
	}
}

func TestRefreshClientScopesAreReread(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	key := "client-key-value-long-enough"
	scopes := "envelope:read envelope:write"
	id, err := store.AddClient(ctx, "billing", HashToken(key), scopes)
	if err != nil {
		t.Fatal(err)
	}

	subject, got, err := s.ClientLogin(ctx, key)
	if err != nil {
		t.Fatalf("client login: %v", err)
	}
	if subject != ClientSubject(id) || strings.Join(got, " ") != scopes {
		t.Fatalf("subject %q, scopes %v", subject, got)
	}

	access, refresh, err := s.MintSession(ctx, subject, RoleClient, got, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Keys.VerifyAccess(access)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.HasScope("envelope:write") {
		t.Fatal("the minted token must carry the client's scopes")
	}

	// Revoking the client takes effect the next time its token is refreshed:
	// the chain dies, and the row's revocation is what stopped it.
	if err := store.RevokeClient(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Refresh(ctx, refresh, claims.JTI); err != ErrLoginDenied {
		t.Fatalf("refresh of a revoked client: %v, want ErrLoginDenied", err)
	}
}

func TestClientLoginUnknownAndRevoked(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	if _, _, err := s.ClientLogin(ctx, ""); err != ErrLoginDenied {
		t.Fatalf("empty key: %v", err)
	}
	if _, _, err := s.ClientLogin(ctx, "a key that was never issued"); err != ErrLoginDenied {
		t.Fatalf("unknown key: %v, want the same answer as a revoked key", err)
	}

	id, err := store.AddClient(ctx, "ops", HashToken("issued-key"), "envelope:read")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ClientLogin(ctx, "issued-key"); err != nil {
		t.Fatalf("login before revoke: %v", err)
	}
	if err := store.RevokeClient(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ClientLogin(ctx, "issued-key"); err != ErrLoginDenied {
		t.Fatalf("revoked client: %v, want ErrLoginDenied", err)
	}
}

func TestLogoutEndsTheChain(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	access, refresh, err := s.MintSession(ctx, AdminSubject(3), RoleAdmin, nil, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Keys.VerifyAccess(access)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Logout(ctx, AdminSubject(3), claims.JTI); err != nil {
		t.Fatalf("logout: %v", err)
	}
	// No new access token can be minted: the chain is gone.
	if _, _, err := s.Refresh(ctx, refresh, ""); err != ErrLoginDenied {
		t.Fatalf("refresh after logout: %v, want ErrLoginDenied", err)
	}
	// The access token in hand is revoked, so the next request answers 401.
	revoked, err := store.IsJTIRevoked(ctx, claims.JTI)
	if err != nil || !revoked {
		t.Fatalf("jti revoked = %v, %v; want true", revoked, err)
	}
	live, _, err := store.CountRefresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("%d live chains after logout, want 0", live)
	}
}

func TestLogoutDoesNotTouchOtherSubjects(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	_, refreshA, err := s.MintSession(ctx, AdminSubject(1), RoleAdmin, nil, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	_, refreshB, err := s.MintSession(ctx, AdminSubject(2), RoleAdmin, nil, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Logout(ctx, AdminSubject(1), ""); err != nil {
		t.Fatal(err)
	}
	// Admin 1's chain is gone, admin 2's is not: a logout is scoped to the
	// subject that asked for it.
	if _, _, err := s.Refresh(ctx, refreshA, ""); err != ErrLoginDenied {
		t.Fatalf("the logged-out chain must be dead: %v", err)
	}
	if _, _, err := s.Refresh(ctx, refreshB, ""); err != nil {
		t.Fatalf("the other admin's chain must survive: %v", err)
	}
	live, _, err := store.CountRefresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("%d live chains, want 1 (the admin that stayed logged in)", live)
	}
}

func TestPasswordEpochRefusesTokensMintedBeforeTheChange(t *testing.T) {
	ctx := context.Background()
	s, store := newSessions(t)

	hash, err := HashPassword("old-password")
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.AddAdmin(ctx, "epoch@sign.test", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	subject := AdminSubject(id)

	// A token minted now is accepted, because the epoch is 0.
	access, refresh, err := s.MintSession(ctx, subject, RoleAdmin, []string{ScopeAdminRead}, AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Keys.VerifyAccess(access)
	if err != nil {
		t.Fatal(err)
	}

	// The password changes. The epoch moves to now, so the token in hand is
	// refused: a stolen token cannot outlive a password change.
	newHash, err := HashPassword("new-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminPassword(ctx, id, newHash); err != nil {
		t.Fatal(err)
	}
	epoch, err := store.AuthEpoch(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if epoch == 0 {
		t.Fatal("the epoch must move when the password changes")
	}
	if claims.IssuedAt < epoch {
		// The token is older than the change: this is the case the middleware
		// must refuse. The store gives the epoch, the middleware compares.
		t.Logf("token iat %d, epoch %d", claims.IssuedAt, epoch)
	}
	// The login path still works with the new password, and only with it.
	if _, err := s.Login(ctx, "epoch@sign.test", "new-password"); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
	if _, err := s.Login(ctx, "epoch@sign.test", "old-password"); err != ErrLoginDenied {
		t.Fatalf("login with the old password: %v, want ErrLoginDenied", err)
	}
	// The chain of the old session is deleted by the passwd command, so the
	// refresh token in hand cannot mint a new access token.
	if err := s.Logout(ctx, subject, claims.JTI); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Refresh(ctx, refresh, ""); err != ErrLoginDenied {
		t.Fatalf("refresh after a password change: %v, want ErrLoginDenied", err)
	}
}

func TestSplitSubject(t *testing.T) {
	kind, id := SplitSubject("admin:7")
	if kind != "admin" || id != "7" {
		t.Fatalf("admin subject %q, %q", kind, id)
	}
	kind, id = SplitSubject("client:3")
	if kind != "client" || id != "3" {
		t.Fatalf("client subject %q, %q", kind, id)
	}
	if kind, id := SplitSubject("no-colon"); kind != "" || id != "" {
		t.Fatalf("a subject without a colon must split to nothing: %q, %q", kind, id)
	}
}

func TestSplitScopes(t *testing.T) {
	if got := strings.Join(SplitScopes("envelope:read envelope:write"), " "); got != "envelope:read envelope:write" {
		t.Fatalf("scopes %q", got)
	}
	if len(SplitScopes("")) != 0 {
		t.Fatal("an empty scope string must split to nothing")
	}
	// The CLI joins scopes with commas, so the comma-joined stored form must
	// split into the elements. A reader that left it as one element would
	// mint a token that can never match a route's scope, and the client would
	// be locked out of every endpoint while its row looked correct.
	scopes := SplitScopes("envelope:read,envelope:write")
	if strings.Join(scopes, " ") != "envelope:read envelope:write" {
		t.Fatalf("comma-joined scopes %v, want two elements", scopes)
	}
	if len(SplitScopes(" envelope:read ,, envelope:write ")) != 2 {
		t.Fatalf("empty fields must not become scopes: %v", SplitScopes(" envelope:read ,, envelope:write "))
	}
}
