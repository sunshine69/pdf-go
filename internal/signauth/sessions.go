package signauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Login state: the pair of tokens a caller gets, and the rules for spending
// them.
//
// The access token is short-lived (15 min) and self-contained; the refresh
// token is a 256-bit random value stored as a hash, single-use, with a 12-day
// deadline. Spending one marks it consumed inside a transaction and issues its
// replacement, so a refresh token replayed from a copied database cannot mint a
// second access token.

// RefreshTTL is the lifetime of a refresh chain. Long enough that a signing
// session survives a working week; short enough that a device left behind stops
// being a credential.
const RefreshTTL = 12 * 24 * time.Hour

// dummyHash is a real argon2id hash, computed offline with the parameters in
// password.go and pasted here. Login verifies against it when the email is
// unknown, so a request for an address that does not exist costs the same as a
// request for one that does: the answer cannot be read from how long the server
// was busy.
//
// It is not a secret. It is a fixed hash with a fixed salt, and verifying a
// password against it fails, which is the point.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$vNLvGkZsbhTVVdGhYPhDwQ$C1YclEBtt2nwBQZiIEGQvGevL2C0k6rozuwvlOHVzM4"

// Subjects are the owners of a refresh chain, in the encoding the JWT "sub"
// claim carries. Keeping the kind in the subject means a chain traces back to
// the row it belongs to without a second table.
func AdminSubject(id int64) string  { return "admin:" + fmt.Sprint(id) }
func ClientSubject(id int64) string { return "client:" + fmt.Sprint(id) }

// SplitSubject splits a subject into its kind and id.
func SplitSubject(subject string) (kind, id string) {
	kind, id, ok := strings.Cut(subject, ":")
	if !ok {
		return "", ""
	}
	return kind, id
}

// ErrLoginDenied is the one answer login gives for a wrong email, a wrong
// password, and a revoked account. The API must not split them: which of the
// three failed is information a caller can use to search for a real address.
var ErrLoginDenied = errors.New("signauth: login refused")

// SessionStore is the slice of the store the login path needs.
type SessionStore interface {
	GetAdminByEmail(ctx context.Context, email string) (*signstore.Admin, error)
	GetClientByKeyHash(ctx context.Context, hash string) (*signstore.Client, error)
	GetClientByID(ctx context.Context, id string) (*signstore.Client, error)
	CreateRefresh(ctx context.Context, subject, hash, expiresAt string) error
	ConsumeRefresh(ctx context.Context, hash string) (subject string, err error)
	DeleteRefreshChain(ctx context.Context, subject string) (int, error)
	RevokeJTI(ctx context.Context, jti, expiresAt string) error
}

// Sessions issues and spends the login pairs.
type Sessions struct {
	Keys  *Keyring
	Store SessionStore
}

// Login verifies an admin password and returns the subject. The dummy hash is
// computed when the email is unknown, so the cost of a refusal is the cost of a
// real verification.
func (s *Sessions) Login(ctx context.Context, email, password string) (string, error) {
	if email == "" || password == "" {
		// A request with empty fields costs nothing to answer: the rate
		// limiter is the control for that, not argon2.
		return "", ErrLoginDenied
	}
	rec, err := s.Store.GetAdminByEmail(ctx, email)
	if err != nil && err != signstore.ErrNotFound {
		return "", fmt.Errorf("signauth: read admin: %w", err)
	}
	hash := dummyHash
	if rec != nil {
		hash = rec.PWHash
	}
	ok, err := VerifyPassword(password, hash)
	if err != nil {
		return "", fmt.Errorf("signauth: password check: %w", err)
	}
	if rec == nil || !ok {
		return "", ErrLoginDenied
	}
	return AdminSubject(rec.ID), nil
}

// ClientLogin resolves a machine API key. A key is presented in the same header
// shape a JWT uses, so the API has one verification path.
func (s *Sessions) ClientLogin(ctx context.Context, key string) (string, []string, error) {
	if key == "" {
		return "", nil, ErrLoginDenied
	}
	rec, err := s.Store.GetClientByKeyHash(ctx, HashToken(key))
	if err != nil && err != signstore.ErrNotFound {
		return "", nil, fmt.Errorf("signauth: read client: %w", err)
	}
	if rec == nil || rec.RevokedAt != "" {
		return "", nil, ErrLoginDenied
	}
	return ClientSubject(rec.ID), splitScopes(rec.Scopes), nil
}

// MintSession issues the pair. The access token carries the subject, the role
// and the scopes; the refresh token is the opaque value whose hash goes to the
// store.
func (s *Sessions) MintSession(ctx context.Context, subject, role string, scopes []string, ttl time.Duration) (access, refresh string, err error) {
	if subject == "" || role == "" {
		return "", "", fmt.Errorf("signauth: session needs a subject and a role")
	}
	if ttl <= 0 {
		ttl = AccessTTL
	}
	refresh, err = NewToken()
	if err != nil {
		return "", "", err
	}
	access, err = s.Keys.MintAccess(&Claims{Subject: subject, Role: role, Scopes: scopes}, ttl)
	if err != nil {
		return "", "", err
	}
	if err := s.Store.CreateRefresh(ctx, subject, HashToken(refresh),
		formatTime(time.Now().UTC().Add(RefreshTTL))); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// Refresh spends a refresh token and issues the pair again. The scopes of a
// client are re-read from the database, so revoking a client takes effect the
// next time its token is refreshed. The jti of the access token in hand is
// revoked at the same time.
func (s *Sessions) Refresh(ctx context.Context, refresh, revokeJTI string) (access, next string, err error) {
	if refresh == "" {
		return "", "", ErrLoginDenied
	}
	subject, err := s.Store.ConsumeRefresh(ctx, HashToken(refresh))
	if err != nil {
		return "", "", ErrLoginDenied
	}
	role, scopes := s.roleAndScopes(ctx, subject)
	if role == "" {
		// The subject is gone, or revoked: the chain dies with it.
		return "", "", ErrLoginDenied
	}
	if revokeJTI != "" {
		if err := s.Store.RevokeJTI(ctx, revokeJTI,
			formatTime(time.Now().UTC().Add(AccessTTL))); err != nil {
			return "", "", err
		}
	}
	return s.MintSession(ctx, subject, role, scopes, AccessTTL)
}

// Logout ends a session: the refresh chain is deleted and the access token in
// hand is revoked. A password change uses the same call, which is why the
// `passwd` command also revokes the current token.
func (s *Sessions) Logout(ctx context.Context, subject, jti string) error {
	if subject == "" {
		return fmt.Errorf("signauth: logout needs a subject")
	}
	if _, err := s.Store.DeleteRefreshChain(ctx, subject); err != nil {
		return err
	}
	if jti != "" {
		return s.Store.RevokeJTI(ctx, jti, formatTime(time.Now().UTC().Add(AccessTTL)))
	}
	return nil
}

// roleAndScopes resolves a subject back to a role and a scope set. An admin
// carries the admin scope; a client's scopes come from its row, so a revoked
// client refreshes to nothing.
func (s *Sessions) roleAndScopes(ctx context.Context, subject string) (string, []string) {
	kind, id := SplitSubject(subject)
	switch kind {
	case RoleAdmin:
		// An admin carries every scope. The admin UI is the whole service, and
		// a scope set that has to be grown route by route ends up being a
		// formality that the admin worked around.
		return RoleAdmin, []string{ScopeAdminRead, ScopeEnvelopeRead, ScopeEnvelopeWrite}
	case RoleClient:
		rec, err := s.Store.GetClientByID(ctx, id)
		if err != nil || rec == nil || rec.RevokedAt != "" {
			return "", nil
		}
		return RoleClient, splitScopes(rec.Scopes)
	}
	return "", nil
}

// SplitScopes turns a stored scope string into the slice a token carries.
// Exported for the API layer, which stores scopes as a space-separated string.
func SplitScopes(s string) []string { return splitScopes(s) }

func splitScopes(s string) []string {
	// The stored form is space-separated, and a comma is accepted as well: a
	// scope list typed on the command line tends to be comma-separated, and a
	// reader that refuses "envelope:read,envelope:write" as one token would
	// grant nothing while the row looks correct.
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// formatTime is the timestamp format the store uses, duplicated here so this
// package does not import signstore for a formatter.
func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
