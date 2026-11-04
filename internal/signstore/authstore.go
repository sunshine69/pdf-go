package signstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Storage for the login state: refresh tokens, and the two facts the login
// path reads (an admin by address, a client by key).
//
// A refresh token is 256-bit random and stored as its SHA-256, for the same
// reason a signer link token is stored as a hash: a copied database must not
// be enough to authenticate. `consumed_at` is what makes it single-use, and
// spending a token and issuing its replacement happen in one transaction, so
// two concurrent requests cannot both spend the same token.

// RefreshToken is one row of a refresh chain.
type RefreshToken struct {
	Hash       string
	Subject    string
	CreatedAt  string
	ExpiresAt  string
	ConsumedAt string
}

// CreateRefresh inserts a refresh token for a subject. subject is the "sub"
// encoding the access token uses ("admin:7", "client:3"), so a chain can be
// dropped on logout, on a password change, or when a client is revoked.
func (s *Store) CreateRefresh(ctx context.Context, subject, hash, expiresAt string) error {
	if subject == "" || hash == "" || expiresAt == "" {
		return fmt.Errorf("signstore: refresh token needs subject, hash and expiry")
	}
	_, err := s.db.ExecContext(ctx,
		"insert into refresh_tokens(hash, subject, created_at, expires_at) values(?,?,?,?)",
		hash, subject, timeNow(), expiresAt)
	return err
}

// ConsumeRefresh spends a refresh token: the row is marked consumed and the
// owner of the chain is returned. The replacement token is inserted by the
// caller, after it knows the chain is still live.
//
// A hash that is unknown, already spent, or past its own deadline returns
// ErrNotFound. The caller must not learn which of the three it was: the answer
// is the same as the answer to a forged token. Spending the token before the
// chain is checked is deliberate: a chain that turns out to be revoked loses
// its last token on the way to being refused.
func (s *Store) ConsumeRefresh(ctx context.Context, hash string) (string, error) {
	if hash == "" {
		return "", ErrNotFound
	}
	var subject string
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		var spent, expires string
		err := tx.QueryRowContext(ctx,
			"select subject, coalesce(consumed_at, ''), expires_at from refresh_tokens where hash = ?",
			hash).Scan(&subject, &spent, &expires)
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if spent != "" || expires < timeNow() {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx,
			"update refresh_tokens set consumed_at = ? where hash = ?", timeNow(), hash); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return subject, nil
}

// DeleteRefreshChain drops every refresh token of a subject, which is how
// logout and a password change end a session: the access token in hand dies
// with its own expiry, and no new one can be minted.
func (s *Store) DeleteRefreshChain(ctx context.Context, subject string) (int, error) {
	res, err := s.db.ExecContext(ctx, "delete from refresh_tokens where subject = ?", subject)
	if err != nil {
		return 0, err
	}
	return rowsAffected(res), nil
}

// DeleteExpiredRefresh drops the chains whose own deadline has passed. Called
// by the sweep, so a device that was never seen again does not keep a row.
func (s *Store) DeleteExpiredRefresh(ctx context.Context, now string) (int, error) {
	res, err := s.db.ExecContext(ctx, "delete from refresh_tokens where expires_at < ?", now)
	if err != nil {
		return 0, err
	}
	return rowsAffected(res), nil
}

// Counts is the row count of every table the operator looks at, keyed by the
// table name. One round of queries, so the admin stats endpoint is one call.
func (s *Store) Counts(ctx context.Context) (map[string]int, error) {
	tables := []string{"envelopes", "parties", "revisions", "consents",
		"admins", "clients", "refresh_tokens", "revoked_jtis", "mail_queue", "batch_queue"}
	out := map[string]int{}
	for _, t := range tables {
		var n int
		// The table names are a constant list, not a parameter: there is no
		// user input in the statement.
		if err := s.db.QueryRowContext(ctx, "select count(*) from "+t).Scan(&n); err != nil {
			return nil, fmt.Errorf("signstore: count %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// CountRefresh reports the live and the consumed rows, for dbstatus.
func (s *Store) CountRefresh(ctx context.Context) (live, consumed int, err error) {
	err = s.db.QueryRowContext(ctx,
		"select count(*) from refresh_tokens where consumed_at is null and expires_at >= ?",
		timeNow()).Scan(&live)
	if err != nil {
		return 0, 0, err
	}
	err = s.db.QueryRowContext(ctx,
		"select count(*) from refresh_tokens where consumed_at is not null").Scan(&consumed)
	return live, consumed, err
}

// GetAdminByID reads an admin. Login uses it after the password is verified,
// so the subject the token carries is the row's own id.
func (s *Store) GetAdminByID(ctx context.Context, id string) (*Admin, error) {
	row := s.db.QueryRowContext(ctx,
		"select id, email, pw_hash, role, created_at, coalesce(last_login, '') "+
			"from admins where id = ?", id)
	var a Admin
	err := scanRow(row, &a.ID, &a.Email, &a.PWHash, &a.Role, &a.CreatedAt, &a.LastLogin)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// SetAdminPassword stores a new argon2id hash. It records the change time in
// the same statement: an access token minted before it is refused, which is
// what makes `signsrv admin passwd` end the sessions the password protected.
func (s *Store) SetAdminPassword(ctx context.Context, id int64, pwHash string) error {
	if pwHash == "" {
		return fmt.Errorf("signstore: admin password hash is empty")
	}
	res, err := s.db.ExecContext(ctx,
		"update admins set pw_hash = ?, pw_changed_at = ? where id = ?",
		pwHash, timeNow(), id)
	if err != nil {
		return err
	}
	return expectOne(res, "admin")
}

// AuthEpoch is the moment the credential behind a subject last stopped being
// valid, as a unix time; 0 when nothing has happened. An access token whose
// iat is before the epoch was minted under a credential that has since been
// replaced, and is refused.
//
// Two things set an epoch: a password change (admins.pw_changed_at), and a
// client revocation (clients.revoked_at). Both mean the same thing to the
// middleware — the token in hand must stop working — so the middleware has one
// check.
func (s *Store) AuthEpoch(ctx context.Context, subject string) (int64, error) {
	kind, id, ok := strings.Cut(subject, ":")
	if !ok {
		return 0, nil
	}
	var raw string
	switch kind {
	case "admin":
		err := s.db.QueryRowContext(ctx,
			"select coalesce(pw_changed_at, '') from admins where id = ?", id).Scan(&raw)
		if err == sql.ErrNoRows {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
	case "client":
		err := s.db.QueryRowContext(ctx,
			"select coalesce(revoked_at, '') from clients where id = ?", id).Scan(&raw)
		if err == sql.ErrNoRows {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
	default:
		return 0, nil
	}
	if raw == "" {
		return 0, nil
	}
	t, err := time.Parse(timeFormat, raw)
	if err != nil {
		return 0, fmt.Errorf("signstore: %s epoch %q: %w", kind, raw, err)
	}
	return t.Unix(), nil
}

// GetClientByID reads a machine client. A refresh of a client token re-reads
// the scopes, so revoking a client takes effect the next time its token is
// refreshed.
func (s *Store) GetClientByID(ctx context.Context, id string) (*Client, error) {
	row := s.db.QueryRowContext(ctx,
		"select id, name, key_hash, scopes, created_at, coalesce(revoked_at, '') "+
			"from clients where id = ?", id)
	var c Client
	err := scanRow(row, &c.ID, &c.Name, &c.KeyHash, &c.Scopes, &c.CreatedAt, &c.RevokedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
