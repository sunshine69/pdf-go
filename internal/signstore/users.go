package signstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Users: one account per operator and per machine caller. See schema_v5.go for
// why password is a hash and jwt_secret is not.

// ErrDuplicateUsername is returned when a username is taken. The HTTP layer
// answers a create that collides the same way it answers any other rejected
// name: a taken username is information about who is on the system.
var ErrDuplicateUsername = errors.New("signstore: username taken")

// User is one row of users. JWTSecret is returned by a create (the secret is
// shown once, like a client key) and by the two lookups used for verification;
// ListUsers never selects it, so the secret cannot leave through the admin
// list.
type User struct {
	ID          int64
	Username    string
	Password    string
	JWTSecret   string
	Scopes      string
	Role        string
	CreatedAt   string
	LastLogin   string
	PWChangedAt string
	RevokedAt   string

	// HasPassword and HasSecret are set only by ListUsers, which selects the
	// presence of each credential and never its value. A list of accounts is
	// something an operator reads every day; the secrets are something only the
	// two code paths that verify a credential ever need.
	HasPassword bool
	HasSecret   bool
}

// NewJWTSecret returns a 256-bit secret as URL-safe base64 without padding —
// the same encoding as an opaque token. It is the string a caller is given;
// the row stores it verbatim, because the server needs it to verify HMAC.
func NewJWTSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("signstore: no randomness")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DefaultUserScopes is what a row grants when the caller names nothing.
const DefaultUserScopes = "envelope:read,envelope:write"

// AddUser inserts a row and returns the id. The username is normalised by the
// caller, not here: what counts as a legal login name is the input layer's
// business, and this function is also used by the migration backfill.
func (s *Store) AddUser(ctx context.Context, username, passwordHash, jwtSecret, scopes, role string) (int64, error) {
	if role == "" {
		role = "user"
	}
	if scopes == "" {
		scopes = DefaultUserScopes
	}
	res, err := s.db.ExecContext(ctx,
		"insert into users(username, password, jwt_secret, scopes, role, created_at, pw_changed_at)"+
			" values(?,?,?,?,?,?,?)",
		username, passwordHash, jwtSecret, scopes, role, timeNow(), timeNow())
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrDuplicateUsername
		}
		return 0, err
	}
	return res.LastInsertId()
}

// userColumns is the full row, including the secret. The column named in %s is
// chosen by this file and never by a caller, so the format is safe: the two
// calls below pass "username" and "id", and both are indexed.
const userColumns = "select id, username, password, jwt_secret, scopes, role, created_at," +
	" last_login, pw_changed_at, revoked_at from users where %s = ?"

// GetByUsername reads a row, for login and for the HS256 verification path.
// The lookup uses the UNIQUE index on username. The secret, the scopes and
// revoked_at come from this row, so revoking a user takes effect on its next
// request: there is no token state to expire.
func (s *Store) GetByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, fmt.Sprintf(userColumns, "username"), username))
}

// GetUserByID reads a row by id, for the rotate and revoke endpoints.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, fmt.Sprintf(userColumns, "id"), id))
}

// ListUsers answers the admin list. password and jwt_secret are not selected:
// the list is rendered in a browser, and a secret that can be listed is a
// secret that leaks.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	// The presence of the two credentials is selected as a boolean, not the
	// values: a list that reports "this row has a secret" is useful, and a list
	// that carries the secrets is a breach waiting for a token to leak.
	rows, err := s.db.QueryContext(ctx,
		"select id, username, scopes, role, created_at, last_login, revoked_at,"+
			" password <> '', jwt_secret <> '' from users order by id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		var hasPW, hasSecret bool
		if err := scanRow(rows, &u.ID, &u.Username, &u.Scopes, &u.Role,
			&u.CreatedAt, &u.LastLogin, &u.RevokedAt, &hasPW, &hasSecret); err != nil {
			return nil, err
		}
		u.HasPassword = hasPW
		u.HasSecret = hasSecret
		out = append(out, u)
	}
	return out, rows.Err()
}

// RotateJWTSecret replaces the secret and returns the new one. The old secret
// stops verifying immediately, because verification reads the row and the row
// now holds a different string. This is the "that laptop is gone" action, and
// it needs no restart.
func (s *Store) RotateJWTSecret(ctx context.Context, id int64) (string, error) {
	secret, err := NewJWTSecret()
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx, "update users set jwt_secret = ? where id = ?", secret, id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return secret, nil
}

// RotateJWTSecretByUsername is the CLI shape of a rotation: the operator knows
// the username, not the id. The new secret is generated here and returned, so
// the caller prints it exactly once.
func (s *Store) RotateJWTSecretByUsername(ctx context.Context, username string) (*User, string, error) {
	u, err := s.GetByUsername(ctx, username)
	if err != nil {
		return nil, "", err
	}
	secret, err := s.RotateJWTSecret(ctx, u.ID)
	if err != nil {
		return nil, "", err
	}
	u.JWTSecret = secret
	return u, secret, nil
}

// RevokeUserByUsername is the CLI shape of a revocation. The row is read again
// after the stamp, so what the caller gets back is the row as it now is: a
// returned row with an empty revoked_at would tell an operator the account is
// open, in the same breath as the command closed it.
func (s *Store) RevokeUserByUsername(ctx context.Context, username string) (*User, error) {
	u, err := s.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if err := s.RevokeUser(ctx, u.ID); err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, u.ID)
}

// RevokeUser stamps revoked_at. Both doors then refuse the row: the
// verification lookup, and the credential-epoch check.
func (s *Store) RevokeUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		"update users set revoked_at = ? where id = ? and revoked_at is null", timeNow(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserPassword replaces the password and stamps pw_changed_at, so a token
// minted before the stamp stops working at its next epoch check. The web
// portal's "change my password" is this function.
func (s *Store) SetUserPassword(ctx context.Context, id int64, passwordHash string) error {
	res, err := s.db.ExecContext(ctx,
		"update users set password = ?, pw_changed_at = ? where id = ?", passwordHash, timeNow(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchUserLastLogin records the moment a login succeeded.
func (s *Store) TouchUserLastLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "update users set last_login = ? where id = ?", timeNow(), id)
	return err
}

// SetUserScopes replaces the scopes of a row. The guard takes scopes from the
// row, not from the claims, so the change applies to a token already in hand.
func (s *Store) SetUserScopes(ctx context.Context, id int64, scopes string) error {
	res, err := s.db.ExecContext(ctx, "update users set scopes = ? where id = ?", scopes, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanUser(row rowScanner) (*User, error) {
	u := &User{}
	err := scanRow(row, &u.ID, &u.Username, &u.Password, &u.JWTSecret, &u.Scopes, &u.Role,
		&u.CreatedAt, &u.LastLogin, &u.PWChangedAt, &u.RevokedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// isUniqueViolation recognises SQLite's UNIQUE failure. The driver reports it
// as a plain error string, and the callers that care are the ones that offer a
// name into a UNIQUE column.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// unixTime turns a stored timestamp into seconds. An empty stamp is 0, which
// the epoch check reads as "no epoch".
func unixTime(stamp string) (int64, error) {
	if stamp == "" {
		return 0, nil
	}
	t, err := time.Parse(timeFormat, stamp)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// ScopeList splits a stored scope string into the names it grants. "a,b"
// grants two; "" grants none.
func ScopeList(scopes string) []string {
	parts := strings.FieldsFunc(scopes, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
