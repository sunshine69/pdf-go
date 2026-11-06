package signstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotFound is returned by every read that found no row. Callers compare
// with errors.Is.
var ErrNotFound = errors.New("signstore: not found")

// MaxPDFBytes and MaxBlobBytes bound what the store accepts. They are
// enforced here as well as at the HTTP layer, so a bug in a handler cannot
// write an unbounded file.
const (
	MaxPDFBytes  = 50 << 20
	MaxBlobBytes = 1 << 20
)

// Open opens the database, creating the file if needed, with the pragmas the
// service relies on: WAL for reader/writer coexistence, foreign keys so the
// ON DELETE CASCADE rules work, and a busy timeout so the worker and the API
// do not fail on a momentary lock.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("signstore: create db dir: %w", err)
		}
	}
	// _txlock(immediate) makes every BEGIN take the write lock at once, so
	// the state machine's transactions cannot start concurrently and then
	// discover they are both allowed to advance the same envelope.
	dsn := "file:" + path + "?_txlock(immediate)&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("signstore: open: %w", err)
	}
	// One writer, so the service never has to resolve its own write
	// conflicts. Reads share the connection; SQLite serialises them.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("signstore: ping: %w", err)
	}
	return db, nil
}

// Store is the persistence layer. It owns the database handle and the
// content-addressed file store.
type Store struct {
	db         *sql.DB
	storageDir string
}

// NewStore returns a store over an open database, with the directory that
// holds PDF revisions and consent images.
func NewStore(db *sql.DB, storageDir string) *Store {
	return &Store{db: db, storageDir: storageDir}
}

// DB exposes the handle for migrations and tests. Queries from outside the
// store are a signstore bug: all SQL lives in this package.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Tx runs fn inside a transaction, committing when it returns nil.
func (s *Store) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---------- envelopes ----------

const envelopeCols = "id, title, status, template_sha, filled_sha, current_sha, serial," +
	" created_by, created_at, updated_at, expires_at, sent_at, delivered_at, cancelled_at"

// CreateEnvelope inserts a new envelope. Status is validated; the allowed
// transitions are checked by signflow, not here.
func (s *Store) CreateEnvelope(ctx context.Context, e *Envelope) error {
	if !e.Status.valid() {
		return fmt.Errorf("signstore: envelope status %q", e.Status)
	}
	if len(e.ID) != 32 {
		return fmt.Errorf("signstore: envelope id must be 32 hex characters")
	}
	if e.CreatedAt == "" {
		e.CreatedAt = timeNow()
	}
	e.UpdatedAt = timeNow()
	_, err := s.db.ExecContext(ctx,
		"insert into envelopes("+envelopeCols+") values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		e.ID, e.Title, string(e.Status), e.TemplateSHA, e.FilledSHA, e.CurrentSHA, e.Serial,
		createdBy(e.CreatedBy), e.CreatedAt, e.UpdatedAt, e.ExpiresAt,
		e.SentAt, e.DeliveredAt, e.CancelledAt)
	return err
}

// createdBy writes NULL when there is no creator row, so "no admin created
// this" is stored as SQL NULL and not as the integer 0.
func createdBy(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// GetEnvelope reads one envelope.
func (s *Store) GetEnvelope(ctx context.Context, id string) (*Envelope, error) {
	row := s.db.QueryRowContext(ctx, "select "+envelopeCols+" from envelopes where id = ?", id)
	return scanEnvelope(row)
}

// UpdateEnvelope writes the mutable columns of an envelope. updated_at is
// always refreshed.
func (s *Store) UpdateEnvelope(ctx context.Context, e *Envelope) error {
	if !e.Status.valid() {
		return fmt.Errorf("signstore: envelope status %q", e.Status)
	}
	res, err := s.db.ExecContext(ctx,
		`update envelopes set title = ?, status = ?, template_sha = ?, filled_sha = ?,
		 current_sha = ?, serial = ?, updated_at = ?, expires_at = ?,
		 sent_at = ?, delivered_at = ?, cancelled_at = ?
		 where id = ?`,
		e.Title, string(e.Status), e.TemplateSHA, e.FilledSHA, e.CurrentSHA, e.Serial,
		timeNow(), e.ExpiresAt, e.SentAt, e.DeliveredAt, e.CancelledAt, e.ID)
	if err != nil {
		return err
	}
	return expectOne(res, "envelope "+e.ID)
}

// UpdateEnvelopeStatus is the narrow write used by the state machine: it
// changes the status and one timestamp in a single statement, so a crash
// cannot leave a new status with the old timestamp.
func (s *Store) UpdateEnvelopeStatus(ctx context.Context, id string, status EnvelopeStatus, stampCol string) error {
	if !status.valid() {
		return fmt.Errorf("signstore: envelope status %q", status)
	}
	switch stampCol {
	case "", "sent_at", "delivered_at", "cancelled_at":
	default:
		return fmt.Errorf("signstore: envelope timestamp column %q", stampCol)
	}
	now := timeNow()
	q := "update envelopes set status = ?, updated_at = ?"
	args := []any{string(status), now}
	if stampCol != "" {
		q += ", " + stampCol + " = ?"
		args = append(args, now)
	}
	q += " where id = ?"
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	return expectOne(res, "envelope "+id)
}

// SetEnvelopeCurrentSHA points an envelope at the document it currently holds.
// The batch writes it after every signature, so the download endpoint and the
// report always agree on which bytes are the document.
func (s *Store) SetEnvelopeCurrentSHA(ctx context.Context, id, sha string) error {
	if sha == "" {
		return fmt.Errorf("signstore: empty document hash")
	}
	res, err := s.db.ExecContext(ctx,
		"update envelopes set current_sha = ?, updated_at = ? where id = ?", sha, timeNow(), id)
	if err != nil {
		return err
	}
	return expectOne(res, "envelope "+id)
}

// scanRow reads a row, mapping a NULL in a text column to the empty string.
// Every nullable column in the schema is a plain string in the model, so a
// direct Scan of NULL fails with "converting NULL to string is unsupported".
// This is the one place that knows the mapping, so no query has to write
// `coalesce(...)`.
func scanRow(r rowScanner, cols ...any) error {
	vals := make([]any, len(cols))
	nulls := make([]sql.NullString, len(cols))
	nullInts := make([]sql.NullInt64, len(cols))
	for i, c := range cols {
		switch c.(type) {
		case *string:
			vals[i] = &nulls[i]
		case *int64:
			vals[i] = &nullInts[i]
		default:
			vals[i] = c
		}
	}
	if err := r.Scan(vals...); err != nil {
		return err
	}
	for i, c := range cols {
		switch p := c.(type) {
		case *string:
			*p = nulls[i].String
		case *int64:
			*p = nullInts[i].Int64
		}
	}
	return nil
}

func scanEnvelope(r rowScanner) (*Envelope, error) {
	var e Envelope
	var status string
	err := scanRow(r, &e.ID, &e.Title, &status, &e.TemplateSHA, &e.FilledSHA, &e.CurrentSHA,
		&e.Serial, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt, &e.ExpiresAt,
		&e.SentAt, &e.DeliveredAt, &e.CancelledAt)
	e.Status = EnvelopeStatus(status)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// rowScanner is the shared shape of *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// ---------- parties ----------

const partyCols = "id, envelope_id, order_idx, email, name, status, token_hash," +
	" token_expires_at, claim_at, consent_at, delivered_at, session_hash, reason"

// CreateParty inserts a party. A duplicate (envelope_id, email) or
// (envelope_id, order_idx) is returned as an error; the UNIQUE constraints
// enforce it in the database.
func (s *Store) CreateParty(ctx context.Context, p *Party) error {
	if !p.Status.valid() {
		return fmt.Errorf("signstore: party status %q", p.Status)
	}
	if p.OrderIdx < 1 {
		return fmt.Errorf("signstore: party order_idx must start at 1")
	}
	if p.TokenExpires == "" {
		return fmt.Errorf("signstore: party token_expires_at is required")
	}
	_, err := s.db.ExecContext(ctx,
		"insert into parties("+partyCols+") values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
		p.ID, p.EnvelopeID, p.OrderIdx, p.Email, p.Name, string(p.Status), p.TokenHash,
		p.TokenExpires, p.ClaimAt, p.ConsentAt, p.DeliveredAt, p.SessionHash, p.Reason)
	return err
}

// ListParties returns the parties of an envelope in signing order.
func (s *Store) ListParties(ctx context.Context, envelopeID string) ([]Party, error) {
	rows, err := s.db.QueryContext(ctx,
		"select "+partyCols+" from parties where envelope_id = ? order by order_idx", envelopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Party{}
	for rows.Next() {
		var p Party
		if err := scanRow(rows, &p.ID, &p.EnvelopeID, &p.OrderIdx, &p.Email, &p.Name, &p.Status,
			&p.TokenHash, &p.TokenExpires, &p.ClaimAt, &p.ConsentAt, &p.DeliveredAt,
			&p.SessionHash, &p.Reason); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetParty reads one party.
func (s *Store) GetParty(ctx context.Context, id string) (*Party, error) {
	row := s.db.QueryRowContext(ctx, "select "+partyCols+" from parties where id = ?", id)
	var p Party
	err := scanRow(row, &p.ID, &p.EnvelopeID, &p.OrderIdx, &p.Email, &p.Name, &p.Status,
		&p.TokenHash, &p.TokenExpires, &p.ClaimAt, &p.ConsentAt, &p.DeliveredAt,
		&p.SessionHash, &p.Reason)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPartyByTokenHash resolves a signing link. The caller compares the hash
// of the presented token with parties.token_hash; the raw token is never
// stored. A token of a cancelled or expired envelope resolves here and is
// rejected by the state machine, keeping the token lookup a single index hit.
func (s *Store) GetPartyByTokenHash(ctx context.Context, hash string) (*Party, error) {
	if hash == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, "select "+partyCols+" from parties where token_hash = ?", hash)
	var p Party
	err := scanRow(row, &p.ID, &p.EnvelopeID, &p.OrderIdx, &p.Email, &p.Name, &p.Status,
		&p.TokenHash, &p.TokenExpires, &p.ClaimAt, &p.ConsentAt, &p.DeliveredAt,
		&p.SessionHash, &p.Reason)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPartyBySessionHash resolves the party a session cookie belongs to. The
// cookie carries the random value, the database keeps only its SHA-256, so a
// copied database cannot be used to sign.
func (s *Store) GetPartyBySessionHash(ctx context.Context, hash string) (*Party, error) {
	if hash == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, "select "+partyCols+" from parties where session_hash = ?", hash)
	var p Party
	err := scanRow(row, &p.ID, &p.EnvelopeID, &p.OrderIdx, &p.Email, &p.Name, &p.Status,
		&p.TokenHash, &p.TokenExpires, &p.ClaimAt, &p.ConsentAt, &p.DeliveredAt,
		&p.SessionHash, &p.Reason)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdatePartyStatus changes a party's status and one timestamp. reason is
// written when non-empty (decline reason, expiry note).
func (s *Store) UpdatePartyStatus(ctx context.Context, id string, status PartyStatus, stampCol string, reason string) error {
	if !status.valid() {
		return fmt.Errorf("signstore: party status %q", status)
	}
	switch stampCol {
	case "", "claim_at", "consent_at", "delivered_at":
	default:
		return fmt.Errorf("signstore: party timestamp column %q", stampCol)
	}
	q := "update parties set status = ?"
	args := []any{string(status)}
	if stampCol != "" {
		q += ", " + stampCol + " = ?"
		args = append(args, timeNow())
	}
	if reason != "" {
		q += ", reason = ?" + fmt.Sprint(len(args)+1)
		args = append(args, reason)
	}
	q += " where id = ?"
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	return expectOne(res, "party "+id)
}

// SetPartyToken sets or replaces a party's signing token hash and its
// expiry. Reissuing a link uses this: the old hash stops resolving.
func (s *Store) SetPartyToken(ctx context.Context, id, hash, expiresAt string) error {
	if hash == "" || expiresAt == "" {
		return fmt.Errorf("signstore: party token hash and expiry are required")
	}
	res, err := s.db.ExecContext(ctx,
		"update parties set token_hash = ?, token_expires_at = ? where id = ?",
		hash, expiresAt, id)
	if err != nil {
		return err
	}
	return expectOne(res, "party "+id)
}

// SetPartySession records the hash of the short session cookie issued after
// a successful claim, so the link's claim and its consent POST are tied to
// the same browser.
func (s *Store) SetPartySession(ctx context.Context, id, sessionHash string) error {
	res, err := s.db.ExecContext(ctx,
		"update parties set session_hash = ? where id = ?", sessionHash, id)
	if err != nil {
		return err
	}
	return expectOne(res, "party "+id)
}

// CountPartiesByStatus counts parties of an envelope in a status.
func (s *Store) CountPartiesByStatus(ctx context.Context, envelopeID string) (total int, consented int, declined int, err error) {
	err = s.db.QueryRowContext(ctx,
		`select count(*),
		        coalesce(sum(case when status = 'consented' then 1 else 0 end), 0),
		        coalesce(sum(case when status = 'declined'  then 1 else 0 end), 0)
		 from parties where envelope_id = ?`, envelopeID).Scan(&total, &consented, &declined)
	return total, consented, declined, err
}

// ---------- revisions ----------

const revisionCols = "id, envelope_id, sha256, prev_id, kind, sig_field, party_id," +
	" cert_serial, cert_fingerprint, produced_by, size, created_at"

// AddRevision records a PDF that is already in storage.
func (s *Store) AddRevision(ctx context.Context, r *Revision) error {
	if r.SHA256 == "" {
		return fmt.Errorf("signstore: revision sha256 is required")
	}
	if r.CreatedAt == "" {
		r.CreatedAt = timeNow()
	}
	_, err := s.db.ExecContext(ctx,
		"insert into revisions("+revisionCols+") values(?,?,?,?,?,?,?,?,?,?,?,?)",
		r.ID, r.EnvelopeID, r.SHA256, r.PrevID, r.Kind, r.SigField, r.PartyID,
		r.CertSerial, r.CertFingerprint, r.ProducedBy, r.Size, r.CreatedAt)
	return err
}

// ListRevisions returns the revisions of an envelope in creation order: the
// audit chain, template to final document.
func (s *Store) ListRevisions(ctx context.Context, envelopeID string) ([]Revision, error) {
	rows, err := s.db.QueryContext(ctx,
		"select "+revisionCols+" from revisions where envelope_id = ? order by created_at, rowid", envelopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Revision{}
	for rows.Next() {
		var r Revision
		if err := scanRow(rows, &r.ID, &r.EnvelopeID, &r.SHA256, &r.PrevID, &r.Kind, &r.SigField,
			&r.PartyID, &r.CertSerial, &r.CertFingerprint, &r.ProducedBy, &r.Size, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRevision reads one revision by its id. The caller must check the
// envelope_id: a revision id from another envelope must not be served.
func (s *Store) GetRevision(ctx context.Context, id string) (*Revision, error) {
	row := s.db.QueryRowContext(ctx, "select "+revisionCols+" from revisions where id = ?", id)
	var r Revision
	err := scanRow(row, &r.ID, &r.EnvelopeID, &r.SHA256, &r.PrevID, &r.Kind, &r.SigField,
		&r.PartyID, &r.CertSerial, &r.CertFingerprint, &r.ProducedBy, &r.Size, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetRevisionOfEnvelope finds the revision of one envelope by the hash of its
// bytes. The hash alone is not unique across envelopes: two envelopes built
// from the same template share the template bytes, so the lookup is scoped.
func (s *Store) GetRevisionOfEnvelope(ctx context.Context, envelopeID, sha string) (*Revision, error) {
	row := s.db.QueryRowContext(ctx,
		"select "+revisionCols+" from revisions where envelope_id = ? and sha256 = ?", envelopeID, sha)
	var r Revision
	err := scanRow(row, &r.ID, &r.EnvelopeID, &r.SHA256, &r.PrevID, &r.Kind, &r.SigField,
		&r.PartyID, &r.CertSerial, &r.CertFingerprint, &r.ProducedBy, &r.Size, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetRevisionBySHA looks a revision up by the hash of its bytes.
func (s *Store) GetRevisionBySHA(ctx context.Context, sha string) (*Revision, error) {
	row := s.db.QueryRowContext(ctx, "select "+revisionCols+" from revisions where sha256 = ?", sha)
	var r Revision
	err := scanRow(row, &r.ID, &r.EnvelopeID, &r.SHA256, &r.PrevID, &r.Kind, &r.SigField,
		&r.PartyID, &r.CertSerial, &r.CertFingerprint, &r.ProducedBy, &r.Size, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------- consents ----------

const consentCols = "id, party_id, envelope_id, signature_text, document_sha," +
	" image_sha, appearance_json, consent_at, ip, user_agent"

// AddConsent records the consent of a party. The UNIQUE constraint on
// party_id means a second consent for the same party fails here, which is
// the point: one consent per party, enforced by the schema.
func (s *Store) AddConsent(ctx context.Context, c *Consent) error {
	if c.ConsentAt == "" {
		c.ConsentAt = timeNow()
	}
	_, err := s.db.ExecContext(ctx,
		"insert into consents("+consentCols+") values(?,?,?,?,?,?,?,?,?,?)",
		c.ID, c.PartyID, c.EnvelopeID, c.SignatureText, c.DocumentSHA, c.ImageSHA,
		c.Appearance, c.ConsentAt, c.IP, c.UserAgent)
	return err
}

// GetConsentByParty reads the consent of a party.
func (s *Store) GetConsentByParty(ctx context.Context, partyID string) (*Consent, error) {
	row := s.db.QueryRowContext(ctx, "select "+consentCols+" from consents where party_id = ?", partyID)
	var c Consent
	err := scanRow(row, &c.ID, &c.PartyID, &c.EnvelopeID, &c.SignatureText, &c.DocumentSHA,
		&c.ImageSHA, &c.Appearance, &c.ConsentAt, &c.IP, &c.UserAgent)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListConsents returns every consent of an envelope, in signing order.
func (s *Store) ListConsents(ctx context.Context, envelopeID string) ([]Consent, error) {
	rows, err := s.db.QueryContext(ctx,
		"select "+consentCols+" from consents where envelope_id = ? order by rowid", envelopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Consent{}
	for rows.Next() {
		var c Consent
		if err := scanRow(rows, &c.ID, &c.PartyID, &c.EnvelopeID, &c.SignatureText, &c.DocumentSHA,
			&c.ImageSHA, &c.Appearance, &c.ConsentAt, &c.IP, &c.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- admins, clients, revoked jtis ----------

// AddAdmin inserts an admin. pwHash must be an argon2id encoding; the store
// never sees a plaintext password.
func (s *Store) AddAdmin(ctx context.Context, email, pwHash, role string) (int64, error) {
	if role == "" {
		role = "admin"
	}
	res, err := s.db.ExecContext(ctx,
		"insert into admins(email, pw_hash, role, created_at) values(?,?,?,?)",
		email, pwHash, role, timeNow())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetAdminByEmail reads an admin.
func (s *Store) GetAdminByEmail(ctx context.Context, email string) (*Admin, error) {
	row := s.db.QueryRowContext(ctx,
		"select id, email, pw_hash, role, created_at, coalesce(last_login, '') from admins where email = ?", email)
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

// TouchAdminLogin records a successful login.
func (s *Store) TouchAdminLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "update admins set last_login = ? where id = ?", timeNow(), id)
	return err
}

// ListAdmins returns every admin.
func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := s.db.QueryContext(ctx,
		"select id, email, role, created_at, coalesce(last_login, '') from admins order by id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Admin{}
	for rows.Next() {
		var a Admin
		if err := scanRow(rows, &a.ID, &a.Email, &a.Role, &a.CreatedAt, &a.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddClient inserts a machine API client. keyHash is a SHA-256 of the key
// that is printed once to the operator.
func (s *Store) AddClient(ctx context.Context, name, keyHash, scopes string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		"insert into clients(name, key_hash, scopes, created_at) values(?,?,?,?)",
		name, keyHash, scopes, timeNow())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetClientByKeyHash resolves an API key.
func (s *Store) GetClientByKeyHash(ctx context.Context, hash string) (*Client, error) {
	if hash == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		"select id, name, key_hash, scopes, created_at, coalesce(revoked_at, '') from clients where key_hash = ?", hash)
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

// ListClients returns every client, with the key hash exposed: it is not a
// secret, it is an identifier of a credential the operator already holds.
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx,
		"select id, name, key_hash, scopes, created_at, coalesce(revoked_at, '') from clients order by id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		if err := scanRow(rows, &c.ID, &c.Name, &c.KeyHash, &c.Scopes, &c.CreatedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeClient marks a client revoked and expires its live tokens.
func (s *Store) RevokeClient(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		"update clients set revoked_at = ? where id = ? and revoked_at is null",
		timeNow(), id)
	if err != nil {
		return err
	}
	return expectOne(res, "client")
}

// RevokeJTI records a token identifier that must stop validating before its
// natural expiry.
func (s *Store) RevokeJTI(ctx context.Context, jti, expiresAt string) error {
	_, err := s.db.ExecContext(ctx,
		"insert into revoked_jtis(jti, expires_at) values(?,?) on conflict(jti) do nothing",
		jti, expiresAt)
	return err
}

// IsJTIRevoked reports whether a token identifier was revoked.
func (s *Store) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "select count(*) from revoked_jtis where jti = ?", jti).Scan(&n)
	return n > 0, err
}

// ---------- queues ----------

// EnqueueBatch asks the worker to run the signing batch of an envelope.
// Re-enqueueing resets the lease and keeps the attempt count, so a batch
// that keeps failing keeps its backoff.
func (s *Store) EnqueueBatch(ctx context.Context, envelopeID string, nextAt string) error {
	if nextAt == "" {
		nextAt = timeNow()
	}
	_, err := s.db.ExecContext(ctx,
		`insert into batch_queue(envelope_id, attempts, next_at, enqueued_at)
		 values(?, 0, ?, ?)
		 on conflict(envelope_id) do update set next_at = excluded.next_at, lease_until = null`,
		envelopeID, nextAt, timeNow())
	return err
}

// CountBatchQueue reports how many signing batches are waiting. The worker
// logs it, and it is the number an operator reads when an envelope is stuck:
// a row here means a batch is queued and not yet run.
func (s *Store) CountBatchQueue(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, "select count(*) from batch_queue").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ClaimBatch takes the lease on one due batch, incrementing its attempt
// count. Returns ErrNotFound when nothing is due. The worker must finish with
// CompleteBatch (success) or RequeueBatch (failure, with a backoff); a lease
// left behind is picked up again by the sweep once it expires.
func (s *Store) ClaimBatch(ctx context.Context, lease time.Duration) (*BatchItem, error) {
	now := timeNow()
	until := formatTime(time.Now().UTC().Add(lease))
	var b BatchItem
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx,
			`select envelope_id from batch_queue
			 where next_at <= ? and (lease_until is null or lease_until < ?)
			 order by enqueued_at limit 1`,
			now, now).Scan(&id)
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"update batch_queue set lease_until = ?, attempts = attempts + 1 where envelope_id = ?",
			until, id); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			"select envelope_id, attempts, next_at, lease_until, enqueued_at"+
				" from batch_queue where envelope_id = ?",
			id).Scan(&b.EnvelopeID, &b.Attempts, &b.NextAt, &b.LeaseUntil, &b.EnqueuedAt)
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ClaimBatchFor claims one envelope's batch row. It is the operator's path:
// "sign this document now" is about a specific envelope, so the claim is on
// that row and not on whatever the queue happens to hold first. A row another
// process holds under a live lease is not taken (ErrNotFound), so two
// processes cannot sign the same document.
func (s *Store) ClaimBatchFor(ctx context.Context, envelopeID string, lease time.Duration) (*BatchItem, error) {
	until := formatTime(time.Now().UTC().Add(lease))
	var b BatchItem
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		var has bool
		err := tx.QueryRowContext(ctx,
			`select (lease_until is null or lease_until < ?) from batch_queue where envelope_id = ?`,
			until, envelopeID).Scan(&has)
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !has {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx,
			"update batch_queue set lease_until = ?, attempts = attempts + 1 where envelope_id = ?",
			until, envelopeID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			"select envelope_id, attempts, next_at, lease_until, enqueued_at"+
				" from batch_queue where envelope_id = ?",
			envelopeID).Scan(&b.EnvelopeID, &b.Attempts, &b.NextAt, &b.LeaseUntil, &b.EnqueuedAt)
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) CompleteBatch(ctx context.Context, envelopeID string) error {
	_, err := s.db.ExecContext(ctx, "delete from batch_queue where envelope_id = ?", envelopeID)
	return err
}

// RequeueBatch releases the lease of a batch that failed and pushes its next
// attempt back by delay (backoff).
func (s *Store) RequeueBatch(ctx context.Context, envelopeID string, delay time.Duration) error {
	next := formatTime(time.Now().UTC().Add(delay))
	res, err := s.db.ExecContext(ctx,
		"update batch_queue set lease_until = null, next_at = ? where envelope_id = ?",
		next, envelopeID)
	if err != nil {
		return err
	}
	return expectOne(res, "batch "+envelopeID)
}

// EnqueueMail adds a message to the mail queue.
// QueueBacklog is the queue depth an operator watches: how many rows are
// waiting, how many are in flight under a lease, and how late the oldest
// waiting row is. The counts exclude each other: a row is either waiting or
// leased, so the two add up to the queue's size.
type QueueBacklog struct {
	MailWaiting   int `json:"mail_waiting"`
	MailClaimed   int `json:"mail_claimed"`
	MailOldest    int `json:"mail_oldest_seconds"`
	BatchWaiting  int `json:"batch_waiting"`
	BatchClaimed  int `json:"batch_claimed"`
	BatchOldest   int `json:"batch_oldest_seconds"`
	BatchFailures int `json:"batch_failures"`
}

func (s *Store) queuedBacklog(ctx context.Context, table string) (waiting, claimed, oldest, failures int, err error) {
	if err := s.db.QueryRowContext(ctx,
		"select count(*) from "+table+" where lease_until is null or lease_until < ?", timeNow()).Scan(&waiting); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("signstore: %s waiting count: %w", table, err)
	}
	if err := s.db.QueryRowContext(ctx,
		"select count(*) from "+table+" where lease_until is not null and lease_until >= ?", timeNow()).Scan(&claimed); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("signstore: %s claimed count: %w", table, err)
	}
	// The oldest wait is computed in Go, not in SQL: the timestamps are RFC3339
	// text and the store's own parser is the only thing that knows their shape.
	var oldestAt sql.NullString
	err = s.db.QueryRowContext(ctx, "select min(next_at) from "+table).Scan(&oldestAt)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("signstore: %s oldest read: %w", table, err)
	}
	if oldestAt.String != "" {
		if at, err := parseTime(oldestAt.String); err == nil {
			if wait := time.Now().UTC().Sub(at); wait > 0 {
				oldest = int(wait.Seconds())
			}
		}
	}
	if err := s.db.QueryRowContext(ctx,
		"select coalesce(max(attempts), 0) from "+table).Scan(&failures); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("signstore: %s attempts read: %w", table, err)
	}
	return waiting, claimed, oldest, failures, nil
}

// QueueBacklog reads the depth of both queues in one round of queries.
func (s *Store) QueueBacklog(ctx context.Context) (*QueueBacklog, error) {
	out := &QueueBacklog{}
	var err error
	out.MailWaiting, out.MailClaimed, out.MailOldest, _, err = s.queuedBacklog(ctx, "mail_queue")
	if err != nil {
		return nil, err
	}
	out.BatchWaiting, out.BatchClaimed, out.BatchOldest, out.BatchFailures, err = s.queuedBacklog(ctx, "batch_queue")
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) EnqueueMail(ctx context.Context, envelopeID, partyID, kind, sha256 string) error {
	_, err := s.db.ExecContext(ctx,
		"insert into mail_queue(envelope_id, party_id, kind, sha256, next_at) values(?,?,?,?,?)",
		envelopeID, partyID, kind, sha256, timeNow())
	return err
}

// ClaimMail takes the lease on one unsent message.
const mailCols = "id, envelope_id, party_id, kind, coalesce(sha256, ''), attempts," +
	" next_at, coalesce(lease_until, ''), coalesce(sent_at, ''), coalesce(last_error, '')"

// ClaimMail takes the lease on one unsent message, incrementing its attempt
// count. ErrNotFound when nothing is due. The worker finishes with
// MarkMailSent or MarkMailFailed; an abandoned lease is released by Sweep.
func (s *Store) ClaimMail(ctx context.Context, lease time.Duration) (*MailItem, error) {
	now := timeNow()
	until := formatTime(time.Now().UTC().Add(lease))
	var m MailItem
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx,
			`select id from mail_queue where sent_at is null and next_at <= ?
			 and (lease_until is null or lease_until < ?) order by id limit 1`,
			now, now).Scan(&id)
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"update mail_queue set lease_until = ?, attempts = attempts + 1 where id = ?",
			until, id); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			"select "+mailCols+" from mail_queue where id = ?", id).
			Scan(&m.ID, &m.EnvelopeID, &m.PartyID, &m.Kind, &m.SHA256, &m.Attempts,
				&m.NextAt, &m.LeaseUntil, &m.SentAt, &m.LastError)
	})
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ClaimMailFor takes the lease on one unsent message of one envelope. The
// scoped form is what a send uses: draining a send must not pick up a row of
// another envelope, which a global claim would do and then have to release.
func (s *Store) ClaimMailFor(ctx context.Context, envelopeID string, lease time.Duration) (*MailItem, error) {
	now := timeNow()
	until := formatTime(time.Now().UTC().Add(lease))
	var m MailItem
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx,
			`select id from mail_queue where sent_at is null and envelope_id = ?
			 and next_at <= ? and (lease_until is null or lease_until < ?)
			 order by id limit 1`,
			envelopeID, now, now).Scan(&id)
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"update mail_queue set lease_until = ?, attempts = attempts + 1 where id = ?",
			until, id); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			"select "+mailCols+" from mail_queue where id = ?", id).
			Scan(&m.ID, &m.EnvelopeID, &m.PartyID, &m.Kind, &m.SHA256, &m.Attempts,
				&m.NextAt, &m.LeaseUntil, &m.SentAt, &m.LastError)
	})
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// MarkMailSent records a delivered message.
func (s *Store) MarkMailSent(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		"update mail_queue set sent_at = ?, lease_until = null, last_error = null where id = ?",
		timeNow(), id)
	if err != nil {
		return err
	}
	return expectOne(res, "mail item")
}

// MarkMailFailed releases the lease and records the error. nextAt is left to
// the caller so the worker can back off.
func (s *Store) MarkMailFailed(ctx context.Context, id int64, nextAt, reason string) error {
	res, err := s.db.ExecContext(ctx,
		"update mail_queue set lease_until = null, next_at = ?, last_error = ? where id = ?",
		nextAt, truncate(reason, 400), id)
	if err != nil {
		return err
	}
	return expectOne(res, "mail item")
}

// GiveUpMail closes a row after MaxAttempts failures: no lease, no next time,
// and the last error kept. It is not retried by Sweep, so a permanently
// failing message stays visible in the queue as a failed row.
func (s *Store) GiveUpMail(ctx context.Context, id int64, reason string) error {
	res, err := s.db.ExecContext(ctx,
		"update mail_queue set lease_until = null, next_at = '9999-12-31T00:00:00Z', last_error = ? where id = ?",
		truncate(reason, 400), id)
	if err != nil {
		return err
	}
	return expectOne(res, "mail item")
}

// ListMail returns the queue, unsent first.
func (s *Store) ListMail(ctx context.Context, envelopeID string) ([]MailItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`select id, envelope_id, party_id, kind, coalesce(sha256, ''), attempts,
		        next_at, coalesce(lease_until, ''), coalesce(sent_at, ''), coalesce(last_error, '')
		 from mail_queue where (? = '' or envelope_id = ?) order by sent_at is not null, id`,
		envelopeID, envelopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MailItem{}
	for rows.Next() {
		var m MailItem
		if err := scanRow(rows, &m.ID, &m.EnvelopeID, &m.PartyID, &m.Kind, &m.SHA256, &m.Attempts,
			&m.NextAt, &m.LeaseUntil, &m.SentAt, &m.LastError); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- events, settings ----------

// AddEvent appends one audit entry. payload is JSON built by the caller.
func (s *Store) AddEvent(ctx context.Context, envelopeID, actor, kind, payload string) error {
	if payload == "" {
		payload = "{}"
	}
	_, err := s.db.ExecContext(ctx,
		"insert into events(envelope_id, actor, kind, payload, created_at) values(?,?,?,?,?)",
		envelopeID, actor, kind, payload, timeNow())
	return err
}

// ListEvents returns the audit trail of an envelope, oldest first.
func (s *Store) ListEvents(ctx context.Context, envelopeID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		"select id, coalesce(envelope_id, ''), actor, kind, payload, created_at"+
			" from events where envelope_id = ? order by id", envelopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := scanRow(rows, &e.ID, &e.EnvelopeID, &e.Actor, &e.Kind, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListRecentEvents is the audit log in the shape the operator reads it: newest
// first, one page, and with the total number of rows the filter matches so the
// page can tell the operator how far the log goes. An empty envelopeID is the
// whole log — the settings writes live there, with no envelope to hang from.
func (s *Store) ListRecentEvents(ctx context.Context, envelopeID string, limit, offset int) ([]Event, int, error) {
	total := 0
	var err error
	if envelopeID == "" {
		err = s.db.QueryRowContext(ctx, "select count(*) from events").Scan(&total)
	} else {
		err = s.db.QueryRowContext(ctx,
			"select count(*) from events where envelope_id = ?", envelopeID).Scan(&total)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("signstore: events total: %w", err)
	}
	query := "select id, coalesce(envelope_id, ''), actor, kind, payload, created_at from events"
	args := []any{}
	if envelopeID != "" {
		query += " where envelope_id = ?"
		args = append(args, envelopeID)
	}
	query += " order by id desc limit ? offset ?"
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("signstore: recent events: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := scanRow(rows, &e.ID, &e.EnvelopeID, &e.Actor, &e.Kind, &e.Payload, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// GetSetting reads one setting.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "select value from settings where key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting writes one setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"insert into settings(key, value, updated_at) values(?,?,?)"+
			" on conflict(key) do update set value = excluded.value, updated_at = excluded.updated_at",
		key, value, timeNow())
	return err
}

// ---------- content-addressed storage ----------

// PutPDF stores a PDF revision and returns the SHA-256 that names it. Files
// are immutable: writing the same bytes twice is a no-op, and a non-PDF
// prefix is refused so a bad handler cannot fill the store with junk.
func (s *Store) PutPDF(data []byte) (string, error) { return s.put(data, ".pdf", MaxPDFBytes, "%PDF-") }

// PutBlob stores a consent image or a small artefact.
func (s *Store) PutBlob(data []byte, ext string) (string, error) {
	return s.put(data, "."+strings.TrimPrefix(ext, "."), MaxBlobBytes, "")
}

func (s *Store) put(data []byte, ext string, max int, prefix string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("signstore: empty data")
	}
	if len(data) > max {
		return "", fmt.Errorf("signstore: %d bytes exceeds the %d byte limit", len(data), max)
	}
	if prefix != "" && !strings.HasPrefix(string(data[:min(len(data), len(prefix))]), prefix) {
		return "", fmt.Errorf("signstore: data does not start with %q", prefix)
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(s.storageDir, 0o750); err != nil {
		return "", fmt.Errorf("signstore: storage dir: %w", err)
	}
	path := filepath.Join(s.storageDir, sha+ext)
	if _, err := os.Stat(path); err == nil {
		return sha, nil // immutable: same bytes, same name
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return "", fmt.Errorf("signstore: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("signstore: rename: %w", err)
	}
	return sha, nil
}

// PutNamed writes data under a name the caller chooses, so an artefact can be
// filed under the hash of the thing it describes rather than under its own
// hash. A receipt is the example: its name is the signed document's SHA-256,
// which is what lets a reader who holds the document find its receipt.
//
// The rule it enforces is the one that matters: the bytes are written only if
// the name is a well-formed hash, and the write is atomic, so a reader never
// sees a half-written artefact.
func (s *Store) PutNamed(name, ext string, data []byte) error {
	if len(name) != 64 || filepath.Base(name) != name {
		return fmt.Errorf("signstore: name must be 64 hex characters")
	}
	if len(data) == 0 {
		return fmt.Errorf("signstore: empty data")
	}
	if len(data) > MaxBlobBytes {
		return fmt.Errorf("signstore: %d bytes exceeds the %d byte limit", len(data), MaxBlobBytes)
	}
	if err := os.MkdirAll(s.storageDir, 0o750); err != nil {
		return fmt.Errorf("signstore: storage dir: %w", err)
	}
	path := filepath.Join(s.storageDir, name+ext)
	if _, err := os.Stat(path); err == nil {
		return nil // same artefact, same bytes: nothing to do
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("signstore: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("signstore: rename: %w", err)
	}
	return nil
}

// GetPDF reads a stored revision by its SHA-256.
func (s *Store) GetPDF(sha string) ([]byte, error) { return s.get(sha, ".pdf") }

// GetBlob reads a stored blob by its SHA-256.
func (s *Store) GetBlob(sha, ext string) ([]byte, error) {
	return s.get(sha, "."+strings.TrimPrefix(ext, "."))
}

func (s *Store) get(sha, ext string) ([]byte, error) {
	if len(sha) != 64 || filepath.Base(sha) != sha {
		return nil, fmt.Errorf("signstore: sha must be 64 hex characters")
	}
	b, err := os.ReadFile(filepath.Join(s.storageDir, sha+ext))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// StorageDir reports where the store writes.
func (s *Store) StorageDir() string { return s.storageDir }

// ---------- helpers ----------

// expectOne reports an error when a write touched no row: a statement that
// matched nothing is a bug in the caller (a deleted row, a wrong id), not a
// success. what names the row for the message.
func expectOne(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("signstore: no row updated for %s", what)
	}
	return nil
}

// escapeLike neutralises the LIKE wildcards in user input so a search string
// is matched literally. The escape character is declared in each LIKE.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// rowsAffected reports how many rows a statement touched, as an int.
func rowsAffected(res sql.Result) int {
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
