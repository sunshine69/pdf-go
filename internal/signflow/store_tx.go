package signflow

import (
	"context"
	"crypto/rand"
	"database/sql"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The create path writes inside one transaction, so it needs statement-level
// helpers that take a tx. The store's own Create* helpers run on the
// connection, which is the right shape for a single-row write from a handler;
// all-or-nothing creation needs the transaction form, and that is what lives
// here.

const (
	envelopeCols = "id, title, status, template_sha, filled_sha, current_sha, serial," +
		" created_by, created_at, updated_at, expires_at, sent_at, delivered_at, cancelled_at"
	partyCols = "id, envelope_id, order_idx, email, name, status, token_hash," +
		" token_expires_at, claim_at, consent_at, delivered_at, session_hash, reason"
	revisionCols = "id, envelope_id, sha256, prev_id, kind, sig_field, party_id," +
		" cert_serial, cert_fingerprint, produced_by, size, created_at"
)

func insertEnvelope(ctx context.Context, tx *sql.Tx, e *signstore.Envelope) error {
	_, err := tx.ExecContext(ctx,
		"insert into envelopes("+envelopeCols+") values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		e.ID, e.Title, string(e.Status), e.TemplateSHA, e.FilledSHA, e.CurrentSHA, e.Serial,
		e.CreatedBy, e.CreatedAt, e.CreatedAt, e.ExpiresAt, e.SentAt, e.DeliveredAt, e.CancelledAt)
	return err
}

func insertParty(ctx context.Context, tx *sql.Tx, p *signstore.Party) error {
	_, err := tx.ExecContext(ctx,
		"insert into parties("+partyCols+") values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
		p.ID, p.EnvelopeID, p.OrderIdx, p.Email, p.Name, string(p.Status), p.TokenHash,
		p.TokenExpires, p.ClaimAt, p.ConsentAt, p.DeliveredAt, p.SessionHash, p.Reason)
	return err
}

func insertRevision(ctx context.Context, tx *sql.Tx, r *signstore.Revision) error {
	_, err := tx.ExecContext(ctx,
		"insert into revisions("+revisionCols+") values(?,?,?,?,?,?,?,?,?,?,?,?)",
		r.ID, r.EnvelopeID, r.SHA256, r.PrevID, r.Kind, r.SigField, r.PartyID,
		r.CertSerial, r.CertFingerprint, r.ProducedBy, r.Size, r.CreatedAt)
	return err
}

func insertEvent(ctx context.Context, tx *sql.Tx, envelopeID, actor, kind, payload string) error {
	if actor == "" {
		actor = "system"
	}
	if payload == "" {
		payload = "{}"
	}
	_, err := tx.ExecContext(ctx,
		"insert into events(envelope_id, actor, kind, payload, created_at) values(?,?,?,?,?)",
		envelopeID, actor, kind, payload, timeNow())
	return err
}

// randRead fills a buffer from the system entropy source. The service depends
// on crypto/rand for ids, link tokens, and the CA key, so this is the single
// place it is called.
func randRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}
