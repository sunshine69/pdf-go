package signstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SweepReport counts what a sweep changed. The worker logs it and writes one
// events row per sweep, so the audit trail shows that expiry happened
// automatically and when.
type SweepReport struct {
	EnvelopesExpired int
	PartiesExpired   int
	JTIsDeleted      int
	BatchesRequeued  int
	MailRequeued     int
	BatchesFailed    int // batches retried past MaxBatchAttempts, envelope -> failed
	RefreshDeleted   int // refresh chains past their own deadline
	Now              string
}

// MaxBatchAttempts is the number of times a signing batch is retried before
// the envelope is marked failed. A batch that cannot sign is a persistent
// problem (bad bytes, broken keystore), not a transient one, so it is
// reported rather than retried forever.
const MaxBatchAttempts = 5

// Sweep runs the periodic maintenance. It is safe to call from several
// processes: every statement is conditional and idempotent.
//
//  1. envelopes past expires_at, and their parties, become expired;
//  2. mail/batch rows whose lease expired are released so they run again;
//  3. a batch retried MaxBatchAttempts times marks its envelope failed;
//  4. revoked_jtis past their expiry are deleted, keeping the table small.
func Sweep(ctx context.Context, db *sql.DB) (SweepReport, error) {
	now := time.Now().UTC()
	nowS := formatTime(now)
	r := SweepReport{Now: nowS}

	res, err := db.ExecContext(ctx,
		`update parties set status = 'expired'
		 where status in ('invited', 'claimed') and token_expires_at < ?`, nowS)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep parties: %w", err)
	}
	r.PartiesExpired = rowsAffected(res)

	res, err = db.ExecContext(ctx,
		`update envelopes set status = 'expired', updated_at = ?
		 where status in ('ready', 'sent', 'collecting') and expires_at < ?`, nowS, nowS)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep envelopes: %w", err)
	}
	r.EnvelopesExpired = rowsAffected(res)

	res, err = db.ExecContext(ctx, "delete from revoked_jtis where expires_at < ?", nowS)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep jtis: %w", err)
	}
	r.JTIsDeleted = rowsAffected(res)

	// A refresh chain whose own deadline has passed is deleted: a device that
	// was never seen again must not keep a credential in the database.
	res, err = db.ExecContext(ctx,
		"delete from refresh_tokens where expires_at < ?", nowS)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep refresh: %w", err)
	}
	r.RefreshDeleted = rowsAffected(res)

	res, err = db.ExecContext(ctx,
		`update batch_queue set lease_until = null
		 where lease_until is not null and lease_until < ?`, nowS)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep batches: %w", err)
	}
	r.BatchesRequeued = rowsAffected(res)

	res, err = db.ExecContext(ctx,
		`update mail_queue set lease_until = null
		 where sent_at is null and lease_until is not null and lease_until < ?`, nowS)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep mail: %w", err)
	}
	r.MailRequeued = rowsAffected(res)

	res, err = db.ExecContext(ctx,
		`update envelopes set status = 'failed', updated_at = ?
		 where status = 'collecting'
		   and id in (select envelope_id from batch_queue where attempts >= ?)`,
		nowS, MaxBatchAttempts)
	if err != nil {
		return r, fmt.Errorf("signstore: sweep failed batches: %w", err)
	}
	r.BatchesFailed = rowsAffected(res)

	if total := r.EnvelopesExpired + r.PartiesExpired + r.JTIsDeleted +
		r.BatchesRequeued + r.MailRequeued + r.BatchesFailed + r.RefreshDeleted; total > 0 {
		payload := fmt.Sprintf(`{"envelopes_expired":%d,"parties_expired":%d,`+
			`"jtis_deleted":%d,"batches_requeued":%d,"mail_requeued":%d,`+
			`"batches_failed":%d,"refresh_deleted":%d}`,
			r.EnvelopesExpired, r.PartiesExpired, r.JTIsDeleted,
			r.BatchesRequeued, r.MailRequeued, r.BatchesFailed, r.RefreshDeleted)
		if _, err := db.ExecContext(ctx,
			"insert into events(envelope_id, actor, kind, payload, created_at)"+
				" values(null, 'worker', 'sweep', ?, ?)", payload, nowS); err != nil {
			return r, fmt.Errorf("signstore: sweep event: %w", err)
		}
	}
	return r, nil
}
