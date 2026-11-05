package signflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// State is an envelope status. It is the same vocabulary signstore validates,
// re-exported here so the state machine is readable without importing the
// store's names.
type State = signstore.EnvelopeStatus

// The vocabulary, in lifecycle order.
const (
	Draft      = signstore.StatusDraft
	Ready      = signstore.StatusReady
	Sent       = signstore.StatusSent
	Collecting = signstore.StatusCollecting
	Signed     = signstore.StatusSigned
	Completed  = signstore.StatusCompleted
	Delivered  = signstore.StatusDelivered
	Expired    = signstore.StatusExpired
	Cancelled  = signstore.StatusCancelled
	Failed     = signstore.StatusFailed
)

// ErrStateConflict is the error every disallowed transition returns. The API
// maps it to HTTP 409, so "you cannot do that to this document right now" is
// a named answer, not a generic failure.
var ErrStateConflict = errors.New("signflow: state transition not allowed")

// allowed is the transition table. It is the only definition of what may
// happen: no handler, worker, or sweep decides a status on its own, they all
// ask Transition, and Transition consults this map.
//
// The shape of the lifecycle:
//
//	draft -> ready -> sent -> collecting -> signed -> completed -> delivered
//	                   \-> expired  \-> cancelled  \-> failed
//
// sent, collecting, ready can all be cancelled or expire, because a document
// that has not finished signing can be withdrawn by its creator, and the links
// can run out of time. A signed document cannot be cancelled: every party has
// already signed, and their signatures exist on the bytes. failed is reachable
// from signed and completed, the two states a run can break at.
var allowed = map[State][]State{
	Draft: {Ready},
	Ready: {Sent, Cancelled, Expired},
	// sent -> failed is the decline: a party refuses, and the request is over
	// for everyone. It happens before any consent, so it must be reachable
	// from sent, not only from collecting.
	Sent:       {Collecting, Failed, Cancelled, Expired},
	Collecting: {Signed, Failed, Cancelled, Expired},
	Signed:     {Completed, Failed},
	Completed:  {Delivered, Failed},
	Delivered:  {},
	Expired:    {},
	Cancelled:  {},
	Failed:     {},
}

// Can reports whether a transition is in the table.
func Can(from, to State) bool {
	for _, s := range allowed[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Next lists the states reachable from `from`, for a UI that has to show what
// an operator can do.
func Next(from State) []State {
	return allowed[from]
}

// stampColumn names the timestamp a transition writes, so a status and its
// stamp always land in the same statement.
func stampColumn(to State) string {
	switch to {
	case Sent:
		return "sent_at"
	case Delivered:
		return "delivered_at"
	case Cancelled:
		return "cancelled_at"
	default:
		return ""
	}
}

// Flow is the state machine, bound to a store.
type Flow struct {
	store *signstore.Store
}

// NewFlow wires the machine to its store.
func NewFlow(store *signstore.Store) *Flow {
	return &Flow{store: store}
}

// Transition moves one envelope to `to`, under BEGIN IMMEDIATE (the store's
// DSN opens every transaction with the immediate lock), and appends the event
// to the audit trail. Two concurrent signers cannot both advance the same
// envelope: the first takes the write lock, the second sees the new status and
// gets ErrStateConflict.
//
// `payload` is JSON stored with the event; pass "" for a bare event.
func (f *Flow) Transition(ctx context.Context, e *signstore.Envelope, to State, actor, payload string) error {
	if e == nil {
		return fmt.Errorf("signflow: nil envelope")
	}
	if !signstore.ValidStatus(string(to)) {
		return fmt.Errorf("signflow: unknown target state %q", string(to))
	}
	if e.Status == to {
		return fmt.Errorf("signflow: %w: %s is already %s", ErrStateConflict, e.ID, string(to))
	}
	if !Can(e.Status, to) {
		return fmt.Errorf("signflow: %w: %s -> %s (allowed from %s: %s)",
			ErrStateConflict, string(e.Status), string(to), string(e.Status), joinStates(allowed[e.Status]))
	}

	return f.store.Tx(ctx, func(tx *sql.Tx) error {
		// Re-read inside the transaction. The caller's copy is a snapshot;
		// the database is the truth, and the row may have moved since.
		var cur State
		if err := tx.QueryRowContext(ctx,
			"select status from envelopes where id = ?", e.ID).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return signstore.ErrNotFound
			}
			return err
		}
		if cur != e.Status {
			return fmt.Errorf("signflow: %w: envelope %s is %s, not %s",
				ErrStateConflict, e.ID, string(cur), string(e.Status))
		}
		if !Can(cur, to) {
			return fmt.Errorf("signflow: %w: %s -> %s", ErrStateConflict, string(cur), string(to))
		}

		if err := updateStatus(ctx, tx, e.ID, to, stampColumn(to)); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, e.ID, actor, "transition", transitionPayload(to, payload)); err != nil {
			return err
		}
		e.Status = to
		return nil
	})
}

// updateStatus is the narrow write: status plus its timestamp in one
// statement, so a crash cannot leave a new status with an old stamp.
func updateStatus(ctx context.Context, tx *sql.Tx, id string, to State, col string) error {
	q := "update envelopes set status = ?, updated_at = ?"
	args := []any{string(to), timeNow()}
	if col != "" {
		q += ", " + col + " = ?"
		args = append(args, timeNow())
	}
	q += " where id = ?"
	args = append(args, id)
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("signflow: no envelope row updated for %s", id)
	}
	return nil
}

// addEvent writes one audit row. The event is part of the same transaction as
// the status change: an audit trail that can lose a transition is not a trail.
func addEvent(ctx context.Context, tx *sql.Tx, envelopeID, actor, kind, payload string) error {
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

func transitionPayload(to State, payload string) string {
	if payload != "" {
		return payload
	}
	return `{"to":"` + string(to) + `"}`
}

func joinStates(states []State) string {
	out := ""
	for i, s := range states {
		if i > 0 {
			out += ", "
		}
		out += string(s)
	}
	if out == "" {
		out = "none"
	}
	return out
}

// timeNow matches the store's timestamp format, so a value written by the
// machine sorts correctly against a value written by the store.
func timeNow() string { return time.Now().UTC().Format(timeFormat) }

const timeFormat = "2006-01-02T15:04:05Z"

// SweepExpired moves every un-finished envelope whose links have run out to
// expired. The worker calls it on a timer. It reports how many envelopes it
// moved, and writes one event each, in one transaction.
func (f *Flow) SweepExpired(ctx context.Context, now string) (int, error) {
	moved := 0
	err := f.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			"select id, status from envelopes where expires_at <= ? and status in ('ready','sent','collecting')",
			now)
		if err != nil {
			return err
		}
		defer rows.Close()

		type hit struct {
			id     string
			status State
		}
		var hits []hit
		for rows.Next() {
			var h hit
			if err := rows.Scan(&h.id, &h.status); err != nil {
				return err
			}
			hits = append(hits, h)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, h := range hits {
			if !Can(h.status, Expired) {
				continue
			}
			if err := updateStatus(ctx, tx, h.id, Expired, ""); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, h.id, "worker", "transition", `{"to":"expired","reason":"links expired"}`); err != nil {
				return err
			}
			moved++
		}
		return nil
	})
	return moved, err
}

// SweepExpiredFrom is the single-envelope form the API uses when a request
// arrives for a document whose links have run out: the caller's view is
// "this document is finished", so the sweep happens on read.
func (f *Flow) SweepExpiredFrom(ctx context.Context, id, now string) (bool, error) {
	var moved bool
	err := f.store.Tx(ctx, func(tx *sql.Tx) error {
		var status State
		var expires string
		err := tx.QueryRowContext(ctx,
			"select status, expires_at from envelopes where id = ?", id).Scan(&status, &expires)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return signstore.ErrNotFound
			}
			return err
		}
		if expires > now {
			// Lexical order of these RFC 3339 UTC strings is chronological,
			// which is the whole reason the store writes them in this shape.
			return nil
		}
		if !Can(status, Expired) {
			return nil
		}
		if err := updateStatus(ctx, tx, id, Expired, ""); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, id, "worker", "transition", `{"to":"expired","reason":"links expired"}`); err != nil {
			return err
		}
		moved = true
		return nil
	})
	return moved, err
}

// stringsHasExpired compares two RFC 3339 UTC strings. Lexical order is
// chronological in this format, which is why the store stores them this way.
func stringsHasExpired(expires, now string) bool { return expires <= now }
