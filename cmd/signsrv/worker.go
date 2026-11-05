package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The worker: the process half of the service. Consent queues a signing batch
// and never runs one; a send enqueues messages and, when the transport is not
// reachable from the request, leaves them in the queue. The worker is where
// that work happens, so no HTTP request ever waits on SMTP, a signature, or a
// TSA round trip.
//
// Three loops share one ticker:
//
//   - the mail queue, drained through the mailer;
//   - the batch queue, drained by the signing batch of step 10 (here it is
//     claimed and released, so the plumbing is proven before there is
//     anything to sign);
//   - the sweep, which expires parties and envelopes past their deadline and
//     releases leases whose holder died.
//
// Every loop is safe to run in several processes at once: a queue row is
// claimed with a lease, and every sweep statement is conditional, so running
// it twice changes nothing the second time.

// MailTick is how often the queues are drained. One minute is short enough that
// a message queued by a send is out within a minute of the send, and long
// enough that an idle service does not spin.
const MailTick = time.Minute

// SweepTick is how often the sweep runs. Five minutes is the figure in the
// design: a deadline is honoured to within a sweep, and an idle database is
// written to once every five minutes.
const SweepTick = 5 * time.Minute

// mailLease is how long a claimed mail row is held. A send that dies mid-flight
// releases the row when the lease expires, so a crashed process cannot
// strand a message.
const mailLease = time.Minute

// batchLease is how long a claimed batch row is held. Signing is CPU work on
// a document, so the lease is longer than a mail lease: a batch that dies
// mid-run releases its row when the lease expires and the next pass runs it
// again, which the idempotent batch makes safe.
const batchLease = 2 * time.Minute

// worker is the loop. It is started by serve and stops when ctx is cancelled;
// it owns no goroutine of its own, so one process runs one worker and the
// shutdown sequence is the shutdown of the server.
type worker struct {
	deps *signflow.Deps
	log  *slog.Logger
	// mailEvery and sweepEvery are the tick periods. A test shortens them;
	// production uses MailTick and SweepTick.
	mailEvery  time.Duration
	sweepEvery time.Duration
	// mailBudget caps the messages one mail tick sends, so a queue built up
	// over an outage is drained in slices rather than in one long tick that
	// delays the sweep.
	mailBudget int
	// batchBudget caps the batches one tick runs, so a queue of documents
	// does not make one tick outlast the mail it is also supposed to send.
	batchBudget int
}

func newWorkerWith(deps *signflow.Deps, log *slog.Logger) *worker {
	return &worker{deps: deps, log: log,
		mailEvery: MailTick, sweepEvery: SweepTick, mailBudget: 50, batchBudget: 4}
}

// newWorker builds the worker from the config, the way the server builds
// everything else: the store is the open database, the mailer is the templates
// plus the SMTP settings, and the signing service is the keystore opened with
// the configured passphrase. A config whose keystore cannot be opened yields a
// worker with no signer, which drains mail and leaves the batch queue waiting
// rather than failing the process: the mail half of the service still works.
func newWorker(cfg *Config, log *slog.Logger, store *signstore.Store) *worker {
	deps := &signflow.Deps{
		Store:  store,
		Signer: signService(cfg, log),
		Flow:   signflow.NewFlow(store),
		Clock:  time.Now,
		Mail:   newMailer(cfg, log),
		Log:    log,
	}
	return newWorkerWith(deps, log)
}

// run is the loop. It returns when ctx is cancelled, after finishing the tick
// it was in, so a message that was being written is written. interval is the
// mail tick; the sweep runs on its own, longer, tick.
func (w *worker) run(ctx context.Context, interval time.Duration) {
	if interval > 0 {
		w.mailEvery = interval
	}
	if w.deps == nil || w.deps.Store == nil {
		return
	}
	mail := time.NewTicker(w.tickOr(w.mailEvery, MailTick))
	sweep := time.NewTicker(w.tickOr(w.sweepEvery, SweepTick))
	defer mail.Stop()
	defer sweep.Stop()

	// One pass at once: a process that restarts with a queue full of rows
	// starts delivering immediately, and does not wait for the first tick.
	w.pass(ctx)

	for {
		select {
		case <-ctx.Done():
			// The final pass is deliberately skipped: a graceful stop leaves
			// claimed rows to their lease, and the next process to start
			// picks them up.
			return
		case <-mail.C:
			w.drainMail(ctx)
		case <-sweep.C:
			w.runSweep(ctx)
		}
	}
}

func (w *worker) tickOr(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// pass runs both drains once. It is the body of a tick, exposed so a test and
// the `signsrv worker --once` path can run exactly one round.
func (w *worker) pass(ctx context.Context) {
	w.drainMail(ctx)
	w.drainBatches(ctx)
	w.runSweep(ctx)
}

// drainMail sends what the queue holds, up to the budget of one tick.
//
// The raw token of a link is not recoverable from the database — only its hash
// is stored — so a message drained from the queue outside the send that
// created it is built from the party row and the link the queue row can
// reconstruct. That is why the send delivers inline when it can, and the queue
// is the retry path.
func (w *worker) drainMail(ctx context.Context) {
	if w.deps.Mail == nil || w.deps.Mail.Renderer == nil {
		return
	}
	sent := 0
	for sent < w.mailBudget {
		item, err := w.deps.Store.ClaimMail(ctx, mailLease)
		if err != nil {
			if errors.Is(err, signstore.ErrNotFound) {
				return
			}
			w.log.Error("mail claim", "error", err)
			return
		}
		if w.deps.Mail.Sender == nil {
			// No transport in this process (SMTP not configured, not dev
			// mode). Release the row: it is not failed, it is waiting for a
			// process that can send.
			if err := w.deps.Store.MarkMailFailed(ctx, item.ID,
				formatStamp(time.Now().Add(mailLease)), "no sender in this process"); err != nil {
				w.log.Error("mail release", "error", err)
			}
			return
		}
		msg, err := signflow.Build(ctx, w.deps.Mail.Renderer, w.deps.Store, item,
			w.deps.Mail.From, w.deps.Mail.LinkBase, signflow.RawToken(item.PartyID),
			w.partyCount(ctx, item.EnvelopeID), time.Now())
		if err != nil {
			w.failMail(ctx, item, err.Error())
			continue
		}
		if err := w.deps.Mail.Sender.Send(ctx, msg); err != nil {
			w.failMail(ctx, item, err.Error())
			continue
		}
		if err := w.deps.Store.MarkMailSent(ctx, item.ID); err != nil {
			w.log.Error("mail mark sent", "error", err, "id", item.ID)
			return
		}
		sent++
	}
}

func (w *worker) partyCount(ctx context.Context, envelopeID string) int {
	parties, err := w.deps.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return 0
	}
	return len(parties)
}

// failMail applies the retry rule: backoff up to the attempt limit, then give
// up and raise an event, which is how the admin learns a message died.
func (w *worker) failMail(ctx context.Context, item *signstore.MailItem, reason string) {
	if item.Attempts >= signmail.MaxAttempts {
		if err := w.deps.Store.GiveUpMail(ctx, item.ID, reason); err != nil {
			w.log.Error("mail give up", "error", err, "id", item.ID)
			return
		}
		if err := w.deps.Store.AddEvent(ctx, item.EnvelopeID, "worker", "mail_failed",
			signflow.PayloadJSON(map[string]any{"kind": item.Kind, "party": item.PartyID,
				"error": reason})); err != nil {
			w.log.Error("mail failed event", "error", err)
		}
		return
	}
	next := time.Now().Add(signmail.BackoffFor(item.Attempts))
	if err := w.deps.Store.MarkMailFailed(ctx, item.ID, formatStamp(next), reason); err != nil {
		w.log.Error("mail backoff", "error", err, "id", item.ID)
	}
}

// drainBatches walks the batch queue.
//
// A batch row is claimed under a lease, the signing happens outside any
// transaction, and the row is completed or requeued at the end — the contract
// the queue exists to enforce. The batch itself is idempotent, so a row that a
// crashed process left behind can be run again by whoever claims it next.
func (w *worker) drainBatches(ctx context.Context) {
	if w.deps.Store == nil || w.deps.Signer == nil {
		return // no signing service in this process: the queue waits
	}
	for ran := 0; ran < w.batchBudget; ran++ {
		out, err := w.deps.RunBatch(ctx, batchLease)
		if err != nil {
			w.log.Error("batch run", "error", err,
				"envelope", outEnvelope(out))
			return
		}
		if out == nil {
			return // queue empty
		}
		w.log.Info("batch run", "envelope", out.EnvelopeID, "signed", out.Signed,
			"status", out.Status, "valid", out.Report != nil && out.Report.Valid)
	}
}

func outEnvelope(out *signflow.BatchOutcome) string {
	if out == nil {
		return ""
	}
	return out.EnvelopeID
}

// runSweep is the 5-minute maintenance. It expires parties and envelopes past
// their deadline, releases leases whose holder died, and prunes old JTIs.
//
// An envelope that expires mid-collection is the documented outcome of the
// design: nothing is signed, and the admin and the parties are told. The
// sweep's report says how much it did, and one event per expired envelope
// records the reason in the audit trail.
func (w *worker) runSweep(ctx context.Context) {
	report, err := signstore.Sweep(ctx, w.deps.Store.DB())
	if err != nil {
		w.log.Error("sweep", "error", err)
		return
	}
	if report.EnvelopesExpired == 0 && report.PartiesExpired == 0 &&
		report.MailRequeued == 0 && report.BatchesRequeued == 0 &&
		report.JTIsDeleted == 0 && report.RefreshDeleted == 0 && report.BatchesFailed == 0 {
		return // an idle sweep is not worth a log line
	}
	w.log.Info("sweep", "envelopes_expired", report.EnvelopesExpired,
		"parties_expired", report.PartiesExpired, "mail_requeued", report.MailRequeued,
		"batches_requeued", report.BatchesRequeued, "batches_failed", report.BatchesFailed,
		"jtis_deleted", report.JTIsDeleted, "refresh_deleted", report.RefreshDeleted,
		"at", report.Now)
}

// formatStamp is the store's timestamp format, so a value written by the
// worker sorts against a value written by the store.
func formatStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
