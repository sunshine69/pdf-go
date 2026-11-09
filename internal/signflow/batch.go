package signflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"time"

	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// KindSign is the revision kind the batch writes for a party signature. The
// store names the prefix "signed-"; the batch writes the bare kind and puts
// the party's name in the audit.zip file name.
const KindSign = "signed"

// BatchAttempts is how many times the queue will run one envelope's batch
// before giving up on it. A fault that survives five runs — an unreachable
// time-stamp authority, a storage directory that will not open — is not a fault
// the next tick fixes, and a queue that retries it forever never drains.
const BatchAttempts = 5

// ErrBatchAttemptsExhausted is the queue giving up on one envelope: the row has
// been claimed BatchAttempts times and each claim failed. It is a distinct error
// because the operator action it calls for is different from a signing failure —
// the document is fine, the thing it depends on is not, and the queue row is
// finished rather than retried.
var ErrBatchAttemptsExhausted = errors.New("signflow: batch attempts exhausted")

// logf is the batch's log line. The batch runs in the worker and in the CLI,
// so it writes to the logger the Deps carries; without one the message is
// dropped rather than lost to a closed handle.
func (d *Deps) logf(msg string, args ...any) {
	if d.Log != nil {
		d.Log.Info("signflow: "+msg, args...)
	}
}

// logWarnf is the batch's warning line: the batch continued and the document it
// produced is valid, but it is not what the signer asked for. The cases worth
// warning about are the ones where a fallback turned a failure into a silent
// downgrade.
func (d *Deps) logWarnf(msg string, args ...any) {
	if d.Log != nil {
		d.Log.Warn("signflow: "+msg, args...)
	}
}

// The signing batch of step 09/10. The batch is the only place that turns a
// collection of consents into signed bytes, so it is the one place allowed to
// write a sign revision, to move the envelope from collecting to signed, and
// to hand the finished document over to delivery.
//
// The contract is the one the worker documents: a row is claimed under a
// lease, the work happens outside a transaction, and the row is completed or
// requeued at the end. The batch is idempotent — a second run over an envelope
// whose consents are all already signed produces no new revision — so
// re-triggering a batch after a crash is a repair, not a second signing.

// BatchOutcome is what one batch run did, for the log and for the caller that
// has to decide whether to requeue.
type BatchOutcome struct {
	EnvelopeID string
	Signed     int    // party signatures the batch wrote
	Final      string // sha256 of the document the batch ended with
	Status     string // envelope status after the batch
	Report     *signpdf.Report
	Delivered  int // parties whose copy is accepted, this run and before it
	Total      int // parties the envelope has
	Attempt    int // which claim this was: 1 on the first run, 5 on the last
	Err        error
}

// RunBatch claims one batch row and runs it to the end: every consented party
// signs, the document is verified, and a verified document is completed,
// delivered, and mailed to the parties. The claim is what makes it safe to run
// the batch from more than one process: a row that another process holds is
// not touched.
func (d *Deps) RunBatch(ctx context.Context, lease time.Duration) (*BatchOutcome, error) {
	item, err := d.claimBatch(ctx, lease, "")
	if err != nil || item == nil {
		return nil, err
	}
	return d.runBatchItem(ctx, item)
}

// RunBatchFor runs one envelope's batch: the operator's "sign now". The claim
// is on that envelope's row, so a queue full of other work cannot delay the
// document that was just asked for. A row another process holds under a live
// lease returns (nil, nil) — the batch is running, somewhere else — rather
// than signing the same document twice.
func (d *Deps) RunBatchFor(ctx context.Context, envelopeID string, lease time.Duration) (*BatchOutcome, error) {
	item, err := d.claimBatch(ctx, lease, envelopeID)
	if err != nil || item == nil {
		return nil, err
	}
	return d.runBatchItem(ctx, item)
}

// claimBatch takes the queue row a batch run works on. An empty envelopeID
// means "whatever is due next", which is the worker's shape; a named envelope
// is the operator's shape. Nothing due, or nothing claimable, is (nil, nil).
func (d *Deps) claimBatch(ctx context.Context, lease time.Duration, envelopeID string) (*signstore.BatchItem, error) {
	if d.Store == nil || d.Signer == nil {
		return nil, errors.New("signflow: batch needs a store and a signing service")
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	var item *signstore.BatchItem
	var err error
	if envelopeID == "" {
		item, err = d.Store.ClaimBatch(ctx, lease)
	} else {
		item, err = d.Store.ClaimBatchFor(ctx, envelopeID, lease)
	}
	if errors.Is(err, signstore.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (d *Deps) runBatchItem(ctx context.Context, item *signstore.BatchItem) (*BatchOutcome, error) {
	out := &BatchOutcome{EnvelopeID: item.EnvelopeID}
	env, err := d.Store.GetEnvelope(ctx, item.EnvelopeID)
	if err != nil {
		out.Err = err
		d.finishBatch(ctx, item, err)
		return out, err
	}
	out.Status = string(env.Status)

	// A batch for an envelope that is not waiting for signatures is finished
	// on the spot: the queue is a work list, and a row whose work is already
	// done is not a failure, it is stale work.
	if env.Status != Collecting && env.Status != Signed {
		out.Err = ErrStateConflict
		// The work is done, so the answer is the document the work produced.
		out.Final = env.CurrentSHA
		out.Status = string(env.Status)
		if err := d.Store.CompleteBatch(ctx, item.EnvelopeID); err != nil {
			d.logf("batch complete (stale)", "envelope", item.EnvelopeID, "error", err)
		}
		return out, nil
	}

	// Attempts are counted by the claim, so they are known before the first
	// signature is written. A batch claimed five times has failed five times, and
	// the sixth run closes the envelope instead of trying again: the admin gets a
	// failure with a reason, not a job that never ends.
	out.Attempt = item.Attempts
	if item.Attempts > BatchAttempts {
		// The row has failed BatchAttempts times. Closing the envelope is the
		// honest answer: the admin sees a failure with a reason and the queue
		// empties, instead of a job that outlives the outage it is waiting for.
		out.Err = fmt.Errorf("%w after %d attempts", ErrBatchAttemptsExhausted, item.Attempts)
		d.failEnvelope(ctx, env, "")
		if err := d.Store.AddEvent(ctx, item.EnvelopeID, "batch", "attempts_exhausted",
			PayloadJSON(map[string]any{"attempts": item.Attempts,
				"max_attempts": BatchAttempts, "reason": out.Err.Error()})); err != nil {
			d.logf("batch attempts event", "envelope", item.EnvelopeID, "error", err)
		}
		out.Status = string(Failed)
		d.finishBatch(ctx, item, nil)
		return out, out.Err
	}

	parties, err := d.Store.ListParties(ctx, item.EnvelopeID)
	if err != nil {
		out.Err = err
		d.finishBatch(ctx, item, err)
		return out, err
	}
	consents, err := d.Store.ListConsents(ctx, item.EnvelopeID)
	if err != nil {
		out.Err = err
		d.finishBatch(ctx, item, err)
		return out, err
	}
	byParty := make(map[string]*signstore.Consent, len(consents))
	for i := range consents {
		byParty[consents[i].PartyID] = &consents[i]
	}
	// Every party has to have had its say before anything is signed. A batch that
	// signed the consented subset would produce a document that cannot be mailed
	// to the parties still outstanding, and "here is your signed document" would
	// be a lie about a signature that is not on it. The envelope waits; the row
	// is finished, not failed, because the missing consent is not a fault.
	for _, p := range parties {
		if p.Status == signstore.PartyDeclined {
			out.Err = ErrStateConflict
			d.failEnvelope(ctx, env, p.ID)
			d.finishBatch(ctx, item, out.Err)
			return out, out.Err
		}
		if p.Status != signstore.PartyConsented {
			out.Err = fmt.Errorf("%w: party %d of %d has not consented",
				ErrStateConflict, p.OrderIdx, len(parties))
			d.finishBatch(ctx, item, ErrStateConflict)
			return out, out.Err
		}
	}

	revisions, err := d.Store.ListRevisions(ctx, item.EnvelopeID)
	if err != nil {
		out.Err = err
		d.finishBatch(ctx, item, err)
		return out, err
	}
	if len(revisions) == 0 {
		out.Err = errors.New("signflow: batch has no revisions to sign")
		d.finishBatch(ctx, item, out.Err)
		return out, out.Err
	}
	// The batch signs the newest revision. Idempotence comes from the sign
	// revisions that already exist: a party with a sign revision is not asked
	// to sign again.
	signed := make(map[string]bool, len(revisions))
	prevID := revisions[len(revisions)-1].ID
	current := revisions[len(revisions)-1]
	for _, r := range revisions {
		if r.Kind == KindSign {
			signed[r.PartyID] = true
		}
		if r.ID != "" {
			prevID = r.ID
		}
		current = r
	}
	data, err := d.Store.GetPDF(current.SHA256)
	if err != nil {
		out.Err = err
		d.finishBatch(ctx, item, err)
		return out, err
	}
	// The bytes are checked against the digest they are stored under before a
	// single signature is added. Every party signature is an approval of these
	// bytes, so a document swapped on disk turns the whole batch into approvals
	// of content nobody reviewed. Gate 1 at the end would catch it, but only
	// after the signatures exist; this is the check that refuses to create them.
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != current.SHA256 {
		out.Err = fmt.Errorf("%w: batch input hashes to %s, expected %s",
			ErrVerifyGate, hex.EncodeToString(got[:]), current.SHA256)
		d.failEnvelope(ctx, env, "")
		if err := d.Store.AddEvent(ctx, item.EnvelopeID, "batch", "verify_failed",
			PayloadJSON(map[string]any{"expected_sha": current.SHA256,
				"got_sha": hex.EncodeToString(got[:]),
				"errors":  []string{out.Err.Error()}})); err != nil {
			d.logf("batch gate 1 event", "envelope", item.EnvelopeID, "error", err)
		}
		d.finishBatch(ctx, item, nil)
		out.Status = string(Failed)
		return out, out.Err
	}

	now := d.clock()
	order := make([]signstore.Party, 0, len(parties))
	for _, p := range parties {
		if p.Status == signstore.PartyConsented && !signed[p.ID] {
			order = append(order, p)
		}
	}
	for i, p := range order {
		c := byParty[p.ID]
		if c == nil {
			continue
		}
		image, err := d.consentImage(ctx, c)
		if err != nil {
			out.Err = fmt.Errorf("signflow: consent image for %s: %w", p.ID, err)
			d.failEnvelope(ctx, env, p.ID)
			d.finishBatch(ctx, item, out.Err)
			return out, out.Err
		}
		signedOut, err := d.Signer.SignParty(ctx, data, signpdf.PartyOptions{
			Name:      p.Name,
			Email:     p.Email,
			Reason:    partyReason(p, c),
			Signature: c.SignatureText,
			Image:     image,
			Now:       now,
			Widget:    partyWidget(i),
			TSAURL:    d.TSAOverride,
		})
		if err != nil {
			// The envelope stays where it is. A timestamp authority that is
			// down, or a signing service that blinked, is an outage: the row is
			// requeued and the next attempt re-signs from the certified document.
			// Closing the envelope here would destroy a live signing session on
			// a transient fault, and the queue's attempt limit is what turns a
			// persistent fault into a failure.
			out.Err = fmt.Errorf("signflow: party %s: %w", p.ID, err)
			d.finishBatch(ctx, item, out.Err)
			return out, out.Err
		}
		sha, err := d.Store.PutPDF(signedOut.Data)
		if err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}

		rid := newID()
		if err := d.Store.AddRevision(ctx, &signstore.Revision{
			ID:              rid,
			EnvelopeID:      item.EnvelopeID,
			SHA256:          sha,
			PrevID:          prevID,
			Kind:            KindSign,
			SigField:        fmt.Sprintf("Signature_%d", p.OrderIdx),
			PartyID:         p.ID,
			CertSerial:      signedOut.Serial,
			CertFingerprint: certFingerprint(signedOut.CertPEM),
			ProducedBy:      "batch",
			Size:            int64(len(signedOut.Data)),
			CreatedAt:       formatTime(now),
		}); err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}
		if err := d.Store.AddEvent(ctx, item.EnvelopeID, "batch", "party_signed",
			PayloadJSON(map[string]any{"party_id": p.ID, "email": p.Email,
				"sha256": sha, "cert_serial": signedOut.Serial})); err != nil {
			d.logf("batch party event", "envelope", item.EnvelopeID, "error", err)
		}
		data = signedOut.Data
		prevID = rid
		current = signstore.Revision{ID: rid, SHA256: sha}
		out.Signed++
		// The envelope points at the newest document after every signature, so
		// a download or a report never reads the pre-batch bytes.
		if err := d.Store.SetEnvelopeCurrentSHA(ctx, item.EnvelopeID, sha); err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}
	}

	if env.Status == Collecting {
		if err := d.Flow.Transition(ctx, env, Signed, "batch",
			PayloadJSON(map[string]any{"signed": out.Signed + len(signed)})); err != nil {
			out.Err = err
			d.failEnvelope(ctx, env, "")
			d.finishBatch(ctx, item, err)
			return out, err
		}
	}

	if current.ID != "" {
		if err := d.Store.SetEnvelopeCurrentSHA(ctx, item.EnvelopeID, current.SHA256); err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}
	}

	report, err := d.Signer.Verify(ctx, data)
	if err != nil {
		out.Err = err
		d.failEnvelope(ctx, env, "")
		d.finishBatch(ctx, item, err)
		return out, err
	}
	out.Report = report
	out.Final = current.SHA256
	out.Status = string(env.Status)

	// Verification is the gate on delivery. A document whose signatures do not
	// verify is a failure, not a delivery: nobody is mailed an unverifiable
	// document, and the admin sees the reason in the audit trail.
	if !report.Valid {
		out.Err = fmt.Errorf("signflow: verification failed: %v", report.Errors)
		d.failEnvelope(ctx, env, "")
		d.finishBatch(ctx, item, out.Err)
		return out, out.Err
	}
	// The count is part of Gate 1. A document that verifies but carries the
	// certification and two of three party signatures is a document someone
	// rebuilt, and the only way to notice is to count.
	if want := 1 + out.Signed + alreadySigned(parties, revisions); len(report.Signers) != want {
		out.Err = fmt.Errorf("signflow: final document carries %d signatures, expected %d",
			len(report.Signers), want)
		d.logf("batch gate 1 signer count", "envelope", item.EnvelopeID,
			"expected", want, "got", len(report.Signers))
		d.failEnvelope(ctx, env, "")
		if err := d.Store.AddEvent(ctx, item.EnvelopeID, "batch", "verify_failed",
			PayloadJSON(map[string]any{"expected_signers": want, "signers": len(report.Signers),
				"errors": []string{out.Err.Error()}})); err != nil {
			d.logf("batch gate 1 event", "envelope", item.EnvelopeID, "error", err)
		}
		d.finishBatch(ctx, item, nil)
		return out, out.Err
	}
	if err := d.Store.AddEvent(ctx, item.EnvelopeID, "batch", "verified",
		PayloadJSON(map[string]any{"sha256": current.SHA256, "signers": len(report.Signers),
			"valid": true})); err != nil {
		d.logf("batch verify event", "envelope", item.EnvelopeID, "error", err)
	}

	if env.Status == Signed {
		if err := d.Flow.Transition(ctx, env, Completed, "batch",
			PayloadJSON(map[string]any{"sha256": current.SHA256})); err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}
	}

	// Hand the finished document to delivery. Gate 2 lives there: the bytes are
	// read back from storage, verified again, and only then attached. The batch
	// does not send anything itself, and nothing reaches a party that did not
	// pass this gate.
	if env.Status == Completed {
		dl, dErr := d.Deliver(ctx, item.EnvelopeID, current.SHA256)
		out.Delivered, out.Total = dl.Accepted, dl.Total
		if dErr != nil && errors.Is(dErr, ErrVerifyGate) {
			// A tampered or unverifiable document is not retried: the envelope
			// closes as failed and the queue row is finished.
			out.Err = dErr
			out.Status = string(Failed)
			d.failEnvelope(ctx, env, "")
			d.finishBatch(ctx, item, nil)
			return out, dErr
		}
		if dErr != nil {
			// A transport failure is a reason to try again, not a reason to close
			// anything. The copies that were accepted are recorded, so the next
			// claim delivers the rest instead of resending what already arrived.
			out.Err = dErr
			out.Status = string(env.Status)
			d.finishBatch(ctx, item, dErr)
			return out, dErr
		}
		if err := d.Flow.Transition(ctx, env, Delivered, "batch",
			PayloadJSON(map[string]any{"sha256": current.SHA256, "parties": dl.Accepted,
				"method": dl.Method, "bytes": dl.Bytes})); err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}
	}

	if err := d.Store.CompleteBatch(ctx, item.EnvelopeID); err != nil {
		d.logf("batch complete", "envelope", item.EnvelopeID, "error", err)
	}
	out.Status = string(env.Status)
	return out, nil
}

// finishBatch releases the queue row. A batch that failed requeues with a
// backoff so a persistent fault is retried but not spun on; a batch that
// succeeded or reached a closed state is completed, which is what empties the
// queue.
// batchFailureEvent records one failed attempt. The attempt number is the
// point: an operator reading the trail should see five attempts with the same
// reason before the envelope closed, and should see which fault it was.
func (d *Deps) batchFailureEvent(ctx context.Context, envelopeID string, attempt int, err error) {
	if err := d.Store.AddEvent(ctx, envelopeID, "batch", "failed",
		PayloadJSON(map[string]any{"attempt": attempt, "max_attempts": BatchAttempts,
			"reason": err.Error()})); err != nil {
		d.logf("batch failure event", "envelope", envelopeID, "error", err)
	}
}

// certFingerprint is the SHA-256 of the leaf certificate's DER encoding, which
// is the identifier an auditor can match against the certificate embedded in
// the PDF. A document digest is not that: it says nothing about who signed, and
// two parties' rows would carry the same value.
func certFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func (d *Deps) finishBatch(ctx context.Context, item *signstore.BatchItem, err error) {
	if item == nil {
		return
	}
	if err != nil && !errors.Is(err, ErrStateConflict) {
		d.batchFailureEvent(ctx, item.EnvelopeID, item.Attempts, err)
	}
	if err == nil || errors.Is(err, ErrStateConflict) {
		if cErr := d.Store.CompleteBatch(ctx, item.EnvelopeID); cErr != nil {
			d.logf("batch complete", "envelope", item.EnvelopeID, "error", cErr)
		}
		return
	}
	if rErr := d.Store.RequeueBatch(ctx, item.EnvelopeID, BatchBackoffFor(item.Attempts)); rErr != nil {
		d.logf("batch requeue", "envelope", item.EnvelopeID, "error", rErr)
	}
}

// BatchBackoffFor is how long a failed batch waits before its next attempt:
// 30s, 2m, 10m, 30m, 2h. The ladder is steep because the faults that stop a
// signature (a timestamp authority that is down) are usually measured in
// minutes, and a queue that retries them every thirty seconds fills up with
// work it cannot do.
func BatchBackoffFor(attempt int) time.Duration {
	switch attempt {
	case 0, 1:
		return 30 * time.Second
	case 2:
		return 2 * time.Minute
	case 3:
		return 10 * time.Minute
	case 4:
		return 30 * time.Minute
	default:
		return 2 * time.Hour
	}
}

// failEnvelope moves the envelope to failed, the documented outcome of a batch
// that could not produce a valid document. The failure is written once; a
// second call finds the envelope already closed and is ignored.
func (d *Deps) failEnvelope(ctx context.Context, env *signstore.Envelope, partyID string) {
	if env == nil || env.Status == Failed || env.Status == Delivered || env.Status == Cancelled {
		return
	}
	if err := d.Flow.Transition(ctx, env, Failed, "batch",
		PayloadJSON(map[string]any{"party_id": partyID})); err != nil {
		d.logf("batch fail transition", "envelope", env.ID, "error", err)
	}
}

// consentExtensions are the blob suffixes a consent image can carry. The
// consent write names the blob from the content type it decoded as — .png for
// PNG, .jpg for JPEG — so a read that asks for one fixed suffix finds only half
// of what can be stored.
var consentExtensions = []string{".png", ".jpg"}

// consentImage reads the signature image a consent captured, if it captured
// one. A consent without an image signs with the typed text only.
//
// The suffix is not known at read time, so each candidate is tried: the blob is
// content addressed and the signature image is at most 512 KB, so probing two
// suffixes is two directory lookups at worst. A miss still returns nil rather
// than an error, because the appearance is allowed to sign with the typed name
// and failing the batch over a missing decoration would destroy a live signing
// session. It is logged: an image that was uploaded, stored and then not found
// is a bug in this package, and a signer who sees their own handwriting missing
// from the page has no way to tell us so.
func (d *Deps) consentImage(ctx context.Context, c *signstore.Consent) ([]byte, error) {
	if c.ImageSHA == "" {
		return nil, nil
	}
	for _, ext := range consentExtensions {
		data, err := d.Store.GetBlob(c.ImageSHA, ext)
		switch {
		case err == nil:
			return data, nil
		case errors.Is(err, signstore.ErrNotFound):
			continue // try the other suffix
		default:
			return nil, err
		}
	}
	// Reaching here means no suffix held the blob: every candidate missed,
	// since any other error returned above.
	d.logWarnf("consent image not found",
		"consent", c.ID, "party", c.PartyID, "envelope", c.EnvelopeID,
		"image_sha", c.ImageSHA)
	return nil, nil
}

// partyWidget places the signature widgets down the first page. It defers to
// signpdf so that the box size and the spacing between boxes have one
// definition: the stride has to clear the height of a box, and a stack whose
// spacing is written in a second place can drift back into overlapping without
// anything noticing.
func partyWidget(index int) signpdf.Widget {
	return signpdf.PartyWidget(index)
}

// alreadySigned counts the parties this envelope already has a signature
// revision for, which is what a re-claimed batch adds to the signatures it
// writes now to know how many the finished document should carry.
func alreadySigned(parties []signstore.Party, revisions []signstore.Revision) int {
	have := make(map[string]bool, len(revisions))
	for _, r := range revisions {
		if r.Kind == KindSign && r.PartyID != "" {
			have[r.PartyID] = true
		}
	}
	n := 0
	for _, p := range parties {
		if have[p.ID] {
			n++
		}
	}
	return n
}

// partyReason is the line the party's signature carries. It states what the
// signature means and when the party agreed, so the document itself records the
// consent that produced it.
func partyReason(p signstore.Party, c *signstore.Consent) string {
	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		reason = "electronically signed"
	}
	if c == nil || c.ConsentAt == "" {
		return reason
	}
	return reason + "; electronically agreed " + c.ConsentAt
}
