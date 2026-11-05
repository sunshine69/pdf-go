package signflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"time"

	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// KindSign is the revision kind the batch writes for a party signature. The
// store names the prefix "signed-"; the batch writes the bare kind and puts
// the party's name in the audit.zip file name.
const KindSign = "signed"

// logf is the batch's log line. The batch runs in the worker and in the CLI,
// so it writes to the logger the Deps carries; without one the message is
// dropped rather than lost to a closed handle.
func (d *Deps) logf(msg string, args ...any) {
	if d.Log != nil {
		d.Log.Info("signflow: "+msg, args...)
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
		if err := d.Store.CompleteBatch(ctx, item.EnvelopeID); err != nil {
			d.logf("batch complete (stale)", "envelope", item.EnvelopeID, "error", err)
		}
		return out, nil
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
	for _, p := range parties {
		if p.Status == signstore.PartyDeclined {
			out.Err = ErrStateConflict
			d.failEnvelope(ctx, env, p.ID)
			d.finishBatch(ctx, item, out.Err)
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
			Reason:    "signature",
			Signature: c.SignatureText,
			Image:     image,
			Now:       now,
			Widget:    partyWidget(i),
		})
		if err != nil {
			out.Err = fmt.Errorf("signflow: party %s: %w", p.ID, err)
			d.failEnvelope(ctx, env, p.ID)
			d.finishBatch(ctx, item, out.Err)
			return out, out.Err
		}
		sha, err := d.Store.PutPDF(signedOut.Data)
		if err != nil {
			out.Err = err
			d.finishBatch(ctx, item, err)
			return out, err
		}
		sum := sha256.Sum256(signedOut.Data)
		rid := newID()
		if err := d.Store.AddRevision(ctx, &signstore.Revision{
			ID:              rid,
			EnvelopeID:      item.EnvelopeID,
			SHA256:          sha,
			PrevID:          prevID,
			Kind:            KindSign,
			SigField:        fmt.Sprintf("Signature%d", i+1),
			PartyID:         p.ID,
			CertSerial:      signedOut.Serial,
			CertFingerprint: hex.EncodeToString(sum[:]),
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
	if env.Status == Completed {
		for _, p := range parties {
			if err := d.Store.EnqueueMail(ctx, item.EnvelopeID, p.ID, KindSigned, current.SHA256); err != nil {
				d.logf("batch delivery mail", "envelope", item.EnvelopeID, "error", err)
				break
			}
		}
		if err := d.Flow.Transition(ctx, env, Delivered, "batch",
			PayloadJSON(map[string]any{"sha256": current.SHA256, "parties": len(parties)})); err != nil {
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
func (d *Deps) finishBatch(ctx context.Context, item *signstore.BatchItem, err error) {
	if item == nil {
		return
	}
	if err == nil || errors.Is(err, ErrStateConflict) {
		if cErr := d.Store.CompleteBatch(ctx, item.EnvelopeID); cErr != nil {
			d.logf("batch complete", "envelope", item.EnvelopeID, "error", cErr)
		}
		return
	}
	if rErr := d.Store.RequeueBatch(ctx, item.EnvelopeID, 30*time.Second); rErr != nil {
		d.logf("batch requeue", "envelope", item.EnvelopeID, "error", rErr)
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

// consentImage reads the signature image a consent captured, if it captured
// one. A consent without an image signs with the typed text only.
func (d *Deps) consentImage(ctx context.Context, c *signstore.Consent) ([]byte, error) {
	if c.ImageSHA == "" {
		return nil, nil
	}
	data, err := d.Store.GetBlob(c.ImageSHA, ".png")
	if errors.Is(err, signstore.ErrNotFound) {
		return nil, nil
	}
	return data, err
}

// partyWidget places the signature widgets down the first page, the same
// column the selftest uses, so the signed document looks the same whatever
// signed it.
func partyWidget(index int) signpdf.Widget {
	return signpdf.Widget{Page: 1, X: 60, Y: 60 + 40*float64(index), W: 220, H: 30}
}
