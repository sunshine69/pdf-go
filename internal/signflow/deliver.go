package signflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Delivery of the finished document, step 10.
//
// The batch produced a verified document. Delivery is the part that hands it
// to the parties, and it is where the second verification gate lives: a
// document that was valid when the batch finished is verified again, from the
// bytes that are about to be attached, immediately before they are attached.
// A file swapped on disk between finalize and send is caught here and stops
// every delivery, not just the one whose bytes were wrong.
//
// Delivery is recorded per party in the deliveries table, and the envelope
// reaches delivered only when every party's delivery has been accepted. A
// message that leaves with tampered bytes is a refusal, and it is stored as
// one, with the hashes that did not match.

// AttachLimit is the largest document that travels as an attachment. Past it
// the copy travels as a single-use download link instead, because a 40 MB
// attachment is refused by real mail servers and a refused attachment is a
// party who never got their document.
//
// It is a variable, not a constant, so a test can drive the large-document
// branch without building a 20 MB PDF.
var AttachLimit = 20 * 1024 * 1024

// DownloadTTL is how long a large-document link stays alive: 72 hours, no
// authentication, one document, and no way to reach a different document from
// it. The token is 32 random bytes; only its hash is stored, so the database
// cannot be used to walk the links.
const DownloadTTL = 72 * time.Hour

// DeliveryOutcome is what one delivery run did, for the log and for the caller
// that has to decide whether the envelope may be called delivered.
type DeliveryOutcome struct {
	EnvelopeID string `json:"envelope_id"`
	FinalSHA   string `json:"final_sha"`
	Bytes      int64  `json:"bytes"`
	Accepted   int    `json:"accepted"` // accepted copies, this run and earlier ones
	Total      int    `json:"total"`    // parties the envelope has
	Refused    int    `json:"refused"`
	Method     string `json:"method"` // attach or link (the method the copies used)
	Err        error  `json:"-"`
}

// ErrVerifyGate is Gate 2's refusal: the bytes about to be sent do not verify,
// or are not the document the receipt says they are.
var ErrVerifyGate = errors.New("signflow: delivery verification gate failed")

// verifyGate is Gate 2. It reads the document back from storage and verifies
// it, and it is the only place in the delivery path that reads the bytes: the
// attachment, the download link, and the record of what was sent all come from
// the same read, so what was verified is what was sent.
//
// Two things must hold. The signatures must verify, and the bytes must hash to
// the final_sha the batch recorded. The second is what catches a swap: a
// document with a valid signature from someone else is a valid document and the
// wrong one.
func (d *Deps) verifyGate(ctx context.Context, sha string) ([]byte, *signpdf.Report, error) {
	data, err := d.Store.GetPDF(sha)
	if err != nil {
		return nil, nil, fmt.Errorf("signflow: gate 2 read %s: %w", short(sha), err)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != sha {
		// Both digests in full. The audit event reads them back as fields, and a
		// truncated hash cannot be compared against the revision it should match.
		return nil, nil, fmt.Errorf("%w: stored bytes hash to %s, expected %s",
			ErrVerifyGate, hex.EncodeToString(got[:]), sha)
	}
	if d.Signer == nil {
		return nil, nil, fmt.Errorf("%w: no signer in this process", ErrVerifyGate)
	}
	report, err := d.Signer.Verify(ctx, data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: verify: %v", ErrVerifyGate, err)
	}
	if !report.Valid {
		return nil, report, fmt.Errorf("%w: %s", ErrVerifyGate, strings.Join(report.Errors, "; "))
	}
	return data, report, nil
}

// Deliver is Gate 2 plus the send, for one envelope whose document is finished.
//
// The order is deliberate: verify, then build, then hand over, then record.
// Any refusal stops the whole envelope — one party must not receive a document
// the others did not, when the reason one did not is that the bytes were wrong.
func (d *Deps) Deliver(ctx context.Context, envelopeID, finalSHA string) (*DeliveryOutcome, error) {
	out := &DeliveryOutcome{EnvelopeID: envelopeID, FinalSHA: finalSHA, Method: "attach"}
	env, err := d.Store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		out.Err = err
		return out, err
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		out.Err = err
		return out, err
	}
	if len(parties) == 0 {
		out.Err = errors.New("signflow: nothing to deliver")
		return out, out.Err
	}
	out.Total = len(parties)
	// A run a crashed process left half done must not send one party two copies:
	// the delivery row is what says whether this party was already reached with
	// these bytes, and an accepted row is counted without being sent again. The
	// document is still re-verified in full, because the gate is about the
	// document, not about one party.
	already := make(map[string]bool, len(parties))
	for _, p := range parties {
		rec, err := d.Store.GetDelivery(ctx, envelopeID, p.ID)
		if err == nil && rec.Status == signstore.DeliveryAccepted && rec.SHA256 == finalSHA {
			already[p.ID] = true
			out.Accepted++
		}
	}

	data, report, err := d.verifyGate(ctx, finalSHA)
	if err != nil {
		out.Err = err
		d.refuseAll(ctx, env, parties, finalSHA, err)
		return out, err
	}
	out.Bytes = int64(len(data))
	// Every party of the envelope must be signed on the copy that is about to go
	// out. A document that verifies with the certification and two of three
	// signatures is a real, valid document of the wrong thing: sending it tells
	// the third party their signature is on a file it is not. The copy travels
	// with the envelope's party list, so the count is the check.
	if want := 1 + len(parties); len(report.Signers) < want {
		err := fmt.Errorf("%w: document carries %d signatures, the envelope has %d parties",
			ErrVerifyGate, len(report.Signers), len(parties))
		out.Err = err
		d.refuseAll(ctx, env, parties, finalSHA, err)
		return out, err
	}

	now := d.clock()

	// A document over the attachment limit travels as a link. One link per
	// party, minted here, and the party's message carries the link rather than
	// the file.
	link := len(data) > AttachLimit
	if link {
		out.Method = "link"
	}

	// The receipt is built over the bytes Gate 2 just verified, so the evidence
	// and the document an auditor receives describe the same bytes.
	receipt, err := d.BuildReceipt(ctx, env, parties, data, report)
	if err != nil {
		out.Err = err
		d.refuseAll(ctx, env, parties, finalSHA, err)
		return out, err
	}
	if _, err := d.StoreReceipt(finalSHA, receipt); err != nil {
		out.Err = err
		d.refuseAll(ctx, env, parties, finalSHA, err)
		return out, err
	}

	for i := range parties {
		p := parties[i]
		if already[p.ID] {
			continue
		}
		rec := &signstore.Delivery{
			EnvelopeID: envelopeID,
			PartyID:    p.ID,
			SHA256:     finalSHA,
			Bytes:      int64(len(data)),
			VerifiedAt: formatTime(now),
			Verified:   true,
			Method:     "attach",
		}
		if link {
			token, err := NewDownloadToken()
			if err != nil {
				out.Err = err
				d.refuseAll(ctx, env, parties, finalSHA, err)
				return out, err
			}
			until := now.Add(DownloadTTL)
			if err := d.Store.CreateDownload(ctx, &signstore.Download{
				TokenHash:  HashDownloadToken(token),
				EnvelopeID: envelopeID,
				PartyID:    p.ID,
				SHA256:     finalSHA,
				ExpiresAt:  formatTime(until),
				CreatedAt:  formatTime(now),
			}); err != nil {
				out.Err = err
				d.refuseAll(ctx, env, parties, finalSHA, err)
				return out, err
			}
			rec.Method = "link"
			rec.DownloadID = token
			rec.UntilAt = formatTime(until)
		}
		if err := d.sendSignedCopy(ctx, env, p, data, receipt, rec); err != nil {
			// A transport failure is this party's problem, not a reason to
			// hold the document from everyone: the row is recorded as pending
			// with the error, and the mail queue keeps retrying it.
			out.Refused++
			rec.Status = signstore.DeliveryPending
			rec.VerifiedAt = formatTime(d.clock())
			rec.LastError = err.Error()
			if sErr := d.Store.UpsertDelivery(ctx, rec); sErr != nil {
				d.logf("delivery record", "envelope", envelopeID, "error", sErr)
			}
			d.logf("delivery send", "envelope", envelopeID, "party", p.ID, "error", err)
			continue
		}
		rec.Status = signstore.DeliveryAccepted
		rec.DeliveredAt = formatTime(d.clock())
		if err := d.Store.UpsertDelivery(ctx, rec); err != nil {
			out.Err = err
			return out, err
		}
		if err := d.Store.SetPartyDeliveredAt(ctx, p.ID, rec.DeliveredAt); err != nil {
			d.logf("delivery party stamp", "envelope", envelopeID, "error", err)
		}
		out.Accepted++
	}

	if out.Accepted == len(parties) {
		if err := d.Store.AddEvent(ctx, envelopeID, "delivery", "accepted",
			PayloadJSON(map[string]any{"sha256": finalSHA, "bytes": out.Bytes,
				"method": out.Method, "parties": out.Accepted,
				"verified_at": formatTime(now)})); err != nil {
			d.logf("delivery event", "envelope", envelopeID, "error", err)
		}
		// The envelope column is stamped here, and only here: every party's copy
		// has been accepted, which is the one fact delivered_at is allowed to
		// assert.
		env.DeliveredAt = formatTime(d.clock())
		if err := d.Store.SetEnvelopeDeliveredAt(ctx, envelopeID, env.DeliveredAt); err != nil {
			d.logf("delivery envelope stamp", "envelope", envelopeID, "error", err)
		}
		return out, nil
	}
	out.Err = fmt.Errorf("signflow: %d of %d deliveries accepted", out.Accepted, len(parties))
	return out, out.Err
}

// AllDelivered reports whether every party of an envelope has an accepted
// delivery, which is the answer the delivered status has to be built on.
func (d *Deps) AllDelivered(ctx context.Context, envelopeID string) (bool, int, int, error) {
	accepted, parties, err := d.Store.CountDeliveries(ctx, envelopeID)
	if err != nil {
		return false, 0, 0, err
	}
	return parties > 0 && accepted == parties, accepted, parties, nil
}

// sendSignedCopy builds and hands over one party's copy. The attachment bytes
// are the bytes Gate 2 verified, and the receipt is attached with them, so the
// party receives the document and the evidence in the same message.
func (d *Deps) sendSignedCopy(ctx context.Context, env *signstore.Envelope, p signstore.Party,
	data []byte, receipt []byte, rec *signstore.Delivery) error {
	if d.Mail == nil || d.Mail.Renderer == nil {
		return errors.New("signflow: no mail renderer in this process")
	}
	slug := slugTitle(env.Title)

	// The signed copy carries no signing link: the document is finished, and the
	// links that asked for signatures are dead. The template is given the names
	// of the files it is about to receive, so the body describes the message
	// the party actually gets.
	d2 := signmail.Data{
		Kind:        KindSigned,
		Title:       env.Title,
		Signer:      p.Name,
		Email:       p.Email,
		ExpiresAt:   p.TokenExpires,
		SHA256:      rec.SHA256,
		Bytes:       int(rec.Bytes),
		SignedAt:    rec.VerifiedAt,
		Order:       p.OrderIdx,
		From:        d.Mail.From,
		MailFrom:    d.Mail.From,
		Legal:       signmail.DefaultLegal,
		ReceiptName: slug + "-receipt.json",
	}
	if rec.Method == "attach" {
		d2.Attachment = slug + "-signed.pdf"
	} else {
		// The document is too large to attach, so the message carries a
		// time-limited download link in its place.
		d2.DownloadURL = DownloadLinkFor(d.linkBase(), rec.DownloadID)
		d2.RetainedDays = int(DownloadTTL / time.Hour)
	}
	total, _, _, err := d.Store.CountPartiesByStatus(ctx, env.ID)
	if err == nil {
		d2.N = total
	}
	text, html, err := d.Mail.Renderer.Render(d2)
	if err != nil {
		return fmt.Errorf("signflow: render signed message: %w", err)
	}
	msg := &signmail.Message{
		Kind:       KindSigned,
		EnvelopeID: env.ID,
		PartyID:    p.ID,
		To:         p.Email,
		From:       d.Mail.From,
		Subject:    signedSubject(env, slug),
		Text:       text,
		HTML:       html,
	}
	if rec.Method == "attach" {
		msg.Files = []signmail.File{
			{Name: slug + "-signed.pdf", Type: "application/pdf", Data: data},
			{Name: slug + "-receipt.json", Type: "application/json", Data: receipt},
		}
	} else {
		// The document is too large to attach. The evidence is small, so it
		// still travels as an attachment; the document travels as a link.
		msg.Files = []signmail.File{
			{Name: slug + "-receipt.json", Type: "application/json", Data: receipt},
		}
	}
	if d.Mail.Sender == nil {
		return errors.New("signflow: no mail sender in this process")
	}
	return d.Mail.Sender.Send(ctx, msg)
}

// refuseAll records Gate 2's refusal for every party, and writes the event the
// design names: verify_failed, carrying both hashes, so an operator can see
// which document was expected and which one was found.
func (d *Deps) refuseAll(ctx context.Context, env *signstore.Envelope, parties []signstore.Party,
	expectedSHA string, gateErr error) {
	now := formatTime(d.clock())
	for _, p := range parties {
		if prev, err := d.Store.GetDelivery(ctx, env.ID, p.ID); err == nil &&
			prev.Status == signstore.DeliveryAccepted {
			// A copy that a party already received is not rewritten by a later
			// refusal: the audit trail keeps the accepted record, and the refusal
			// is recorded for the parties who did not get anything.
			continue
		}
		if err := d.Store.UpsertDelivery(ctx, &signstore.Delivery{
			EnvelopeID: env.ID, PartyID: p.ID, SHA256: expectedSHA,
			VerifiedAt: now, Verified: false, Method: "attach",
			Status: signstore.DeliveryRefused, LastError: gateErr.Error(),
		}); err != nil {
			d.logf("delivery refusal record", "envelope", env.ID, "error", err)
		}
	}
	_, got := expectedAndGot(gateErr)
	payload := map[string]any{
		"expected_sha": expectedSHA,
		"got_sha":      got,
		"errors":       []string{gateErr.Error()},
	}
	if err := d.Store.AddEvent(ctx, env.ID, "delivery", "verify_failed",
		PayloadJSON(payload)); err != nil {
		d.logf("delivery verify_failed event", "envelope", env.ID, "error", err)
	}
	d.logf("delivery gate 2 refused", "envelope", env.ID, "error", gateErr)
}

// expectedAndGot pulls the two hashes out of a gate failure for the event
// payload, so the audit trail states them as fields rather than buried in a
// message string.
func expectedAndGot(err error) (string, string) {
	var expected, got string
	if err == nil {
		return expected, got
	}
	msg := err.Error()
	for _, part := range strings.Split(msg, " ") {
		p := strings.Trim(part, ",;")
		if len(p) == 64 && isHex(p) {
			if got == "" {
				got = p
			} else {
				expected = p
			}
		}
	}
	return expected, got
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// DownloadToken is one large-document link's raw token: 32 random bytes, hex.
type DownloadToken [32]byte

// NewDownloadToken mints one.
func NewDownloadToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("signflow: download token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// HashDownloadToken is the value the database stores. The raw token exists only
// in the message that was sent.
func HashDownloadToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// DownloadLinkFor builds the URL a party clicks. It lives under /d/, is not
// under /api/v1, and carries the raw token — the only place the token appears.
func DownloadLinkFor(base, token string) string {
	base = strings.TrimRight(base, "/")
	return base + "/d/" + token
}

// DownloadHandler serves one large-document link. It is not an API route: no
// authentication, no scope, no party list — one token resolves to one document,
// and an expired or unknown token is the same 410 answer, so nothing can be
// learned by probing.
func (d *Deps) DownloadHandler(store *signstore.Store, w http.ResponseWriter, r *http.Request, token string) {
	if !validDownloadToken(token) {
		writeDownloadGone(w)
		return
	}
	row, err := store.GetDownload(r.Context(), HashDownloadToken(token))
	if err != nil {
		if errors.Is(err, signstore.ErrNotFound) {
			writeDownloadGone(w)
			return
		}
		d.logf("download lookup", "error", err)
		writeDownloadGone(w)
		return
	}
	if exp, err := time.Parse(time.RFC3339, row.ExpiresAt); err != nil || exp.Before(d.clock()) {
		writeDownloadGone(w)
		return
	}
	data, report, err := d.verifyGate(r.Context(), row.SHA256)
	if err != nil {
		// Gate 2 guards the download path as strictly as the attachment path:
		// a link is not a way to hand out bytes that do not verify.
		d.logf("download gate 2", "envelope", row.EnvelopeID, "error", err)
		writeDownloadGone(w)
		return
	}
	slug := "document"
	if env, err := store.GetEnvelope(r.Context(), row.EnvelopeID); err == nil {
		slug = slugTitle(env.Title)
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+slug+`-signed.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Document-Sha256", row.SHA256)
	w.Header().Set("X-Document-Signers", fmt.Sprint(len(report.Signers)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeDownloadGone(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	_, _ = w.Write([]byte(`{"error":{"code":"download_expired","message":"this link is not available"}}` + "\n"))
}

func validDownloadToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	return isHex(token)
}

// signedSubject names the message that carries a party's copy of the finished
// document, so the subject line and the attachment say the same thing.
func signedSubject(env *signstore.Envelope, slug string) string {
	return "Signed document " + slug
}

// short is the log form of a hash: enough to compare two by eye, not enough to
// paste into a command.
func short(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

// slugTitle turns a document title into a file name. A title is user data; a
// file name is not a place user data gets to run.
func slugTitle(title string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(title) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "document"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
