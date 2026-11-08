package signflow

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"
	"time"
	"unicode"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Consent is data. Nothing in this file opens a PDF, writes a revision, or
// touches a key: the party is recording a decision about bytes they reviewed,
// and the signing of those bytes is a later, separate, queued step. Keeping
// the two apart is what makes the consent defensible — it says what the party
// saw, and the signature says what the service did.
//
// MaxSignatureText is the length ceiling of an e-signature. 120 characters is
// longer than any real name-plus-title line, so a longer string is a payload
// probe, not a signature.
const MaxSignatureText = 120

// MaxImageBytes is the ceiling of a consent image: 512 KB. The image is
// handwriting, not a scan; anything bigger is an upload attempt.
const MaxImageBytes = 512 * 1024

// MaxImageEdge is the pixel ceiling of a consent image on either side.
const MaxImageEdge = 2000

// DeclineReasonLength is the ceiling of a decline reason.
const DeclineReasonLength = 1000

// ErrDeclineReason is a decline reason the rules refuse. 400.
var ErrDeclineReason = errors.New("signflow: decline reason is not valid")

// ConsentInput is everything a party may send with a consent, and nothing
// else. The type is deliberately tiny: a field here is a field the signing
// page controls, so the absence of order, certificate, key, TSA, and field
// rectangles is the security property, and the test suite greps this
// declaration to prove it stays that way.
type ConsentInput struct {
	SignatureText string `json:"signature_text"`
	Consent       bool   `json:"consent"`
	Image         string `json:"image"`
	DocumentSHA   string `json:"document_sha"`

	// IP and UserAgent are facts about the request, filled in by the
	// handler from the transport. They are not read from the body.
	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

// ConsentResult is the answer to a consent.
type ConsentResult struct {
	OK           bool   `json:"ok"`
	Status       string `json:"status"`
	AllConsented bool   `json:"all_consented"`
	ConsentID    string `json:"consent_id"`
}

// DeclineResult is the answer to a decline. The request is over, and the
// answer says so without describing the internals.
//
// Whether the drafter was told is deliberately not here. The drafter's address
// is not the party's to learn — a party who declined a contract now holds a
// piece of the other side's contact details they did not ask for and have no
// use for — and a field that says "we tried to tell them and failed" invites a
// party to re-decline to fix a problem that is not theirs. The outcome of the
// notification goes to the event log, which the operator reads.
type DeclineResult struct {
	OK      bool   `json:"ok"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ValidateSignatureText is the signature rule: present, at most 120
// characters, and no control characters. Control characters are the reason
// this is not just a length check — a newline inside the text that is later
// embedded in a PDF appearance stream is how injection starts.
func ValidateSignatureText(s string) error {
	t := strings.TrimSpace(s)
	if t == "" {
		return fmt.Errorf("%w: signature_text is required", ErrSignatureText)
	}
	if len([]rune(t)) > MaxSignatureText {
		return fmt.Errorf("%w: signature_text is longer than %d characters",
			ErrSignatureText, MaxSignatureText)
	}
	for _, r := range t {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: signature_text contains a control character", ErrSignatureText)
		}
	}
	return nil
}

// decodeConsentImage validates and decodes the optional handwriting image.
//
// A data: prefix is accepted because that is how a canvas produces a data
// URL; the base64 body is decoded strictly, so padding and alphabet are
// enforced. Magic bytes are checked before any decoder runs, so a PNG claim on
// a JPEG body is refused rather than re-encoded.
func decodeConsentImage(s string) (data []byte, contentType string, width, height int, err error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil, "", 0, 0, fmt.Errorf("%w: image is empty", ErrConsentImage)
	}
	if i := strings.Index(raw, ";base64,"); strings.HasPrefix(raw, "data:") && i >= 0 {
		raw = raw[i+len(";base64,"):]
	}
	// Newlines ride along in a canvas data URL; they are not part of the
	// payload and stripping them keeps the size check honest.
	raw = strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(raw)

	data, derr := base64.StdEncoding.DecodeString(raw)
	if derr != nil {
		return nil, "", 0, 0, fmt.Errorf("%w: image is not valid base64", ErrConsentImage)
	}
	if len(data) == 0 {
		return nil, "", 0, 0, fmt.Errorf("%w: image is empty", ErrConsentImage)
	}
	if len(data) > MaxImageBytes {
		return nil, "", 0, 0, fmt.Errorf("%w: image is larger than %d KB",
			ErrConsentImage, MaxImageBytes/1024)
	}
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		contentType = "image/png"
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		contentType = "image/jpeg"
	default:
		return nil, "", 0, 0, fmt.Errorf("%w: image is not PNG or JPEG", ErrConsentImage)
	}
	cfg, _, cerr := image.DecodeConfig(bytes.NewReader(data))
	if cerr != nil {
		return nil, "", 0, 0, fmt.Errorf("%w: image cannot be decoded: %v", ErrConsentImage, cerr)
	}
	if cfg.Width > MaxImageEdge || cfg.Height > MaxImageEdge || cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, "", 0, 0, fmt.Errorf("%w: image is larger than %dx%d pixels",
			ErrConsentImage, MaxImageEdge, MaxImageEdge)
	}
	return data, contentType, cfg.Width, cfg.Height, nil
}

// Consent records a party's decision about the certified document.
//
// The rules run in the order of the API table, first failure wins, and every
// refusal is an event: a consent that arrives for the wrong document, from a
// party that has declined, on an expired link, is exactly the trail an
// investigator reads.
//
// When every rule passes, one transaction writes the consent, moves the party,
// invalidates the session, advances the envelope, and — on the last consent —
// queues the signing batch. The batch is queued, never run here: no signing
// happens inside an HTTP request.
func (d *Deps) Consent(ctx context.Context, token string, in ConsentInput, now time.Time) (*ConsentResult, error) {
	store := d.Store

	// 1 + 2 + 8 (token/envelope/expiry): resolution carries the token
	// deadline, the envelope status, and envelope expiry.
	s, err := ResolveSigner(ctx, store, token, now)
	if err != nil {
		return nil, err
	}
	p, env := s.Party, s.Envelope

	// A party that has consented, declined, or expired cannot consent again.
	// This is checked before the payload rules so a replay of a valid body on
	// a closed party is a 409, not an invitation to keep probing.
	if p.Status != signstore.PartyInvited && p.Status != signstore.PartyClaimed {
		return nil, fmt.Errorf("%w: party is %s", ErrPartyStatus, string(p.Status))
	}

	// 3. consent: true is the affirmative act. Absent, false, or a non-boolean
	// (which fails JSON binding upstream) is a 400.
	if !in.Consent {
		return nil, ErrConsentRequired
	}

	// 4. the e-signature text.
	if err := ValidateSignatureText(in.SignatureText); err != nil {
		return nil, err
	}

	// 5. the document. The party's view carries the sha it was shown; a
	// consent about a different sha is a consent about a document the service
	// is not holding, so it is refused and the party is told to reload.
	want := env.CurrentSHA
	got := strings.ToLower(strings.TrimSpace(in.DocumentSHA))
	if got == "" || want == "" || got != strings.ToLower(want) {
		return nil, ErrDocumentSHA
	}

	// 6. the optional image.
	var (
		imageData   []byte
		contentType string
		width       int
		height      int
	)
	if strings.TrimSpace(in.Image) != "" {
		data, ct, w, h, ierr := decodeConsentImage(in.Image)
		if ierr != nil {
			return nil, ierr
		}
		imageData, contentType, width, height = data, ct, w, h
	}

	// 7. the envelope has to be open for signatures.
	if env.Status != signstore.StatusSent && env.Status != signstore.StatusCollecting {
		return nil, fmt.Errorf("%w: envelope is %s", ErrStateConflict, string(env.Status))
	}

	// The image is stored before the transaction: the blob is content
	// addressed, so a write that is never referenced is a harmless orphan,
	// while a transaction that fails after a blob write leaves the file
	// available for the retry.
	imageSHA := ""
	if len(imageData) > 0 {
		ext := "png"
		if contentType == "image/jpeg" {
			ext = "jpg"
		}
		sha, perr := store.PutBlob(imageData, ext)
		if perr != nil {
			return nil, fmt.Errorf("signflow: store consent image: %w", perr)
		}
		imageSHA = sha
	}

	at := formatTime(now)
	consentID := newID()
	consent := &signstore.Consent{
		ID: consentID, PartyID: p.ID, EnvelopeID: env.ID,
		SignatureText: strings.TrimSpace(in.SignatureText),
		DocumentSHA:   strings.ToLower(want),
		ImageSHA:      imageSHA,
		Appearance: jsonPayload(map[string]any{
			"content_type": contentType, "width": width, "height": height,
			"bytes": len(imageData), "has_image": imageSHA != "",
		}),
		ConsentAt: at, IP: in.IP, UserAgent: in.UserAgent,
	}

	result := &ConsentResult{OK: true, Status: string(env.Status)}
	err = store.Tx(ctx, func(tx *sql.Tx) error {
		// The consent row first: everything after this describes the party
		// and the envelope, and a consent with no row is a consent that did
		// not happen.
		if _, err := tx.ExecContext(ctx,
			`insert into consents(id, party_id, envelope_id, signature_text, document_sha,
			 image_sha, appearance_json, consent_at, ip, user_agent)
			 values(?,?,?,?,?,?,?,?,?,?)`,
			consent.ID, consent.PartyID, consent.EnvelopeID, consent.SignatureText,
			consent.DocumentSHA, nullString(consent.ImageSHA), consent.Appearance,
			consent.ConsentAt, consent.IP, consent.UserAgent); err != nil {
			return fmt.Errorf("signflow: insert consent: %w", err)
		}

		// The party becomes consented and loses its session in the same
		// statement: one consent per party, and the cookie that proved the
		// session cannot be replayed after it.
		if _, err := tx.ExecContext(ctx,
			`update parties set status = 'consented', consent_at = ?, session_hash = null
			 where id = ?`, at, p.ID); err != nil {
			return fmt.Errorf("signflow: consent party: %w", err)
		}

		// The consent event. The payload is a digest of the record, not the
		// record: the consent row holds the IP and the text, and the audit
		// trail says that a consent exists, for which document, at when.
		if err := addEvent(ctx, tx, env.ID, "party:"+p.ID, "consent",
			jsonPayload(map[string]any{"consent_id": consentID,
				"document_sha": consent.DocumentSHA, "consent_at": at,
				"sha256": HashLink(consent.ID + consent.SignatureText + consent.DocumentSHA)})); err != nil {
			return err
		}

		// sent -> collecting on the first consent, through the machine's
		// table. The transition is in this transaction, so an envelope marked
		// collecting always has a consent behind it.
		if env.Status == signstore.StatusSent {
			if !Can(Sent, Collecting) {
				return fmt.Errorf("signflow: %w: sent -> collecting is not allowed", ErrStateConflict)
			}
			if err := updateStatus(ctx, tx, env.ID, Collecting, stampColumn(Collecting)); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, env.ID, "party:"+p.ID, "transition",
				transitionPayload(Collecting, `{"reason":"first consent"}`)); err != nil {
				return err
			}
			result.Status = string(Collecting)
		}

		// The last consent queues the batch. The count is done inside the
		// transaction, after this party's row was written, so exactly one
		// concurrent consent sees "all consented" and enqueues.
		var pending int
		if err := tx.QueryRowContext(ctx,
			`select count(*) from parties where envelope_id = ? and status != 'consented'`,
			env.ID).Scan(&pending); err != nil {
			return fmt.Errorf("signflow: count pending parties: %w", err)
		}
		if pending == 0 {
			if _, err := tx.ExecContext(ctx,
				`insert into batch_queue(envelope_id, attempts, next_at, enqueued_at)
				 values(?, 0, ?, ?)
				 on conflict(envelope_id) do update set next_at = excluded.next_at,
					lease_until = null`, env.ID, at, at); err != nil {
				return fmt.Errorf("signflow: queue batch: %w", err)
			}
			if err := addEvent(ctx, tx, env.ID, "system", "batch_queued",
				jsonPayload(map[string]any{"queued_at": at, "document_sha": consent.DocumentSHA})); err != nil {
				return err
			}
			result.AllConsented = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result.ConsentID = consentID
	return result, nil
}

// Decline records a party refusing the request, and closes it.
//
// A refusal is not "this party is done": it is "the document will not be
// signed". The envelope goes to failed, and every other party's link and
// session are destroyed, so nobody continues to work on a request that is
// over. The reason is stored for the creator, and the admin is notified
// through an event, which is what the worker turns into a message.
func (d *Deps) Decline(ctx context.Context, token, reason string, in DeclineMeta, now time.Time) (*DeclineResult, error) {
	store := d.Store
	s, err := ResolveSigner(ctx, store, token, now)
	if err != nil {
		return nil, err
	}
	p, env := s.Party, s.Envelope

	if p.Status == signstore.PartyConsented {
		return nil, fmt.Errorf("%w: party has already consented", ErrPartyStatus)
	}
	if p.Status == signstore.PartyDeclined {
		return nil, fmt.Errorf("%w: party has already declined", ErrPartyStatus)
	}
	if env.Status != signstore.StatusSent && env.Status != signstore.StatusCollecting {
		return nil, fmt.Errorf("%w: envelope is %s", ErrStateConflict, string(env.Status))
	}
	if len([]rune(reason)) > DeclineReasonLength {
		return nil, fmt.Errorf("%w: reason is longer than %d characters",
			ErrDeclineReason, DeclineReasonLength)
	}

	at := formatTime(now)
	reason = strings.TrimSpace(reason)
	result := &DeclineResult{OK: true, Status: string(Failed),
		Message: "the request is closed"}

	err = store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`update parties set status = 'declined', reason = ?, session_hash = null
			 where id = ?`, reason, p.ID); err != nil {
			return fmt.Errorf("signflow: decline party: %w", err)
		}
		if err := addEvent(ctx, tx, env.ID, "party:"+p.ID, "declined",
			jsonPayload(map[string]any{"reason": reason, "ip": in.IP, "ua": in.UserAgent})); err != nil {
			return err
		}

		// The envelope stops. Both sent and collecting can reach failed, so
		// this is the machine moving, not a write around it.
		if !Can(env.Status, Failed) {
			return fmt.Errorf("signflow: %w: %s -> failed", ErrStateConflict, string(env.Status))
		}
		if err := updateStatus(ctx, tx, env.ID, Failed, stampColumn(Failed)); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, env.ID, "party:"+p.ID, "transition",
			transitionPayload(Failed, `{"reason":"declined"}`)); err != nil {
			return err
		}

		// No session survives the decline. The token hashes stay: a party whose
		// link is still in its inbox must be told the request is closed (410),
		// and the only way to tell it is for the link to still resolve.
		if _, err := tx.ExecContext(ctx,
			`update parties set session_hash = null
			 where envelope_id = ? and id != ?`, env.ID, p.ID); err != nil {
			return fmt.Errorf("signflow: close links: %w", err)
		}

		// The admin-facing event. The worker's mail queue is the delivery
		// channel; the event is the record that the request died and why.
		if err := addEvent(ctx, tx, env.ID, "system", "declined_notify",
			jsonPayload(map[string]any{"party_id": p.ID, "party_name": p.Name,
				"reason": reason, "at": at})); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Tell the drafter. The decline is committed, so a failure here cannot
	// undo it and must not be returned as one: the party's screen would say
	// "your decline failed" when it did not, and a party who believes that
	// signs again or walks away. So the failure is reported where an operator
	// reads it — an event naming the decline whose notice did not go out —
	// rather than to a party who can do nothing about it.
	//
	// It happens here, after the transaction, for the same reason cancel
	// queues after its transition: the queue row must not describe a decline
	// that a rollback then erased.
	//
	// The party's own words are carried across verbatim. A decline without a
	// reason reads to the drafter exactly like a party who never opened the
	// link, and the whole reason this notice exists is that they were
	// indistinguishable before.
	if _, err := NotifyDrafter(ctx, store, env.ID, p.ID, KindDeclined, reason); err != nil {
		if eerr := store.AddEvent(ctx, env.ID, "system", "declined_notify_failed",
			jsonPayload(map[string]any{"party_id": p.ID, "error": err.Error()})); eerr != nil {
			return nil, eerr
		}
	}

	return result, nil
}

// DeclineMeta is the transport facts of a decline.
type DeclineMeta struct {
	IP        string
	UserAgent string
}

// nullString maps "" to a SQL NULL, so an absent image is stored as NULL and
// not as an empty string, which the schema reads as "no image".
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
