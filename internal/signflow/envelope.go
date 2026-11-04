package signflow

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/schema"
	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signfill"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Create builds an envelope: store the template, fill it, certify it, record
// the parties with their links, and mark the document ready. It is all-or-
// nothing: every row is written inside one transaction, so a request that
// fails leaves no envelope, no revisions, and no parties behind.
//
// The PDF work (fill, certify) runs before the transaction. The bytes are
// content-addressed, so an aborted create leaves unreferenced files in
// storage; no row points at them, no download can reach them, and the sweep
// that collects unlinked revisions (step 10) removes them. Running the fill
// and the TSA round trip inside the transaction would hold the database write
// lock across a network call, which is the kind of stall that makes a service
// look hung.

// MaxTemplateBytes is the upload limit of the create endpoint.
const MaxTemplateBytes = 20 << 20

// MaxParties bounds one envelope.
const MaxParties = 20

// Party is one signing party as the create request supplies it.
type Party struct {
	Email  string
	Name   string
	Order  int
	Reason string
}

// Widget is the signature appearance placement, kept with the envelope so the
// batch runner can lay each party's signature on the same page.
type Widget struct {
	Field string
	Page  int
	X, Y  float64
}

// CreateRequest is the validated input of Create. The API parses the multipart
// body into this; Create re-validates, because a request that reached Create
// by another path must be refused for the same reasons.
type CreateRequest struct {
	Template  []byte
	Fill      schema.FillSpec
	Parties   []Party
	Title     string
	ExpiresIn time.Duration
	Widget    Widget
	Subject   string
	Message   string
	Actor     string // the client or admin who created it, recorded in the event
	LinkBase  string // public_url, used to build each link in the response
}

// Created is the result of Create. The plaintext link tokens appear here and
// nowhere else: the store keeps only their SHA-256.
type Created struct {
	Envelope *signstore.Envelope
	Links    []Link
	Fill     signfill.Summary
}

// Link is one party's signing link, with the raw token. Returning it is the
// only moment the raw token exists outside the request.
type Link struct {
	PartyID   string `json:"party_id"`
	Email     string `json:"email"`
	Order     int    `json:"order"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	URL       string `json:"url"`
}

// Deps is what Create needs: the store, the signing service, the state
// machine, and the identity the certification signature carries.
type Deps struct {
	Store  *signstore.Store
	Signer *signpdf.Service
	Flow   *Flow
	// CertifyAs is the service identity in the certification signature.
	CertifyAs  string
	CertReason string
	// Clock is the signing clock. It is injected so a test can make the
	// certification time deterministic.
	Clock func() time.Time
}

// ErrValidation carries a field-level problem. The API maps it to 400 with a
// hint; every create failure is this error so the answer is always the same
// shape.
type ErrValidation struct {
	Field string
	Msg   string
	Hint  string
}

// AsValidation reports whether err is a create validation failure, writing it
// to *out. The API uses it to answer 400 with the field name, so a client
// that sent an unusable fill spec gets the field back.
func AsValidation(err error, out **ErrValidation) bool {
	v, ok := err.(*ErrValidation)
	if !ok {
		return false
	}
	*out = v
	return true
}

// IsConflict reports whether err is a state conflict: the document was not in
// the state the request assumed. The API answers 409.
func IsConflict(err error) bool {
	return errors.Is(err, ErrStateConflict)
}

func (e *ErrValidation) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("signflow: %s: %s", e.Field, e.Msg)
	}
	return "signflow: " + e.Msg
}

// Create validates, fills, certifies, and stores. The order is fixed:
// validation first, so nothing is written for a request that cannot succeed.
func (d *Deps) Create(ctx context.Context, r CreateRequest) (*Created, error) {
	if d.Store == nil || d.Signer == nil || d.Flow == nil {
		return nil, errors.New("signflow: Create is missing its store, signer, or flow")
	}
	if r.Template == nil {
		return nil, validation("template", "required", "upload the PDF as the template field")
	}
	if len(r.Template) > MaxTemplateBytes {
		return nil, validation("template", fmt.Sprintf("%d bytes exceeds the %d byte limit",
			len(r.Template), MaxTemplateBytes), "reduce the file size")
	}
	if !strings.HasPrefix(string(r.Template[:min(len(r.Template), 5)]), "%PDF-") {
		return nil, validation("template", "not a PDF", "the file must start with %PDF-")
	}
	if r.Title == "" {
		return nil, validation("title", "required", "a short name for the document, up to 200 characters")
	}
	if len(r.Title) > 200 {
		return nil, validation("title", "too long", "200 characters maximum")
	}
	if r.ExpiresIn <= 0 {
		r.ExpiresIn = 168 * time.Hour
	}
	if r.ExpiresIn > 720*time.Hour {
		return nil, validation("expires_in", "exceeds 720h", "a link lifetime of 720 hours is the maximum")
	}
	if len(r.Parties) < 1 || len(r.Parties) > MaxParties {
		return nil, validation("parties", "need 1 to 20 entries",
			`[{"email":"a@x","name":"Ann","order":1,"reason":"I agree"}]`)
	}

	// Parties: every email must be a real address, unique; orders must be
	// 1..n with no gaps. A gap in the order is a hole in the signing chain,
	// so it is refused rather than renumbered.
	seen := map[string]bool{}
	orders := map[int]bool{}
	for i, p := range r.Parties {
		if p.Email == "" {
			return nil, validation("parties[].email", "required", "a signing party needs an email address")
		}
		addr, err := mail.ParseAddress(p.Email)
		if err != nil {
			return nil, validation("parties[].email", fmt.Sprintf("%q is not a valid address", p.Email),
				"one address per party, e.g. ann@example.com")
		}
		key := strings.ToLower(addr.Address)
		if seen[key] {
			return nil, validation("parties[].email", fmt.Sprintf("%q appears twice", addr.Address),
				"a party signs once; remove the duplicate")
		}
		seen[key] = true
		if p.Order < 1 {
			return nil, validation("parties[].order", "must start at 1", "order 1 is the first signer")
		}
		if orders[p.Order] {
			return nil, validation("parties[].order", fmt.Sprintf("%d appears twice", p.Order),
				"orders are 1..n, each once")
		}
		orders[p.Order] = true
		if p.Name == "" {
			r.Parties[i].Name = addr.Address
		}
	}
	for n := 1; n <= len(r.Parties); n++ {
		if !orders[n] {
			return nil, validation("parties[].order", fmt.Sprintf("missing %d", n),
				fmt.Sprintf("orders must be contiguous 1..%d with no gaps", len(r.Parties)))
		}
	}

	// Fill spec: resolves against the extracted schema. An unknown field is a
	// hard error, the same rule as `pdf-go fill --strict`.
	schemaData, err := signfill.Extract(r.Template)
	if err != nil {
		return nil, validation("template", err.Error(), "the template must be a readable PDF")
	}
	if signfill.CountFillable(schemaData) == 0 {
		return nil, validation("template", "has no fillable fields",
			"the template needs at least one form field to fill")
	}
	if err := signfill.Validate(schemaData, r.Fill); err != nil {
		return nil, validation("spec.fill", strings.TrimPrefix(err.Error(), "signfill: "),
			"run extract on the template and use its field names")
	}

	// The certified file is read-only: every field is locked, so the document
	// the parties see is the document that is signed. The caller's value for
	// lockForm is ignored on purpose; a signature over an editable form is
	// worthless.
	spec := r.Fill
	spec.LockForm = true

	rep, filled, err := signfill.Fill(r.Template, spec,
		signfill.Options{Strict: true, Path: "template"})
	if err != nil {
		return nil, validation("spec.fill", strings.TrimPrefix(err.Error(), "signfill: "),
			"the fill spec did not apply cleanly to the template")
	}
	sum := signfill.Summarize(rep)

	now := time.Now().UTC()
	if d.Clock != nil {
		now = d.Clock().UTC()
	}
	certifyAs := d.CertifyAs
	if certifyAs == "" {
		certifyAs = "signsrv"
	}
	reason := d.CertReason
	if reason == "" {
		reason = "document certified before signature collection"
	}
	out, err := d.Signer.Certify(ctx, filled, signpdf.CertifyOptions{
		Name:     certifyAs,
		Reason:   reason,
		Location: "online",
		TSAURL:   d.Signer.TSAURL(),
		Now:      now,
	})
	if err != nil {
		return nil, fmt.Errorf("signflow: certify: %w", err)
	}

	// Storage. Files are content-addressed and immutable; writing the same
	// bytes twice is a no-op, so a retried create cannot duplicate a file.
	templateSHA, err := d.Store.PutPDF(r.Template)
	if err != nil {
		return nil, fmt.Errorf("signflow: store template: %w", err)
	}
	filledSHA, err := d.Store.PutPDF(filled)
	if err != nil {
		return nil, fmt.Errorf("signflow: store filled: %w", err)
	}
	certifiedSHA, err := d.Store.PutPDF(out.Data)
	if err != nil {
		return nil, fmt.Errorf("signflow: store certified: %w", err)
	}

	id := newID()
	expiresAt := formatTime(now.Add(r.ExpiresIn))
	envelope := &signstore.Envelope{
		ID:          id,
		Title:       r.Title,
		Status:      Draft,
		TemplateSHA: templateSHA,
		FilledSHA:   filledSHA,
		CurrentSHA:  certifiedSHA,
		Serial:      out.Serial,
		ExpiresAt:   expiresAt,
		CreatedAt:   formatTime(now),
	}

	// One transaction for every row. If any insert fails the whole create is
	// rolled back, so the API never has to reason about a half-built envelope.
	partyRows := make([]signstore.Party, 0, len(r.Parties))
	links := make([]Link, 0, len(r.Parties))
	for _, p := range r.Parties {
		token, err := signauth.NewToken()
		if err != nil {
			return nil, fmt.Errorf("signflow: link token: %w", err)
		}
		party := signstore.Party{
			ID:           newID(),
			EnvelopeID:   id,
			OrderIdx:     p.Order,
			Email:        strings.ToLower(p.Email),
			Name:         p.Name,
			Status:       signstore.PartyInvited,
			TokenHash:    signauth.HashToken(token),
			TokenExpires: expiresAt,
			Reason:       p.Reason,
		}
		partyRows = append(partyRows, party)
		links = append(links, Link{
			PartyID:   party.ID,
			Email:     party.Email,
			Order:     p.Order,
			Token:     token,
			ExpiresAt: expiresAt,
			URL:       linkURL(r.LinkBase, token),
		})
	}

	err = d.Store.Tx(ctx, func(tx *sql.Tx) error {
		if err := insertEnvelope(ctx, tx, envelope); err != nil {
			return err
		}
		prev := ""
		revs := []struct {
			kind, sha string
			serial    string
			size      int
		}{
			{signstore.KindTemplate, templateSHA, "", len(r.Template)},
			{signstore.KindFilled, filledSHA, "", len(filled)},
			{signstore.KindCertified, certifiedSHA, out.Serial, len(out.Data)},
		}
		for _, rev := range revs {
			rid := newID()
			if err := insertRevision(ctx, tx, &signstore.Revision{
				ID:         rid,
				EnvelopeID: id,
				SHA256:     rev.sha,
				PrevID:     prev,
				Kind:       rev.kind,
				CertSerial: rev.serial,
				ProducedBy: "create",
				Size:       int64(rev.size),
				CreatedAt:  formatTime(now),
			}); err != nil {
				return err
			}
			// The chain links revision ids, not hashes: prev_id points at the
			// row before, which is what a reader follows to walk the document
			// history.
			prev = rid
		}
		for i := range partyRows {
			if err := insertParty(ctx, tx, &partyRows[i]); err != nil {
				return err
			}
		}
		payload, err := json.Marshal(map[string]any{
			"title":     r.Title,
			"parties":   len(r.Parties),
			"expires":   expiresAt,
			"widget":    r.Widget,
			"subject":   r.Subject,
			"message":   r.Message,
			"fill":      sum,
			"certified": certifiedSHA,
		})
		if err != nil {
			return err
		}
		return insertEvent(ctx, tx, id, r.Actor, "created", string(payload))
	})
	if err != nil {
		return nil, fmt.Errorf("signflow: create: %w", err)
	}

	// draft -> ready goes through the machine, so the status change is in the
	// table and is audited. A direct write to `ready` would be a transition
	// outside the table.
	if err := d.Flow.Transition(ctx, envelope, Ready, r.Actor, `{"to":"ready"}`); err != nil {
		return nil, fmt.Errorf("signflow: ready: %w", err)
	}

	return &Created{Envelope: envelope, Links: links, Fill: sum}, nil
}

func validation(field, msg, hint string) error {
	return &ErrValidation{Field: field, Msg: msg, Hint: hint}
}

func newID() string {
	var b [16]byte
	if err := randRead(b[:]); err != nil {
		// 16 random bytes is the envelope and party id. A failure here means
		// the system entropy source is broken, which every caller treats as a
		// server fault, so the message says so.
		return "id-" + hex.EncodeToString(sha48())
	}
	return hex.EncodeToString(b[:])
}

func sha48() []byte {
	sum := sha256.Sum256([]byte("signflow entropy failure"))
	return sum[:16]
}

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func linkURL(base, token string) string {
	if base == "" {
		return "/s/" + token
	}
	return strings.TrimSuffix(base, "/") + "/s/" + token
}

// linkURLRegex is exported for tests that check a built link.
var linkURLRegex = regexp.MustCompile(`^/s/[A-Za-z0-9_-]{43}$`)
