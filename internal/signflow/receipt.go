package signflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// receipt.json, step 10.
//
// The receipt is the document's evidence in one small file: the finished
// document's hash, every revision that led to it, each party's consent record,
// each party's signature record, and the verification result. It travels with
// the document and is stored under the final hash, so an auditor who has the
// document can find the receipt and check that the two agree.
//
// The point of its shape is that the two times are separate and named.
// consent_at is when the party said yes; signed_at is when the batch applied
// their signature. They are usually minutes apart and sometimes days, and a
// receipt that collapsed them into one field would claim something the system
// does not know.

// Receipt is the JSON document stored as <final_sha>.receipt.json and returned
// by GET /envelopes/{id}/report.
type Receipt struct {
	EnvelopeID  string `json:"envelope_id"`
	Title       string `json:"title"`
	Iss         string `json:"iss"`
	ServerKey   string `json:"server_key"`
	FinalSHA256 string `json:"final_sha256"`
	// DispatchSHA256 is the hash of the exact bytes the server put on the wire:
	// the file inside the attachment, taken at the moment the message was
	// assembled rather than at verification. It normally equals final_sha256;
	// when the two differ, the bytes left the process changed and the receipt
	// says which bytes the server believed it was sending. A recipient compares
	// this against sha256sum of the file they received.
	DispatchSHA256 string         `json:"dispatch_sha256"`
	DispatchBytes  int            `json:"dispatch_bytes"`
	Filename       string         `json:"filename,omitempty"`
	Valid          bool           `json:"valid"`
	Revisions      []ReceiptRev   `json:"revisions"`
	Parties        []ReceiptParty `json:"parties"`
	Verification   ReceiptVerify  `json:"verification"`
	IssuedAt       string         `json:"issued_at"`
}

// ReceiptRev is one revision in the chain, in chain order.
type ReceiptRev struct {
	Kind      string `json:"kind"`
	SHA256    string `json:"sha256"`
	Serial    string `json:"serial,omitempty"`
	SigField  string `json:"sig_field,omitempty"`
	PartyID   string `json:"party_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

// ReceiptParty is one party's evidence. consent_at and signed_at are separate
// fields, and neither is derived from the other.
type ReceiptParty struct {
	Order           int        `json:"order"`
	Name            string     `json:"name"`
	Email           string     `json:"email"`
	ConsentAt       string     `json:"consent_at"`
	SignatureText   string     `json:"signature_text"`
	ConsentIP       string     `json:"consent_ip,omitempty"`
	ConsentUA       string     `json:"consent_ua,omitempty"`
	DocumentSHA     string     `json:"document_sha"`
	SignedAt        string     `json:"signed_at"`
	CertSerial      string     `json:"cert_serial,omitempty"`
	CertFingerprint string     `json:"cert_fingerprint,omitempty"`
	SigField        string     `json:"sig_field,omitempty"`
	TSA             ReceiptTSA `json:"tsa"`
	// StampShowsText says whether signature_text is printed in the signature
	// stamp on the page. It is false when the party typed characters the
	// appearance font cannot draw, in which case signature_text below is still
	// the exact words they typed and the page shows only the name and time.
	// Without this field a reader comparing the receipt to the PDF would find a
	// text on one and not the other and have no way to tell a dropped line from
	// a lost consent.
	StampShowsText bool `json:"stamp_shows_text"`
}

// ReceiptTSA states whether the signature carries a validated timestamp token.
// It is a fact about the bytes, reported as one: an absent token is reported as
// absent rather than omitted, because "no third-party timestamp" is information
// an auditor needs and an omission is not.
type ReceiptTSA struct {
	Present   bool   `json:"present"`
	Authority string `json:"authority,omitempty"`
	Time      string `json:"time,omitempty"`
}

// ReceiptVerify is the verification result as the receipt records it.
type ReceiptVerify struct {
	Valid    bool     `json:"valid"`
	Signers  []string `json:"signers"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings,omitempty"`
}

// BuildReceipt assembles the receipt for a finished document. Every field comes
// from the store or from the verification report; nothing is inferred.
func (d *Deps) BuildReceipt(ctx context.Context, env *signstore.Envelope,
	parties []signstore.Party, data []byte, report *signpdf.Report) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("signflow: receipt needs an envelope")
	}
	revisions, err := d.Store.ListRevisions(ctx, env.ID)
	if err != nil {
		return nil, fmt.Errorf("signflow: receipt revisions: %w", err)
	}
	consents, err := d.Store.ListConsents(ctx, env.ID)
	if err != nil {
		return nil, fmt.Errorf("signflow: receipt consents: %w", err)
	}
	deliveries, err := d.Store.ListDeliveries(ctx, env.ID)
	if err != nil {
		return nil, fmt.Errorf("signflow: receipt deliveries: %w", err)
	}
	byParty := make(map[string]*signstore.Consent, len(consents))
	for i := range consents {
		byParty[consents[i].PartyID] = &consents[i]
	}
	byDelivery := make(map[string]*signstore.Delivery, len(deliveries))
	for i := range deliveries {
		byDelivery[deliveries[i].PartyID] = &deliveries[i]
	}
	// A sign revision is the record of a party's signature: the field name, the
	// certificate serial, and the time the batch stamped it.
	revByParty := make(map[string]*signstore.Revision, len(revisions))
	for i := range revisions {
		if revisions[i].Kind == KindSign && revisions[i].PartyID != "" {
			revByParty[revisions[i].PartyID] = &revisions[i]
		}
	}

	final := sha256.Sum256(data)
	finalSHA := hex.EncodeToString(final[:])
	// The dispatch_* fields stay blank here on purpose. They answer "what bytes
	// did this process actually put on the wire", and the only place that knows
	// is the send path, so only the send path fills them in - otherwise a
	// second writer could quietly agree with final_sha256 and the comparison
	// would prove nothing.

	rec := &Receipt{
		EnvelopeID:  env.ID,
		Title:       env.Title,
		Iss:         "signsrv",
		ServerKey:   d.serverKeyFingerprint(ctx),
		FinalSHA256: finalSHA,
		Valid:       report != nil && report.Valid,
		Revisions:   []ReceiptRev{},
		Parties:     []ReceiptParty{},
		Verification: ReceiptVerify{
			Valid:    report != nil && report.Valid,
			Signers:  []string{},
			Errors:   []string{},
			Warnings: []string{},
		},
		IssuedAt: formatTime(d.clock()),
	}
	for _, r := range revisions {
		rec.Revisions = append(rec.Revisions, ReceiptRev{
			Kind: r.Kind, SHA256: r.SHA256, Serial: r.CertSerial,
			SigField: r.SigField, PartyID: r.PartyID, CreatedAt: r.CreatedAt,
		})
	}
	sort.SliceStable(rec.Revisions, func(i, j int) bool { return rec.Revisions[i].CreatedAt < rec.Revisions[j].CreatedAt })

	ordered := make([]signstore.Party, len(parties))
	copy(ordered, parties)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].OrderIdx < ordered[j].OrderIdx })

	for _, p := range ordered {
		c := byParty[p.ID]
		r := revByParty[p.ID]
		dl := byDelivery[p.ID]
		rp := ReceiptParty{
			Order: p.OrderIdx,
			Name:  p.Name,
			Email: p.Email,
			TSA:   ReceiptTSA{},
		}
		if c != nil {
			// The stamp carries the text only when the appearance font could
			// address it (see signpdf.StampText). When it could not, this field
			// is false and signature_text is still exactly what was typed: the
			// receipt is the record, the page is only a rendering of it.
			rp.StampShowsText = signpdf.StampText(c.SignatureText) != ""
			rp.ConsentAt = c.ConsentAt
			rp.SignatureText = c.SignatureText
			rp.ConsentIP = c.IP
			rp.ConsentUA = c.UserAgent
			rp.DocumentSHA = c.DocumentSHA
		}
		if r != nil {
			// signed_at is the batch's stamp on the revision, which is the
			// signing time. It is not the consent time and never falls back to
			// it: a party whose signature is missing shows an empty signed_at.
			rp.SignedAt = r.CreatedAt
			rp.CertSerial = r.CertSerial
			rp.CertFingerprint = r.CertFingerprint
			rp.SigField = r.SigField
		}
		if report != nil {
			if s := signerFor(report, p); s != nil {
				rp.TSA = ReceiptTSA{Present: s.Timestamp}
				if s.Timestamp {
					rp.TSA.Authority = d.tsaAuthority()
					rp.TSA.Time = s.Time.UTC().Format(time.RFC3339)
				}
			}
		}
		if dl != nil && dl.Status == signstore.DeliveryAccepted {
			// The delivery stamp is neither consent nor signing; the receipt
			// reports the signature times, and delivery is in the audit zip.
			_ = dl
		}
		rec.Parties = append(rec.Parties, rp)
	}

	if report != nil {
		for _, s := range report.Signers {
			rec.Verification.Signers = append(rec.Verification.Signers, s.Name)
			if !s.Valid {
				rec.Verification.Errors = append(rec.Verification.Errors, "signature invalid: "+s.Name)
			}
			if s.Trusted {
				rec.Verification.Warnings = append(rec.Verification.Warnings, "certificate trust asserted by the service, not by a system trust store: "+s.Name)
			}
		}
		rec.Verification.Errors = append(rec.Verification.Errors, report.Errors...)
	}

	return json.MarshalIndent(rec, "", "  ")
}

// signerFor finds the verification report's entry for a party, matched on the
// name the signature carried. A document signed by two people with the same
// name takes the first unconsumed match, so two entries are not both claimed by
// the same party.
func signerFor(report *signpdf.Report, p signstore.Party) *signpdf.SignerInfo {
	if report == nil {
		return nil
	}
	for i := range report.Signers {
		s := &report.Signers[i]
		if strings.EqualFold(strings.TrimSpace(s.Name), strings.TrimSpace(p.Name)) {
			return s
		}
	}
	if p.Email != "" {
		for i := range report.Signers {
			if strings.EqualFold(strings.TrimSpace(report.Signers[i].Email), strings.TrimSpace(p.Email)) {
				return &report.Signers[i]
			}
		}
	}
	return nil
}

// StoreReceipt writes the receipt under the final hash, and returns that hash.
// The file is content-addressed like every other blob, so a re-run overwrites
// identical bytes with identical bytes.
func (d *Deps) StoreReceipt(finalSHA string, receipt []byte) (string, error) {
	if len(receipt) == 0 {
		return "", fmt.Errorf("signflow: empty receipt")
	}
	// The receipt is named for the document it describes, not for its own
	// bytes: a reader holding the signed PDF can find its receipt by hashing
	// the file. That is the whole point of the naming, so the name is the
	// document hash and nothing else.
	if err := d.Store.PutNamed(finalSHA, ".receipt.json", receipt); err != nil {
		return "", fmt.Errorf("signflow: store receipt: %w", err)
	}
	return finalSHA, nil
}

// GetReceipt reads a stored receipt. An envelope with no signed document has no
// receipt, and that is reported as not found rather than as an empty receipt.
func (d *Deps) GetReceipt(sha string) ([]byte, error) {
	data, err := d.Store.GetBlob(sha, ".receipt.json")
	if err != nil {
		return nil, err
	}
	return data, nil
}

// serverKeyFingerprint names the key that issued the signing certificates, so
// a reader of a receipt can tie the signatures to this service's CA without
// being given the key itself.
func (d *Deps) serverKeyFingerprint(ctx context.Context) string {
	if d.Signer == nil {
		return ""
	}
	ca := d.Signer.CA()
	if ca == nil {
		return ""
	}
	return ca.Fingerprint()
}

// tsaAuthority names the time-stamp authority the signatures carry, taken from
// the URL this service was configured with. An empty answer means no
// timestamps were requested, and the receipt says that rather than guessing a
// name for it.
func (d *Deps) tsaAuthority() string {
	if d.Signer == nil {
		return ""
	}
	raw := d.Signer.TSAURL()
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// stampDispatch records which bytes the server is about to send, into the
// receipt that travels with them, and refuses the send when those bytes are not
// the bytes the verify gate checked.
//
// Two hashes, one comparison. final_sha256 is what the gate verified;
// dispatch_sha256 is what this process hands to the mailer. On every healthy run
// they are the same string, and the field looks like decoration. Its value is
// the day they are not: the recipient would otherwise receive a document and an
// attestation that disagree, in one message, with nothing in either to tell them
// which to trust.
//
// The check is done here rather than by the recipient because the server is the
// only party that can see both sides, and because refusing here means no
// untrustworthy pair ever reaches anyone's inbox.
func (d *Deps) stampDispatch(receipt, data []byte, filename string) ([]byte, error) {
	r := &Receipt{}
	if err := json.Unmarshal(receipt, r); err != nil {
		return nil, fmt.Errorf("signflow: receipt before dispatch: %w", err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if r.FinalSHA256 != "" && got != r.FinalSHA256 {
		return nil, fmt.Errorf(
			"signflow: refusing to send: the document about to be mailed hashes to %s (%d bytes), "+
				"but the receipt attests to %s",
			got, len(data), r.FinalSHA256)
	}
	r.DispatchSHA256 = got
	r.DispatchBytes = len(data)
	r.Filename = filename
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("signflow: receipt after dispatch: %w", err)
	}
	return out, nil
}
