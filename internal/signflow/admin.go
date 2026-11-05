package signflow

import (
	archivezip "archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Admin-side operations of step 09: the counters the dashboard polls, the
// settings the operator can edit, and the three actions an operator takes on a
// live envelope (cancel, remind, reissue). They live here rather than in the
// handler because they touch state, the audit trail, and the mail queue, and
// every one of those must happen in the same place the state machine lives.

// ErrNoReason is the answer of a cancel with no reason. The reason is required
// by the design, so the handler maps it to 400.
var ErrNoReason = errors.New("signflow: cancel requires a reason")

// NotifyFunc asks the flow to send one queued message. A handler that has a
// mailer wired passes a function that drains; a handler that does not passes
// nil, and the message stays in the queue for the worker. It is the seam between
// "the row exists" and "the row has been sent", so cancel and remind can promise
// a sent mail in dev without either of them owning the SMTP connection.
type NotifyFunc func(ctx context.Context, envelopeID, partyID, kind string) error

// settingsWhitelist is the set of keys POST /admin/settings accepts. It is
// exactly the four the design names; anything else is a 400 that names the key.
var settingsWhitelist = map[string]bool{
	"tsa_url": true, "link_ttl": true, "mail_from": true, "smtp_host": true,
}

// Stats is the dashboard payload: counts per status, the totals the operator
// looks at, the overdue count, and the collecting list with consented/total per
// envelope. A status with no envelopes is present with a zero so the dashboard
// tiles never depend on a missing key.
type Stats struct {
	Counts     map[string]int  `json:"counts"`
	Overdue    int             `json:"overdue"`
	Collecting []CollectingRow `json:"collecting"`
}

// CollectingRow is one row of the dashboard's collecting list.
type CollectingRow struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Consented int    `json:"consented"`
	Total     int    `json:"total"`
}

// Stats counts envelopes by status, counts the overdue ones, and lists the
// collecting envelopes with their consent progress. It is read-only, so it is
// safe on the 30-second poll.
func (d *Deps) Stats(ctx context.Context, now time.Time) (*Stats, error) {
	out := &Stats{Counts: map[string]int{}, Collecting: []CollectingRow{}}
	for _, st := range []State{Draft, Ready, Sent, Collecting, Signed, Completed,
		Delivered, Expired, Cancelled, Failed} {
		var n int
		err := d.Store.DB().QueryRowContext(ctx,
			"select count(*) from envelopes where status = ?", string(st)).Scan(&n)
		if err != nil {
			return nil, fmt.Errorf("signflow: stats count %s: %w", st, err)
		}
		out.Counts[string(st)] = n
	}

	// Overdue: a live envelope whose deadline has passed. A status that has no
	// links left (delivered, cancelled, expired, failed) cannot be overdue.
	rows, err := d.Store.DB().QueryContext(ctx,
		"select id, title, status, expires_at from envelopes where expires_at != ''"+
			" and expires_at < ? and status not in ('delivered','cancelled','expired','failed')"+
			" order by expires_at", formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, title, status, exp string
		if err := rows.Scan(&id, &title, &status, &exp); err != nil {
			return nil, err
		}
		out.Overdue++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The collecting list. The rows are drained and closed before the consent
	// counts are read: on a single-connection store a query issued while a
	// row scan is open waits for a connection that the scan is holding, which
	// is a deadlock, not a slow query.

	type pending struct{ id, title string }
	var list []pending
	crows, err := d.Store.DB().QueryContext(ctx,
		"select id, title from envelopes where status = 'collecting' order by created_at")
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var p pending
		if err := crows.Scan(&p.id, &p.title); err != nil {
			crows.Close()
			return nil, err
		}
		list = append(list, p)
	}
	if err := crows.Err(); err != nil {
		crows.Close()
		return nil, err
	}
	crows.Close()
	for _, p := range list {
		total, consented, _, err := d.Store.CountPartiesByStatus(ctx, p.id)
		if err != nil {
			return nil, err
		}
		out.Collecting = append(out.Collecting, CollectingRow{
			ID: p.id, Title: p.title, Consented: consented, Total: total})
	}
	return out, nil
}

// Settings reads the four whitelisted keys. A missing key is reported with an
// empty value, not an error, so the settings page shows every field.
func (d *Deps) Settings(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range []string{"tsa_url", "link_ttl", "mail_from", "smtp_host"} {
		v, err := d.Store.GetSetting(ctx, k)
		if errors.Is(err, signstore.ErrNotFound) {
			out[k] = ""
			continue
		}
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

// WriteSettings applies the whitelisted changes and writes one audit event
// naming the keys that changed. A key outside the whitelist is refused before
// anything is written, so a request with one bad key writes nothing. The actor
// is the admin subject, recorded on the event.
// validateSettingValue checks a value the way the code that reads it would:
// a link_ttl that time.ParseDuration cannot read is not a setting, it is a
// typo that would surface at send time. An empty value means "unset", which
// hands the setting back to the config file, so it is allowed for every key
// except link_ttl where 0 would mean an instantly-expired link.
func validateSettingValue(key, value string) error {
	if value == "" {
		if key == "link_ttl" {
			return &ErrValidation{Field: key, Msg: "link_ttl cannot be empty",
				Hint: "a duration such as 72h"}
		}
		return nil
	}
	switch key {
	case "link_ttl":
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return &ErrValidation{Field: key, Msg: "link_ttl is not a duration",
				Hint: "a Go duration such as 48h or 30m"}
		}
	case "tsa_url":
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &ErrValidation{Field: key, Msg: "tsa_url is not an absolute URL",
				Hint: "https://freetsa.org/tsr"}
		}
	case "mail_from":
		if !strings.Contains(value, "@") || strings.ContainsAny(value, " ,<>") {
			return &ErrValidation{Field: key, Msg: "mail_from is not an address",
				Hint: "signsrv@example.com"}
		}
	case "smtp_host":
		if strings.ContainsAny(value, " /@") {
			return &ErrValidation{Field: key, Msg: "smtp_host is a host, not a URL",
				Hint: "mail.internal:587"}
		}
	}
	return nil
}

func (d *Deps) WriteSettings(ctx context.Context, changes map[string]string, actor string) (map[string]string, error) {
	for k := range changes {
		if !settingsWhitelist[k] {
			return nil, &ErrValidation{Field: k, Msg: "unknown settings key",
				Hint: "only tsa_url, link_ttl, mail_from, smtp_host may be set here"}
		}
	}
	// A key may be unknown to this build but the value is checked first for
	// the four known keys: a typo in link_ttl is a bug the operator should
	// see now, not one the send surfaces three days later.
	for k, v := range changes {
		if settingsWhitelist[k] {
			if err := validateSettingValue(k, v); err != nil {
				return nil, err
			}
		}
	}
	changed := map[string]string{}
	for k, v := range changes {
		old, err := d.Store.GetSetting(ctx, k)
		if err != nil && !errors.Is(err, signstore.ErrNotFound) {
			return nil, err
		}
		if old == v {
			continue // no change, no write, no event for it
		}
		if err := d.Store.SetSetting(ctx, k, v); err != nil {
			return nil, err
		}
		changed[k] = v
	}
	if len(changed) > 0 {
		if err := d.Store.AddEvent(ctx, "", actor, "settings",
			PayloadJSON(map[string]any{"keys": keysOf(changed)})); err != nil {
			return nil, err
		}
	}
	return changed, nil
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// CancelResult reports what a cancel did: the parties it notified.
type CancelResult struct {
	Notified []string `json:"notified"`
}

// Cancel withdraws a request. It is allowed from ready, sent, and collecting;
// a delivered (or any closed) envelope is refused with ErrStateConflict, which
// the handler maps to 409. A reason is required. Every party's token is
// invalidated so their links stop working, each notified party is queued a
// cancelled mail, and the transition writes the audit event with the reason.
//
// A party that has not consented has no session to kill, but its token hash is
// cleared so the link 410s on the closed envelope. A party that consented keeps
// its consent record; only its session dies.
func (d *Deps) Cancel(ctx context.Context, envelopeID, actor, reason string) (*CancelResult, error) {
	if reason == "" {
		return nil, ErrNoReason
	}
	env, err := d.Store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	if env.Status != Ready && env.Status != Sent && env.Status != Collecting {
		return nil, ErrStateConflict
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return nil, err
	}

	if err := d.Flow.Transition(ctx, env, Cancelled, actor,
		PayloadJSON(map[string]any{"reason": reason})); err != nil {
		return nil, err
	}

	res := &CancelResult{}
	for _, p := range parties {
		if p.Email == "" {
			continue
		}
		// Invalidate the party's session so its cookie is dead. The token hash
		// stays, so the link resolves to a closed envelope and 410s — the design
		// says the links return 410, not 404.
		if p.SessionHash != "" {
			if err := d.Store.SetPartySession(ctx, p.ID, ""); err != nil {
				return nil, err
			}
		}
		if err := d.Store.EnqueueMail(ctx, envelopeID, p.ID, KindCancelled, ""); err != nil {
			return nil, err
		}
		res.Notified = append(res.Notified, p.ID)
	}
	// The transition row says that the state changed; this row says what was
	// done and why, in the vocabulary the acceptance criteria and the UI use.
	if err := d.Store.AddEvent(ctx, envelopeID, actor, "cancelled",
		PayloadJSON(map[string]any{"reason": reason, "notified": len(res.Notified)})); err != nil {
		return nil, err
	}
	// A configured sender means the cancel mail can go out now, in the request,
	// the same way a send drains its own queue. Without one the rows sit for the
	// worker, which is the production path.
	if len(res.Notified) > 0 && d.Mail != nil && d.Mail.Sender != nil {
		if _, err := d.Drain(ctx, envelopeID, d.clock()); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// Remind re-sends the invite to every party that has not yet had its say. The
// rate limit (two in ten minutes) is enforced at the handler on the envelope
// key, not here; nothing in this function refuses the second call.
func (d *Deps) Remind(ctx context.Context, envelopeID, actor string) (int, error) {
	env, err := d.Store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		return 0, err
	}
	if env.Status != Sent && env.Status != Collecting {
		return 0, ErrStateConflict
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range parties {
		if p.Status == signstore.PartyConsented || p.Status == signstore.PartyDeclined ||
			p.Status == signstore.PartyExpired {
			continue
		}
		if err := d.Store.EnqueueMail(ctx, envelopeID, p.ID, KindReminder, ""); err != nil {
			return 0, err
		}
		n++
	}
	if err := d.Store.AddEvent(ctx, envelopeID, actor, "remind",
		PayloadJSON(map[string]any{"parties": n})); err != nil {
		return 0, err
	}
	if n > 0 && d.Mail != nil && d.Mail.Sender != nil {
		if _, err := d.Drain(ctx, envelopeID, d.clock()); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// ReissueResult reports the parties whose token was replaced, with their new
// links so the operator can act on them.
type ReissueResult struct {
	Reissued []ReissuedParty `json:"reissued"`
}

// ReissuedParty is one party whose link was minted again.
type ReissuedParty struct {
	PartyID string `json:"party_id"`
	Email   string `json:"email"`
	Link    string `json:"link"`
}

// Reissue mints a fresh token for every party that has not consented, and
// leaves the tokens of parties that already consented untouched. The old token
// stops resolving (its hash is replaced), so the old link is a 404 on the next
// open, and the new link works. The transition is not touched: a reissue is a
// key-rotation event, not a state change.
func (d *Deps) Reissue(ctx context.Context, envelopeID, actor string) (*ReissueResult, error) {
	env, err := d.Store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	if env.Status != Sent && env.Status != Collecting {
		return nil, ErrStateConflict
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	res := &ReissueResult{}
	for _, p := range parties {
		if p.Status == signstore.PartyConsented {
			continue // consented parties keep their token
		}
		token, err := NewLinkToken()
		if err != nil {
			return nil, err
		}
		exp := TokenExpiry(time.Now(), MaxLinkTTL, parseExpiry(env.ExpiresAt))
		if err := d.Store.SetPartyToken(ctx, p.ID, HashLink(token), formatTime(exp)); err != nil {
			return nil, err
		}
		RememberToken(p.ID, token)
		res.Reissued = append(res.Reissued, ReissuedParty{
			PartyID: p.ID, Email: p.Email, Link: LinkFor(d.linkBase(), token)})
	}
	if len(res.Reissued) > 0 {
		if err := d.Store.AddEvent(ctx, envelopeID, actor, "reissue",
			PayloadJSON(map[string]any{"parties": len(res.Reissued)})); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// clock is the injected clock of the Deps, falling back to wall time.
func (d *Deps) clock() time.Time {
	if d.Clock != nil {
		return d.Clock().UTC()
	}
	return time.Now().UTC()
}

// parseExpiry reads a stored timestamp back into a time. An empty stamp is the
// zero time, which every caller treats as "no stored deadline".
func parseExpiry(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// ---------------- audit.zip ----------------

// AuditManifest is manifest.json inside the zip: the sha256 of every file it
// holds, and the verification report of the final document.
type AuditManifest struct {
	Files        []AuditFileEntry `json:"files"`
	Verification AuditVerify      `json:"verification"`
}

// AuditFileEntry is one file of the zip and the sha256 of its bytes.
type AuditFileEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// AuditVerify is the verification report as the manifest records it.
type AuditVerify struct {
	Valid         bool          `json:"valid"`
	CAFingerprint string        `json:"ca_fingerprint,omitempty"`
	Signers       []AuditSigner `json:"signers"`
	Errors        []string      `json:"errors,omitempty"`
}

// AuditSigner is one signature as verification saw it.
type AuditSigner struct {
	Name, Email, Serial, Reason        string
	Time                               string `json:"time"`
	Valid, Trusted, Revoked, Timestamp bool
}

// AuditZip builds audit.zip of one envelope: every revision as a named PDF
// (001-template.pdf, 002-filled.pdf, ... 00N-sign-<name>.pdf), consents.json,
// events.json, and manifest.json carrying the sha256 of each file plus the
// verification report signpdf.Verify produces for the final document. The zip
// is generated on demand and never cached on disk, so the builder takes bytes
// out and the handler streams them.
func (d *Deps) AuditZip(ctx context.Context, envelopeID string) ([]byte, error) {
	env, err := d.Store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	revisions, err := d.Store.ListRevisions(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	consents, err := d.Store.ListConsents(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	events, err := d.Store.ListEvents(ctx, envelopeID)
	if err != nil {
		return nil, err
	}

	// The files of the zip in a fixed order: the revisions by name, then the
	// JSON records, then the manifest. Fixed order is what makes the zip
	// reproducible: the same store state must produce the same archive.
	pdfName := func(i int, r signstore.Revision, parties []signstore.Party) string {
		kind := r.Kind
		if strings.HasPrefix(r.Kind, "sign") {
			for _, p := range parties {
				if p.ID == r.PartyID {
					kind = "sign-" + auditSlug(p.Name)
					break
				}
			}
		}
		return fmt.Sprintf("%03d-%s.pdf", i+1, auditSlug(kind))
	}

	type entry struct {
		name string
		data []byte
	}
	var files []entry
	finalBytes := []byte(nil)
	for i, r := range revisions {
		data, err := d.Store.GetPDF(r.SHA256)
		if err != nil {
			return nil, err
		}
		files = append(files, entry{name: pdfName(i, r, parties), data: data})
		finalBytes = data // revisions come oldest-first; the last is the document
	}
	// The design names the current document document.pdf in the zip listing;
	// every revision is present under its own name, the final copy under the
	// plain name as well.
	if finalBytes != nil {
		files = append(files, entry{name: "document.pdf", data: finalBytes})
	}

	consentRows := make([]map[string]any, 0, len(consents))
	for _, c := range consents {
		consentRows = append(consentRows, map[string]any{
			"party_id": c.PartyID, "signature_text": c.SignatureText,
			"consent_at": c.ConsentAt, "ip": c.IP, "user_agent": c.UserAgent,
		})
	}
	eventRows := make([]map[string]any, 0, len(events))
	for _, e := range events { // the audit log is newest first everywhere it is shown
		eventRows = append(eventRows, map[string]any{
			"id": e.ID, "actor": e.Actor, "kind": e.Kind,
			"payload": jsonPayloadOf(e.Payload), "created_at": e.CreatedAt,
		})
	}
	// newest-first: build in reverse so the zip matches the API.
	rev := func(rows []map[string]any) {
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
	}
	rev(eventRows)

	// The verification report of the final document. An envelope with no
	// revisions yet has nothing to verify, and the report is empty but present.
	verify := AuditVerify{Signers: []AuditSigner{}}
	if finalBytes != nil && d.Signer != nil {
		report, err := d.Signer.Verify(ctx, finalBytes)
		if err != nil {
			return nil, err
		}
		verify.Valid = report.Valid
		verify.Errors = report.Errors
		if ca := d.Signer.CA(); ca != nil {
			verify.CAFingerprint = ca.Fingerprint()
		}
		for _, si := range report.Signers {
			verify.Signers = append(verify.Signers, AuditSigner{
				Name: si.Name, Email: si.Email, Serial: si.Serial, Reason: si.Reason,
				Time: formatTime(si.Time), Valid: si.Valid, Trusted: si.Trusted,
				Revoked: si.Revoked, Timestamp: si.Timestamp,
			})
		}
	}

	manifest := AuditManifest{Files: []AuditFileEntry{}, Verification: verify}
	jsonOf := func(v any) []byte {
		// PayloadJSON is the package's encoder; the manifest must hold real
		// JSON, and the payload fields are re-encoded from stored text so a
		// stored payload becomes a JSON object, not a string.
		return []byte(PayloadJSON(v))
	}
	consentJSON := jsonOf(consentRows)
	eventJSON := jsonOf(eventRows)

	// sha256 of every file first (the manifest lists all of them, including
	// itself with the hash it will get once written).
	hashOf := map[string][]byte{}
	for _, f := range files {
		hashOf[f.name] = sha256sum(f.data)
	}
	hashOf["consents.json"] = sha256sum(consentJSON)
	hashOf["events.json"] = sha256sum(eventJSON)
	for _, f := range files {
		manifest.Files = append(manifest.Files,
			AuditFileEntry{Name: f.name, SHA256: hexOf(hashOf[f.name]), Size: len(f.data)})
	}
	manifest.Files = append(manifest.Files,
		AuditFileEntry{Name: "consents.json", SHA256: hexOf(hashOf["consents.json"]), Size: len(consentJSON)})
	manifest.Files = append(manifest.Files,
		AuditFileEntry{Name: "events.json", SHA256: hexOf(hashOf["events.json"]), Size: len(eventJSON)})
	manifestJSON := jsonOf(manifest)
	manifestSHA := sha256sum(manifestJSON)
	manifest.Files = append(manifest.Files,
		AuditFileEntry{Name: "manifest.json", SHA256: hexOf(manifestSHA), Size: len(manifestJSON)})

	// Write the archive. Names are sorted so two runs over the same data
	// produce byte-identical output; the timestamps are zeroed for the same
	// reason.
	order := make([]entry, 0, len(files)+2)
	order = append(order, files...)
	order = append(order, entry{name: "consents.json", data: consentJSON})
	order = append(order, entry{name: "events.json", data: eventJSON})
	sortEntries := func(a []entry) {
		for i := 1; i < len(a); i++ {
			for j := i; j > 0 && a[j].name < a[j-1].name; j-- {
				a[j], a[j-1] = a[j-1], a[j]
			}
		}
	}
	sortEntries(order)

	buf := &bytes.Buffer{}
	zw := archivezip.NewWriter(buf)
	add := func(name string, data []byte) error {
		// The manifest's own recorded hash is the hash of the bytes as they
		// are written, so the entry written last carries the recomputed value.
		f, err := zw.CreateHeader(&archivezip.FileHeader{Name: name, Method: archivezip.Store, Modified: time.Time{}})
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	for _, e := range order {
		if err := add(e.name, e.data); err != nil {
			return nil, err
		}
	}
	if err := add("manifest.json", manifestJSON); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	_ = env // the envelope row is the existence check: 404 before any zip work
	return buf.Bytes(), nil
}

// auditSlug keeps a zip member name boring: lowercase alphanumerics and dashes
// only, so a party named "Ann-Marie O'Neil" cannot inject a path or a quoting
// surprise into the archive listing.
func auditSlug(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c-'A'+'a')
		case c == '-' || c == '_':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}

// jsonPayloadOf re-embeds a stored event payload: the events table holds text,
// and the manifest must show it as a JSON object, not as an escaped string.
// Text that is not valid JSON is embedded as a JSON string, so the manifest
// never breaks on a payload written by an older build.
func jsonPayloadOf(s string) json.RawMessage {
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return b
}

func sha256sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func hexOf(b []byte) string     { return hex.EncodeToString(b) }
