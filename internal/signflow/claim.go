package signflow

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The public signing endpoints. A party arrives with only its link token; the
// token is the credential, so resolving it is the whole of authentication
// here, and every rule below is enforced server-side because the page the
// party sees is untrusted.
//
// Every failure writes an event. The audit trail is the only way an operator
// can see a broken flow: a token that is used from the wrong address, an
// address that does not match, a consent refused.

// ErrTokenUnknown and ErrTokenExpired are declared in tokens.go and mean the
// same thing here: a made-up link is a 404, an expired one a 410.

// ErrLinkClosed is a live token on an envelope that has stopped. A declined,
// cancelled, expired or finished envelope is over, and its remaining links are
// dead: 410, not 404, because the party's link was real.
var ErrLinkClosed = errors.New("signflow: signing request is closed")

// ErrPartyStatus is a party that cannot act: declined, expired, or already
// consented. 409.
var ErrPartyStatus = errors.New("signflow: party cannot act in its current status")

// ErrClaimEmail is the address check refusing. 403, and always logged: it is
// the only defence a bearer link has against being read by someone else.
var ErrClaimEmail = errors.New("signflow: address does not match the invitation")

// ErrDocumentSHA is a view whose document is not the one on the server. 409,
// and the party is told to reload: the copy they are looking at is stale.
var ErrDocumentSHA = errors.New("signflow: document has changed, reload")

// ErrConsentRequired is consent arriving without consent: true. 400.
var ErrConsentRequired = errors.New("signflow: consent true is required")

// ErrSignatureText is an e-signature text the rules refuse. 400.
var ErrSignatureText = errors.New("signflow: signature text is not valid")

// ErrConsentImage is an image the rules refuse: not decodable, not PNG/JPEG,
// too large in bytes or in pixels. 400.
var ErrConsentImage = errors.New("signflow: consent image is not valid")

// SessionTTL is how long a claim session lives. The cookie is session-scoped,
// so a browser left open on a shared machine is the risk; twelve hours bounds
// it, and the session is destroyed by the consent in any case.
// SessionTTL is how long a claim session lives.
const SessionTTL = 12 * time.Hour

// Signer is a resolved link: the party it belongs to and the envelope it
// belongs to. Both are needed by every rule, because several rules are about
// the envelope (expired, stopped) and several about the party (status).
type Signer struct {
	Party    *signstore.Party
	Envelope *signstore.Envelope
}

// ResolveSigner turns a link token into its party and envelope.
//
// The order of the refusals is the order of the API table: unknown token is a
// 404, an expired token a 410, a closed envelope a 410. Envelope expiry is
// checked here too, so a link on an envelope that the sweep has not reached
// yet is still refused.
func ResolveSigner(ctx context.Context, store *signstore.Store, token string, now time.Time) (*Signer, error) {
	p, err := LookupLink(ctx, store, token, now)
	if err != nil {
		return nil, err
	}
	env, err := store.GetEnvelope(ctx, p.EnvelopeID)
	if err != nil {
		if errors.Is(err, signstore.ErrNotFound) {
			return nil, signstore.ErrNotFound
		}
		return nil, err
	}
	s, err := resolveLink(p, env, now)
	if err != nil {
		return nil, err
	}
	s.Envelope = env
	return s, nil
}

// resolveLink is the link's own facts: the envelope status and the expiry, read
// off rows the caller already has. It is the whole of ResolveSigner that does
// not touch a database, which is why signauth can run the same rules from the
// middleware through the same code.
func resolveLink(p *signstore.Party, env *signstore.Envelope, now time.Time) (*Signer, error) {
	if exp, err := time.Parse(timeFormat, p.TokenExpires); err == nil && exp.Before(now) {
		return nil, ErrTokenExpired
	}
	if statusStopped(env.Status) {
		return nil, ErrLinkClosed
	}
	if env.ExpiresAt != "" {
		if exp, err := time.Parse(timeFormat, env.ExpiresAt); err == nil && exp.Before(now) {
			return nil, ErrTokenExpired
		}
	}
	return &Signer{Party: p}, nil
}

// statusStopped reports the envelope states that close every link on it: a
// request that has failed (which includes a decline), been cancelled, expired,
// or is already finished is over, and a live token into it is a dead link.
func statusStopped(e signstore.EnvelopeStatus) bool {
	switch e {
	case signstore.StatusFailed, signstore.StatusCancelled,
		signstore.StatusExpired, signstore.StatusCompleted, signstore.StatusDelivered:
		return true
	}
	return false
}

// normalizeAddress is the address used for comparison. Addresses are stored
// lowercase; the party types theirs by hand, so case and surrounding space are
// the only differences worth allowing.
func normalizeAddress(a string) string {
	return strings.ToLower(strings.TrimSpace(a))
}

// sameAddress compares in constant time. The comparison is not secret-keeping
// work, but it costs nothing to make the timing uniform, and there is no
// reason to let a probe measure how much of an address matched.
func sameAddress(given, want string) bool {
	g, w := normalizeAddress(given), normalizeAddress(want)
	if len(g) != len(w) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(g), []byte(w)) == 1
}

// ClaimResult carries the session to set. The plaintext appears only here: the
// database holds the hash, and the audit trail holds only the IP.
type ClaimResult struct {
	Session   string
	ExpiresAt string
	PartyID   string
	Email     string
	Name      string
	Title     string
}

// Claim is the address check that opens a signing session.
//
// A party arrives with a link token and states the address the invitation was
// sent to. A match mints a session; a refusal is logged with the IP of the
// caller, so a token used from an unexpected address leaves a trace.
//
// The token is kept: the claim step is allowed to be repeated (a party that
// mistypes its address is not punished by burning the link), so the token is
// not single-use here. What the claim adds is the session cookie, which the
// consent needs.
func Claim(ctx context.Context, store *signstore.Store, token, email string, now time.Time, ip, userAgent string) (*ClaimResult, error) {
	s, err := ResolveSigner(ctx, store, token, now)
	if err != nil {
		// A failure on a token we do not know cannot be logged against a
		// party; there is no party. The handler logs the refusal itself.
		return nil, err
	}
	p := s.Party

	if err := partyOpen(p); err != nil {
		return nil, err
	}

	if !sameAddress(email, p.Email) {
		// 403, and the event. The address is not echoed: the answer that
		// says "no" is enough, and repeating a probe's input back at it is
		// how enumeration becomes comfortable.
		auditClaimFailure(ctx, store, p, ip, userAgent, "address_mismatch")
		return nil, ErrClaimEmail
	}

	secret, err := newSessionSecret()
	if err != nil {
		return nil, err
	}
	at := formatTime(now)
	expiry := formatTime(now.Add(SessionTTL))

	// The columns are the ones the schema has: status, claim_at, session_hash.
	// The session's own deadline rides in the cookie's Expires and in the
	// event; a column for it would be a second clock to keep in step.
	err = store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`update parties set status = 'claimed', claim_at = ?, session_hash = ?
			 where id = ?`, at, HashLink(secret), p.ID); err != nil {
			return fmt.Errorf("signflow: claim party: %w", err)
		}
		return insertEvent(ctx, tx, p.EnvelopeID, "party:"+p.ID, "claimed",
			jsonPayload(map[string]any{"ip": ip, "ua": userAgent, "expires_at": expiry}))
	})
	if err != nil {
		return nil, err
	}
	return &ClaimResult{Session: secret, ExpiresAt: expiry, PartyID: p.ID,
		Email: p.Email, Name: p.Name, Title: s.Envelope.Title}, nil
}

// auditClaimFailure writes the refused claim. It is one event kind,
// claim_failed, with the reason inside: the operator's question is "who tried
// and why was it refused", and that is one row.
func auditClaimFailure(ctx context.Context, store *signstore.Store, p *signstore.Party, ip, userAgent, reason string) {
	payload := jsonPayload(map[string]any{"reason": reason, "ip": ip, "ua": userAgent,
		"party": p.ID})
	// The audit write must not change the answer the party gets. A failure
	// here is logged to the service log by the handler; the refusal stands.
	_ = store.Tx(ctx, func(tx *sql.Tx) error {
		return insertEvent(ctx, tx, p.EnvelopeID, "party:"+p.ID, "claim_failed", payload)
	})
}

// newSessionSecret is 256 bits of session identifier, hex so it is safe in a
// cookie without encoding.
func newSessionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("signflow: session secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// SignerView is the envelope as the signing page sees it.
//
// Before a claim, only the title and the deadline: the page must be able to
// say "this is Quarterly Report Q3, and it expires on Friday" so the party can
// confirm they are where they think they are. Nothing else is shown, because
// a link in an email forward is read by strangers.
//
// After a claim, the party sees its own slot (order, of, name, status,
// consent_at) and the list of everyone in order with their status. No
// addresses: they are personal data, and the signing page has no use for them.
type SignerView struct {
	Title         string         `json:"title"`
	Status        string         `json:"status,omitempty"`
	ExpiresAt     string         `json:"expires_at"`
	DocumentSHA   string         `json:"document_sha,omitempty"`
	My            *MySlot        `json:"my,omitempty"`
	Parties       []PartySummary `json:"parties,omitempty"`
	AllConsented  bool           `json:"all_consented"`
	RemainingSecs int64          `json:"remaining_secs"`
}

// MySlot is the party's own position in the signing order.
type MySlot struct {
	Order      int    `json:"order"`
	Of         int    `json:"of"`
	Name       string `json:"name"`
	Email      string `json:"-"`
	Status     string `json:"status"`
	ConsentAt  string `json:"consent_at"`
	DeclinedAt string `json:"declined_at"`
}

// PartySummary is one line of the signing order. Name and status only.
type PartySummary struct {
	Order  int    `json:"order"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// SignerViewFor builds the view for a resolved link. claimed says whether the
// caller presented a session cookie: the view is not allowed to decide that by
// itself, because the cookie is the proof and the middleware holds it.
func SignerViewFor(ctx context.Context, store *signstore.Store, s *Signer, claimed bool, now time.Time) (*SignerView, error) {
	env := s.Envelope
	v := &SignerView{Title: env.Title, ExpiresAt: env.ExpiresAt}
	if env.ExpiresAt != "" {
		if exp, err := time.Parse(timeFormat, env.ExpiresAt); err == nil {
			d := exp.Sub(now)
			if d < 0 {
				d = 0
			}
			v.RemainingSecs = int64(d.Seconds())
		}
	}
	if !claimed {
		// Pre-claim the answer is the title and the deadline, and nothing
		// else. A party that has not proved its address gets no status, no
		// digest, no slot, and no list: the shape of the request is not a
		// fact you learn by holding a link.
		return v, nil
	}
	v.Status = string(env.Status)
	v.DocumentSHA = env.CurrentSHA
	parties, err := store.ListParties(ctx, env.ID)
	if err != nil {
		return nil, err
	}
	v.Parties = make([]PartySummary, 0, len(parties))
	consented := 0
	for _, p := range parties {
		v.Parties = append(v.Parties, PartySummary{
			Order: p.OrderIdx, Name: p.Name, Status: string(p.Status),
		})
		if p.Status == signstore.PartyConsented {
			consented++
		}
		if p.ID == s.Party.ID {
			v.My = &MySlot{
				Order: p.OrderIdx, Of: len(parties), Name: p.Name,
				Status: string(p.Status), ConsentAt: p.ConsentAt,
			}
		}
	}
	v.AllConsented = len(parties) > 0 && consented == len(parties)
	return v, nil
}

// SignerDocument is the certified bytes the party reviews.
//
// The bytes are the revision the envelope points at, which is the frozen
// certified file. The signing page is not shown a field list, a form, or a
// re-rendered copy: the party signs what the service certified, so that is the
// only thing served.
func SignerDocument(ctx context.Context, store *signstore.Store, s *Signer) (title string, sha string, data []byte, err error) {
	sha = s.Envelope.CurrentSHA
	if sha == "" {
		return "", "", nil, signstore.ErrNotFound
	}
	data, err = store.GetPDF(sha)
	if err != nil {
		return "", sha, nil, err
	}
	return s.Envelope.Title, sha, data, nil
}

// PayloadJSON encodes an event payload. It is exported for the worker, which
// writes audit rows of its own and must produce the same shape.
func PayloadJSON(v any) string { return jsonPayload(v) }

// jsonPayload encodes an event payload. The events table holds text, and a
// payload that is not valid JSON is a broken audit trail, so an encoder
// failure falls back to an object that says so rather than to an empty string.
func jsonPayload(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"payload_error":"the audit payload could not be encoded"}`
	}
	return string(b)
}

// partyOpen reports whether the party may still act. It is the guard's rule and
// the handlers' rule in one place: consented, declined and expired are all
// closed states, and a closed party is a 409 on the API's table (the consent
// table lists them first, before the token expiry, because the party's own
// state is the first fact the endpoint asks about).
func partyOpen(p *signstore.Party) error {
	switch p.Status {
	case signstore.PartyConsented, signstore.PartyDeclined, signstore.PartyExpired:
		return ErrPartyStatus
	}
	return nil
}
