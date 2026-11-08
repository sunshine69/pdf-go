package signflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Sending. A queue row is a job, not a message: the message is rendered when
// the row is claimed, so a change of the link lifetime or of the template
// applies to a message that has not been sent yet.
//
// Enqueue is done inside the create transaction, so an envelope can never be
// ready without an invite waiting. Send enqueues an invite for every invited
// party, re-issuing any token that is missing or expired, then transitions the
// envelope ready -> sent. The queue is drained by the worker (step 07); when a
// sender is configured, Send drains it itself so a send is finished by the time
// the response is written.

// Queue is the store side of the mail queue, kept small so send_test can use a
// fake.
type Queue interface {
	EnqueueMail(ctx context.Context, envelopeID, partyID, kind, sha256 string) error
	// EnqueueMailTo queues a message addressed to an explicit recipient rather
	// than to the party row. The drafter's notices are the only such messages,
	// and they arrive through NotifyDrafter; the interface carries it so a fake
	// can be handed the whole queue.
	EnqueueMailTo(ctx context.Context, envelopeID, partyID, recipient, kind, sha256, detail string) error
}

// EnqueueInvites writes one invite row per party. Called with the create
// transaction so the rows appear with the envelope.
func EnqueueInvites(ctx context.Context, q Queue, envelopeID string, parties []signstore.Party) error {
	for _, p := range parties {
		if err := q.EnqueueMail(ctx, envelopeID, p.ID, KindInvite, ""); err != nil {
			return fmt.Errorf("signflow: queue invite for %s: %w", p.Email, err)
		}
	}
	return nil
}

// The kinds the service sends. The first four go to a party; the last two go
// to the drafter, and they are the only messages in this service whose
// recipient is not a party row — see NotifyDrafter.
const (
	KindInvite        = "invite"
	KindReminder      = "reminder"
	KindCancelled     = "cancelled"
	KindSigned        = "signed"
	KindDeclined      = "declined"
	KindUndeliverable = "undeliverable"
)

// toDrafter is true of a kind addressed to envelopes.notify_email rather than
// to a party. The worker checks it before rendering, so a row of this kind
// whose envelope has no address is closed rather than retried forever.
func toDrafter(kind string) bool {
	return kind == KindDeclined || kind == KindUndeliverable
}

// ErrNoRenderer is the answer of a send with no renderer configured: the
// service runs with mail disabled, and the queue is not drained.
var ErrNoRenderer = errors.New("signflow: no mail renderer is configured")

// Resolver is the store side of the data a message needs.
type Resolver interface {
	GetEnvelope(ctx context.Context, id string) (*signstore.Envelope, error)
	GetParty(ctx context.Context, id string) (*signstore.Party, error)
}

// Build renders one queue row into a message. It reads the envelope and the
// party, so a message carries the title, the signer, the link, and the deadline
// that belong to that row. The store keeps only the token hash, so the caller
// supplies the raw token; Send re-issues a token it has to, and the create
// response records the value in memory.
func Build(ctx context.Context, r *signmail.Renderer, res Resolver, item *signstore.MailItem,
	mailFrom, linkBase, rawToken string, parties int, now time.Time) (*signmail.Message, error) {
	if r == nil {
		return nil, ErrNoRenderer
	}
	env, err := res.GetEnvelope(ctx, item.EnvelopeID)
	if err != nil {
		return nil, fmt.Errorf("signflow: %s: envelope %s: %w", item.Kind, item.EnvelopeID, err)
	}
	p, err := res.GetParty(ctx, item.PartyID)
	if err != nil {
		return nil, fmt.Errorf("signflow: %s: party %s: %w", item.Kind, item.PartyID, err)
	}
	// A drafter's notice carries no link. The party's link is exactly the thing
	// that has stopped working — a declined request closes every link in the
	// envelope, and an undeliverable one never reached anyone who could use it
	// — so printing one would hand out a URL that only answers 410. The token
	// is not looked up, so a row of these kinds renders after a restart, when
	// rawTokens is empty, instead of failing for three days and being given up
	// on. The reason and the party's name come from the party row: that row is
	// who the message is *about*, even though it is not who it is addressed to.
	d := signmail.Data{
		Kind:      item.Kind,
		MailFrom:  mailFrom,
		From:      mailFrom,
		Title:     env.Title,
		Signer:    p.Name,
		ExpiresAt: p.TokenExpires,
		Reason:    p.Reason,
		SHA256:    item.SHA256,
		SignedAt:  env.DeliveredAt,
		Order:     p.OrderIdx,
		N:         parties,
		Email:     p.Email,
	}
	if !toDrafter(item.Kind) {
		token := rawToken
		if token == "" {
			token = RawToken(item.PartyID)
		}
		if token == "" {
			return nil, fmt.Errorf("signflow: %s: party %s: the link token is not available",
				item.Kind, item.PartyID)
		}
		d.Link = LinkFor(linkBase, token)
	}
	if item.Kind == KindReminder {
		d.DaysLeft = remaining(now, p.TokenExpires)
	}
	// The address the row is going to. A party message goes to the party; a
	// drafter's notice goes to the address the row carried, and the party's
	// address goes in the body as the one that failed. ResolveRecipient is the
	// one place that decides, so a row cannot quietly change who reads it.
	to, err := ResolveRecipient(item, p)
	if err != nil {
		return nil, err
	}
	d.Recipient = to
	if toDrafter(item.Kind) {
		// The notice is addressed to the drafter, so the party's mailbox — the
		// one the template names as the address that failed — is the party's,
		// not the reader's.
		d.Email = p.Email
		d.Reason = firstNonEmpty(item.Detail, p.Reason)
	}
	text, html, err := r.Render(d)
	if err != nil {
		return nil, err
	}
	return &signmail.Message{
		Kind:       item.Kind,
		EnvelopeID: item.EnvelopeID,
		PartyID:    item.PartyID,
		To:         to,
		From:       mailFrom,
		Subject:    signmail.SubjectFor(d),
		Text:       text,
		HTML:       html,
	}, nil
}

// ResolveRecipient decides the address one queue row goes to. A row carries
// its own recipient when the message is not addressed to a party; otherwise the
// party row is the address, which is what every signer-facing message does.
//
// A drafter's kind with no recipient is refused rather than sent. Without this
// check such a row would fall through to the party's address, which is the
// wrong person to tell about a decline and the wrong mailbox for a bounce.
// NotifyDrafter only queues when the envelope has an address, so this fires on
// a row written by a future caller, not on today's paths — but "the notice
// silently went to the signer instead" is exactly the failure that would take
// weeks to notice, so it gets an error instead of a silent misdelivery.
func ResolveRecipient(item *signstore.MailItem, p *signstore.Party) (string, error) {
	if toDrafter(item.Kind) {
		if item.Recipient == "" {
			return "", fmt.Errorf("signflow: %s: envelope %s: no drafter address to notify",
				item.Kind, item.EnvelopeID)
		}
		return item.Recipient, nil
	}
	if p.Email == "" {
		return "", fmt.Errorf("signflow: %s: party %s has no address", item.Kind, item.PartyID)
	}
	return p.Email, nil
}

// NotifyUndeliverable tells the drafter that an invitation gave up. Both drain
// loops — the send path's and the worker's — call it, because the two of them
// are one rule that has to hold everywhere a row dies.
//
// Only an invite earns a notice. A reminder is not the reason a party has not
// signed, a cancellation notice nobody received changes nothing about the
// document, and a drafter's own notice gets no notice of its own: two rows
// describing each other's failure is a loop, not a report.
//
// The returned address is empty when nobody was told, which is the state of
// every envelope without an address and is not an error.
func NotifyUndeliverable(ctx context.Context, store *signstore.Store, item *signstore.MailItem) (string, error) {
	if item.Kind != KindInvite {
		return "", nil
	}
	return NotifyDrafter(ctx, store, item.EnvelopeID, item.PartyID, KindUndeliverable,
		firstNonEmpty(item.Detail, item.LastError))
}

// firstNonEmpty returns the first argument that is not empty.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// NotifyDrafter queues one notice to the address the envelope carries. It is a
// no-op when nobody asked to be told, which is the state of every envelope
// created before schema 6 and of any create that left the field out: no row is
// written, no error is returned, and the decline or the failure stays visible
// only in the events table, exactly as it was before this existed.
//
// It returns the address it told, empty when it told nobody, so the caller can
// put that fact in the event it writes next — the event and the queue row are
// two views of one action, and a reader of the event should not have to guess
// which of them happened.
func NotifyDrafter(ctx context.Context, store *signstore.Store, envelopeID, partyID, kind, detail string) (string, error) {
	env, err := store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		return "", fmt.Errorf("signflow: %s: envelope %s: %w", kind, envelopeID, err)
	}
	if env.NotifyEmail == "" {
		return "", nil
	}
	if err := store.EnqueueMailTo(ctx, envelopeID, partyID, env.NotifyEmail, kind, "", detail); err != nil {
		return "", fmt.Errorf("signflow: queue %s for envelope %s: %w", kind, envelopeID, err)
	}
	return env.NotifyEmail, nil
}

// rawTokens holds the plaintext link of a party, in memory only, for the
// duration of the process. A queue row stores the hash, so a send that has to
// re-issue a token can only render a link for a party whose raw value is in
// memory. It is not a cache: it is cleared at restart, which is why a reminder
// sent after a restart is built from a link the API reissues.
var rawTokens = map[string]string{}

// RememberToken records the plaintext link of a party for the send step.
func RememberToken(partyID, token string) { rawTokens[partyID] = token }

// RawToken returns the recorded plaintext link, empty if it is not in memory.
func RawToken(partyID string) string { return rawTokens[partyID] }

// ClearRawTokens drops every recorded link.
func ClearRawTokens() { rawTokens = map[string]string{} }

// remaining is the whole days left of a link.
func remaining(now time.Time, expiresAt string) int {
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return 0
	}
	d := int(exp.Sub(now).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

// Enqueue sends one kind for one party. Used by cancel, completion, and the
// reminder job.
func Enqueue(ctx context.Context, q Queue, envelopeID, partyID, kind, sha256 string) error {
	switch kind {
	case KindInvite, KindReminder, KindCancelled, KindSigned, KindDeclined, KindUndeliverable:
	default:
		return fmt.Errorf("signflow: unknown mail kind %q", strings.ToLower(kind))
	}
	// A drafter's kind has no party to address it to, so it must not come
	// through the party-addressed writer: it would render to the signer.
	if toDrafter(kind) {
		return fmt.Errorf("signflow: mail kind %q is addressed to the drafter, use EnqueueMailTo", kind)
	}
	return q.EnqueueMail(ctx, envelopeID, partyID, kind, sha256)
}

// Send enqueues the invites of an envelope and transitions ready -> sent.
// A party with no token, or a token whose deadline has passed, gets a new
// token: a link that has already expired cannot be sent to a signer. When a
// sender is configured, the queue is drained inside the call so the send is
// finished when the response is written.
func (d *Deps) Send(ctx context.Context, envelopeID string, actor string, now time.Time) ([]Link, error) {
	if d.Store == nil {
		return nil, errors.New("signflow: Send has no store")
	}
	env, err := d.Store.GetEnvelope(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	if env.Status != Ready {
		return nil, ErrStateConflict
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return nil, err
	}
	links := make([]Link, 0, len(parties))
	for i := range parties {
		p := &parties[i]
		if p.Status != signstore.PartyInvited {
			continue
		}
		token, err := d.ensureToken(ctx, p, env, now)
		if err != nil {
			return nil, err
		}
		links = append(links, Link{
			PartyID:   p.ID,
			Email:     p.Email,
			Order:     p.OrderIdx,
			Token:     token,
			ExpiresAt: p.TokenExpires,
			URL:       LinkFor(d.linkBase(), token),
		})
		if err := d.Store.EnqueueMail(ctx, envelopeID, p.ID, KindInvite, ""); err != nil {
			return nil, fmt.Errorf("signflow: queue invite: %w", err)
		}
	}

	// The transition goes through the machine, so it is in the table and
	// audited. It happens after the queue rows exist: an envelope marked sent
	// always has its invites queued.
	if err := d.Flow.Transition(ctx, env, Sent, actor, `{"to":"sent"}`); err != nil {
		return nil, err
	}

	// A configured sender means the send is finished here. A failure to send
	// is recorded in the queue and reported as an event; it does not move the
	// envelope, so a signer that cannot be emailed does not corrupt the state.
	if d.Mail != nil && d.Mail.Sender != nil {
		if _, err := d.Drain(ctx, envelopeID, now); err != nil {
			return nil, err
		}
	}
	return links, nil
}

// linkBase is the public URL used for a link, taken from the mailer when the
// send has one.
func (d *Deps) linkBase() string {
	if d.Mail != nil {
		return d.Mail.LinkBase
	}
	return ""
}

// ensureToken returns the party's plaintext link, re-issuing when the party has
// no token or the stored deadline has passed. The new token is stored as its
// SHA-256, and the raw value is kept in memory so the invite can be rendered.
func (d *Deps) ensureToken(ctx context.Context, p *signstore.Party, env *signstore.Envelope, now time.Time) (string, error) {
	if p.TokenHash != "" && !expired(p.TokenExpires, now) {
		if t := RawToken(p.ID); t != "" {
			return t, nil
		}
	}
	token, err := NewLinkToken()
	if err != nil {
		return "", fmt.Errorf("signflow: link token: %w", err)
	}
	exp := TokenExpiry(now, envExpiryDuration(env, now), envExpiryTime(env))
	if err := d.Store.SetPartyToken(ctx, p.ID, HashLink(token), formatTime(exp)); err != nil {
		return "", fmt.Errorf("signflow: store token: %w", err)
	}
	p.TokenHash = HashLink(token)
	p.TokenExpires = formatTime(exp)
	RememberToken(p.ID, token)
	return token, nil
}

// expired is the deadline test of a stored token.
func expired(expiresAt string, now time.Time) bool {
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return true
	}
	return exp.Before(now)
}

func envExpiryTime(env *signstore.Envelope) time.Time {
	t, err := time.Parse(time.RFC3339, env.ExpiresAt)
	if err != nil {
		return time.Now().Add(720 * time.Hour)
	}
	return t
}

func envExpiryDuration(env *signstore.Envelope, now time.Time) time.Duration {
	return envExpiryTime(env).Sub(now)
}

// Drain sends every queued row of one envelope, in order, through the
// configured sender. A row that fails is given its backoff; a row that reaches
// the attempt limit is given up, and the failure is reported as an event so the
// admin sees it. The envelope is not touched: a message that cannot be sent is
// a delivery problem, not a signing problem.
func (d *Deps) Drain(ctx context.Context, envelopeID string, now time.Time) (int, error) {
	if d.Mail == nil || d.Mail.Renderer == nil {
		return 0, ErrNoRenderer
	}
	parties, err := d.Store.ListParties(ctx, envelopeID)
	if err != nil {
		return 0, err
	}
	sent := 0
	for {
		// The claim is scoped to this envelope, so a send drains its own rows
		// and never picks up, and has to release, a row of another envelope.
		item, err := d.Store.ClaimMailFor(ctx, envelopeID, time.Minute)
		if err != nil {
			if errors.Is(err, signstore.ErrNotFound) {
				return sent, nil
			}
			return sent, err
		}
		msg, err := Build(ctx, d.Mail.Renderer, d.Store, item, d.Mail.From, d.Mail.LinkBase,
			RawToken(item.PartyID), len(parties), now)
		if err != nil {
			if err := d.failMail(ctx, item, now, err.Error()); err != nil {
				return sent, err
			}
			continue
		}
		if err := d.Mail.Sender.Send(ctx, msg); err != nil {
			if err := d.failMail(ctx, item, now, err.Error()); err != nil {
				return sent, err
			}
			continue
		}
		if err := d.Store.MarkMailSent(ctx, item.ID); err != nil {
			return sent, err
		}
		sent++
	}
}

// failMail records one failure. At the attempt limit the row is given up and an
// event is written, so the admin is told; before the limit the row gets its
// backoff.
func (d *Deps) failMail(ctx context.Context, item *signstore.MailItem, now time.Time, reason string) error {
	if item.Attempts >= signmail.MaxAttempts {
		if err := d.Store.GiveUpMail(ctx, item.ID, reason); err != nil {
			return err
		}
		// GiveUpMail has already overwritten last_error with this failure, so
		// the row in hand carries the rejection text the notice quotes.
		item.LastError = reason
		notified, nerr := NotifyUndeliverable(ctx, d.Store, item)
		if nerr != nil {
			// The message is dead and the event must still be written; a
			// failed notice is recorded next to it rather than replacing it.
			reason = reason + " (drafter notice failed: " + nerr.Error() + ")"
		}
		payload := fmt.Sprintf(`{"kind":%q,"party":%q,"error":%q,"notified":%q}`,
			item.Kind, item.PartyID, reason, notified)
		return d.Store.AddEvent(ctx, item.EnvelopeID, "worker", "mail_failed", payload)
	}
	next := now.Add(signmail.BackoffFor(item.Attempts))
	return d.Store.MarkMailFailed(ctx, item.ID, formatTime(next), reason)
}

// Mail-test support: one message, built from the config, sent through the
// configured sender. It reports what the transport said, so a deployment can
// check SMTP without creating an envelope.
func MailTest(ctx context.Context, mailer *Mailer, to string, now time.Time) (*signmail.Message, error) {
	if mailer == nil || mailer.Sender == nil {
		return nil, ErrNoRenderer
	}
	if !signmail.ValidAddress(to) {
		return nil, fmt.Errorf("signflow: %q is not an email address", to)
	}
	token, err := NewLinkToken()
	if err != nil {
		return nil, err
	}
	d := signmail.Data{
		Kind:      KindInvite,
		MailFrom:  mailer.From,
		From:      mailer.From,
		Title:     "mail test",
		Signer:    "the tester",
		Link:      LinkFor(mailer.LinkBase, token),
		Reason:    "This is a test of the mail transport",
		Order:     1,
		N:         1,
		Email:     to,
		ExpiresAt: formatTime(now.Add(24 * time.Hour)),
	}
	text, html, err := mailer.Renderer.Render(d)
	if err != nil {
		return nil, err
	}
	msg := &signmail.Message{Kind: KindInvite, EnvelopeID: "mailtest", PartyID: "mailtest",
		To: to, From: mailer.From, Subject: signmail.SubjectFor(d), Text: text, HTML: html}
	if err := mailer.Sender.Send(ctx, msg); err != nil {
		return msg, err
	}
	return msg, nil
}
