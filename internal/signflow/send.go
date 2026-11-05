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

// The kinds the service sends.
const (
	KindInvite    = "invite"
	KindReminder  = "reminder"
	KindCancelled = "cancelled"
	KindSigned    = "signed"
)

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
	token := rawToken
	if token == "" {
		token = RawToken(item.PartyID)
	}
	if token == "" {
		return nil, fmt.Errorf("signflow: %s: party %s: the link token is not available",
			item.Kind, item.PartyID)
	}
	d := signmail.Data{
		Kind:      item.Kind,
		MailFrom:  mailFrom,
		From:      mailFrom,
		Title:     env.Title,
		Signer:    p.Name,
		Link:      LinkFor(linkBase, token),
		ExpiresAt: p.TokenExpires,
		Reason:    p.Reason,
		SHA256:    item.SHA256,
		SignedAt:  env.DeliveredAt,
		Order:     p.OrderIdx,
		N:         parties,
		Email:     p.Email,
	}
	if item.Kind == KindReminder {
		d.DaysLeft = remaining(now, p.TokenExpires)
	}
	text, html, err := r.Render(d)
	if err != nil {
		return nil, err
	}
	return &signmail.Message{
		Kind:       item.Kind,
		EnvelopeID: item.EnvelopeID,
		PartyID:    item.PartyID,
		To:         p.Email,
		From:       mailFrom,
		Subject:    signmail.SubjectFor(d),
		Text:       text,
		HTML:       html,
	}, nil
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
	if kind != KindInvite && kind != KindReminder && kind != KindCancelled && kind != KindSigned {
		return fmt.Errorf("signflow: unknown mail kind %q", strings.ToLower(kind))
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
		payload := fmt.Sprintf(`{"kind":%q,"party":%q,"error":%q}`, item.Kind, item.PartyID, reason)
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
