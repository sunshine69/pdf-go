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
// that belong to that row, and it needs nothing from the caller beyond the row
// itself. That is the point: a queued message is renderable by any process, in
// any order, however long after the row was written.
func Build(ctx context.Context, r *signmail.Renderer, res Resolver, item *signstore.MailItem,
	mailFrom, linkBase string, parties int, now time.Time) (*signmail.Message, error) {
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
	// is not looked up at all for these kinds, so a row of them renders even
	// for a party that never had a token, instead of failing for three days and
	// being given up on. The reason and the party's name come from the party row: that row is
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
		// The row carries its own link. Nothing outside the database is needed
		// to render a message, which is what makes a queue row survive a
		// restart: the process that queued it can be gone and the text is still
		// the same text.
		if p.TokenRaw == "" {
			return nil, fmt.Errorf("signflow: %s: party %s: the link token is not available",
				item.Kind, item.PartyID)
		}
		d.Link = LinkFor(linkBase, p.TokenRaw)
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

// The plaintext link of a party used to live in a process-wide map here, which
// made the database the only place a link could not be read back from: a queued
// message outlived the process that queued it, and could no longer be rendered.
// It is a column now, so nothing about sending an email depends on which
// process sends it or when the server last restarted.

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

// Send mails the parties of an envelope who have not signed. It is the one
// mailing action, and it is safe to click as often as you like.
//
// A party is mailed when their status is invited or claimed — that is, they
// have not consented, declined, or expired. A claimed party is one who opened
// the link and stopped short of signing; their link still works, so another
// copy of it is a help rather than a duplicate.
//
// The link is reused, not reissued: the token lives in the party's row, so the
// address already in the party's inbox is the address being mailed, and it
// keeps working. Only a party with no token, or one whose deadline has passed,
// gets a new one — an expired link cannot be sent to a signer. Reissue is the
// action that changes the address, and it is the one to reach for when the
// link itself is the problem.
//
// ready -> sent is the only transition this makes. On an envelope already past
// ready there is nothing to advance, and the call is a re-send: a bounced or
// lost invite, a mistyped address, a queue row that outlived the process that
// wrote it. Each queue row is written as an upsert, so clicking twice cannot
// mail the same party twice — the second click finds the first click's
// unsent row and leaves it alone. When the first click's mail already went,
// the row is marked sent, and the second click legitimately queues a new one.
//
// When a sender is configured the queue is drained inside the call, so the
// send is finished when the response is written.
func (d *Deps) Send(ctx context.Context, envelopeID string, actor string, now time.Time) ([]Link, error) {
	if d.Store == nil {
		return nil, errors.New("signflow: Send has no store")
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
	links := make([]Link, 0, len(parties))
	for i := range parties {
		p := &parties[i]
		// The audience is everyone who has not finished. A consented, declined
		// or expired party has no use for another invite; an invited or claimed
		// one might, which is the whole reason this call is repeatable. A
		// claimed party is one who opened the link and stopped before signing,
		// and their link still works, so sending it again is a help.
		if p.Status == signstore.PartyConsented || p.Status == signstore.PartyDeclined ||
			p.Status == signstore.PartyExpired {
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
	//
	// Only the first send transitions. A send on an envelope that is already
	// past ready is a re-send — a bounced or lost invite, an address that was
	// mistyped, a queue row that outlived the process that wrote it — and the
	// state is already correct, so there is nothing to advance. Refusing it
	// here is what used to make the button one-click-only and push operators
	// at the remind and reissue buttons to do what send means.
	if env.Status == Ready {
		if err := d.Flow.Transition(ctx, env, Sent, actor, `{"to":"sent"}`); err != nil {
			return nil, err
		}
	} else if err := d.Store.AddEvent(ctx, envelopeID, actor, "send",
		`{"to":"`+string(env.Status)+`"}`); err != nil {
		// A re-send has no state change to record, and the audit trail is the
		// only evidence that it happened at all. Without this line the trail
		// shows one send no matter how many were made.
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

// ensureToken returns the party's plaintext link, minting a new one only when
// the party has no token or the stored deadline has passed. A minted token is
// stored twice: as the SHA-256 that authorises the link, and in plaintext so
// any later message can print it. The plaintext is not a secret in transit
// (it is in the URL of the email) and not a secret at rest — filesystem
// encryption is the operator's concern, not this table's.
func (d *Deps) ensureToken(ctx context.Context, p *signstore.Party, env *signstore.Envelope, now time.Time) (string, error) {
	if p.TokenHash != "" && !expired(p.TokenExpires, now) {
		// The token is the party's, unexpired, and its plaintext is beside it
		// in the row. Nothing is re-minted, so clicking send again sends the
		// same link: the button is safe to press twice, and a restart changes
		// nothing about what it sends.
		if p.TokenRaw != "" {
			return p.TokenRaw, nil
		}
		// A row written before the plaintext column existed. The hash still
		// authorises the link the party already holds, but there is no way to
		// print it again, so a fresh token is the only honest answer.
	}
	token, err := NewLinkToken()
	if err != nil {
		return "", fmt.Errorf("signflow: link token: %w", err)
	}
	exp := TokenExpiry(now, envExpiryDuration(env, now), envExpiryTime(env))
	if err := d.Store.SetPartyToken(ctx, p.ID, HashLink(token), token, formatTime(exp)); err != nil {
		return "", fmt.Errorf("signflow: store token: %w", err)
	}
	p.TokenHash = HashLink(token)
	p.TokenRaw = token
	p.TokenExpires = formatTime(exp)
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
			len(parties), now)
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
